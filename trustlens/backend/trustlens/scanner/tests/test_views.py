from unittest import mock

from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase

from trustlens.scanner.models import URLCheckRecord
from trustlens.scanner.throttling import CheckURLRateThrottle


class CheckURLViewTests(APITestCase):
    url = "/api/v1/check-url/"

    def setUp(self):
        cache.clear()  # throttle counters live in the cache; start each test clean

    # --- valid URLs ---------------------------------------------------

    def test_valid_request_returns_unknown_stub_verdict(self):
        response = self.client.post(
            self.url,
            {"url": "https://example.com/path", "source": "browser_navigation", "extension_version": "0.1.0"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["verdict"], URLCheckRecord.VERDICT_UNKNOWN)
        self.assertEqual(response.data["confidence"], 0)
        self.assertEqual(response.data["risk_score"], 0)
        self.assertEqual(response.data["reasons"], [])
        self.assertIn("cache_ttl", response.data)
        self.assertEqual(response.data["normalized_url"], "https://example.com/path")

    def test_stub_never_returns_safe_or_malicious(self):
        response = self.client.post(self.url, {"url": "https://example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["verdict"], URLCheckRecord.VERDICT_UNKNOWN)

    def test_source_and_extension_version_are_optional(self):
        response = self.client.post(self.url, {"url": "https://example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        record = URLCheckRecord.objects.latest("created_at")
        self.assertEqual(record.source_context, "other")
        self.assertEqual(record.extension_version, "unknown")

    def test_valid_request_persists_a_record(self):
        before = URLCheckRecord.objects.count()
        self.client.post(self.url, {"url": "https://example.com/path"}, format="json")
        after = URLCheckRecord.objects.count()
        self.assertEqual(after, before + 1)

    # --- invalid URLs --------------------------------------------------

    def test_missing_url_is_rejected(self):
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"]["code"], "validation_error")

    def test_blank_url_is_rejected(self):
        response = self.client.post(self.url, {"url": ""}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_non_http_scheme_is_rejected(self):
        response = self.client.post(self.url, {"url": "javascript:alert(1)"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_data_scheme_is_rejected(self):
        response = self.client.post(self.url, {"url": "data:text/html,hello"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_file_scheme_is_rejected(self):
        response = self.client.post(self.url, {"url": "file:///etc/passwd"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_url_without_host_is_rejected(self):
        response = self.client.post(self.url, {"url": "https:///path"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_oversized_url_is_rejected(self):
        huge_url = "https://example.com/" + ("a" * 3000)
        response = self.client.post(self.url, {"url": huge_url}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_source_format_is_rejected(self):
        response = self.client.post(
            self.url, {"url": "https://example.com", "source": "Not A Valid Source!"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_extension_version_format_is_rejected(self):
        response = self.client.post(
            self.url,
            {"url": "https://example.com", "extension_version": "<script>alert(1)</script>"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_method_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_malformed_json_body_is_rejected_not_500(self):
        response = self.client.post(self.url, data="{not valid json", content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # --- localhost / internal hosts ------------------------------------

    def test_localhost_is_rejected(self):
        response = self.client.post(self.url, {"url": "http://localhost:8000/admin"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_loopback_ip_is_rejected(self):
        response = self.client.post(self.url, {"url": "http://127.0.0.1/"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_private_ip_is_rejected(self):
        response = self.client.post(self.url, {"url": "http://192.168.1.1/"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_public_ip_is_accepted(self):
        response = self.client.post(self.url, {"url": "http://8.8.8.8/"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # --- credentials in URLs --------------------------------------------

    def test_url_with_username_and_password_is_rejected(self):
        response = self.client.post(
            self.url, {"url": "https://user:secretpass@example.com/"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_url_with_bare_username_is_rejected(self):
        response = self.client.post(self.url, {"url": "https://user@example.com/"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_credentials_never_reach_storage(self):
        before = URLCheckRecord.objects.count()
        self.client.post(self.url, {"url": "https://user:secretpass@example.com/"}, format="json")
        after = URLCheckRecord.objects.count()
        self.assertEqual(after, before)  # rejected before any record is created

    # --- sensitive query parameters -------------------------------------

    def test_token_query_param_stripped_from_response(self):
        response = self.client.post(
            self.url, {"url": "https://example.com/reset?token=super-secret-value"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn("super-secret-value", response.data["normalized_url"])

    def test_session_query_param_stripped(self):
        response = self.client.post(
            self.url, {"url": "https://example.com/?session=abc123&page=2"}, format="json"
        )
        self.assertNotIn("session", response.data["normalized_url"])
        self.assertIn("page=2", response.data["normalized_url"])

    def test_sensitive_param_value_never_stored(self):
        distinctive_secret = "xyz789verysecrettoken"
        self.client.post(
            self.url, {"url": f"https://example.com/?token={distinctive_secret}"}, format="json"
        )
        record = URLCheckRecord.objects.latest("created_at")
        for field in record._meta.get_fields():
            value = getattr(record, field.name, None)
            if isinstance(value, str):
                self.assertNotIn(distinctive_secret, value)

    def test_record_does_not_store_raw_url(self):
        distinctive_path = "very-specific-path-should-not-be-stored-xyz123"
        self.client.post(self.url, {"url": f"https://example.com/{distinctive_path}"}, format="json")
        record = URLCheckRecord.objects.latest("created_at")
        for field in record._meta.get_fields():
            value = getattr(record, field.name, None)
            if isinstance(value, str):
                self.assertNotIn(distinctive_path, value)

    # --- structured errors ------------------------------------------------

    def test_error_response_has_structured_envelope(self):
        response = self.client.post(self.url, {"url": "not-a-url-at-all"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertIn("code", response.data["error"])
        self.assertIn("message", response.data["error"])
        self.assertIn("details", response.data["error"])


class CheckURLRateLimitTests(APITestCase):
    url = "/api/v1/check-url/"

    def setUp(self):
        cache.clear()

    def test_requests_beyond_rate_limit_are_throttled(self):
        # DRF's SimpleRateThrottle snapshots THROTTLE_RATES as a class
        # attribute the first time the throttle class is imported in the
        # process — override_settings(REST_FRAMEWORK=...) does NOT reliably
        # change it afterward (a well-known DRF gotcha), so the rate is
        # patched directly on the throttle class instead, which is what
        # get_rate() actually reads at request time.
        with mock.patch.object(CheckURLRateThrottle, "THROTTLE_RATES", {"check_url": "2/min"}):
            self.client.post(self.url, {"url": "https://example.com/1"}, format="json")
            self.client.post(self.url, {"url": "https://example.com/2"}, format="json")
            response = self.client.post(self.url, {"url": "https://example.com/3"}, format="json")

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response.data["error"]["code"], "rate_limited")

    def test_requests_within_rate_limit_are_not_throttled(self):
        with mock.patch.object(CheckURLRateThrottle, "THROTTLE_RATES", {"check_url": "5/min"}):
            response = self.client.post(self.url, {"url": "https://example.com/1"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class HealthViewTests(APITestCase):
    def test_health_check_returns_ok(self):
        response = self.client.get("/api/v1/health/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ok")
