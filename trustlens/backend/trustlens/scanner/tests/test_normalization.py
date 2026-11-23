from django.test import SimpleTestCase

from trustlens.scanner.normalization import (
    extract_domain,
    has_embedded_credentials,
    hash_url,
    is_internal_host,
    normalize_url,
)
from urllib.parse import urlparse


class NormalizeUrlTests(SimpleTestCase):
    def test_strips_fragment(self):
        self.assertEqual(
            normalize_url("https://example.com/path#section"),
            "https://example.com/path",
        )

    def test_strips_default_https_port(self):
        self.assertEqual(
            normalize_url("https://example.com:443/path"),
            "https://example.com/path",
        )

    def test_strips_default_http_port(self):
        self.assertEqual(
            normalize_url("http://example.com:80/path"),
            "http://example.com/path",
        )

    def test_keeps_non_default_port(self):
        self.assertEqual(
            normalize_url("https://example.com:8443/path"),
            "https://example.com:8443/path",
        )

    def test_lowercases_scheme_and_host(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM/Path"),
            "https://example.com/Path",
        )

    def test_strips_sensitive_query_params(self):
        result = normalize_url("https://example.com/login?token=abc123&keep=1")
        self.assertNotIn("token", result)
        self.assertIn("keep=1", result)

    def test_strips_multiple_sensitive_params_case_insensitively(self):
        result = normalize_url(
            "https://example.com/?Token=a&SESSION=b&password=c&safe_param=ok"
        )
        self.assertNotIn("Token", result)
        self.assertNotIn("SESSION", result)
        self.assertNotIn("password", result)
        self.assertIn("safe_param=ok", result)

    def test_no_query_params_left_produces_clean_url(self):
        result = normalize_url("https://example.com/path?token=abc123")
        self.assertEqual(result, "https://example.com/path")


class HashUrlTests(SimpleTestCase):
    def test_same_input_hashes_identically(self):
        self.assertEqual(hash_url("https://example.com/path"), hash_url("https://example.com/path"))

    def test_hash_is_sha256_hex_length(self):
        self.assertEqual(len(hash_url("https://example.com")), 64)

    def test_hash_never_contains_raw_url_substring(self):
        url = "https://example.com/very-specific-path-fragment-xyz"
        self.assertNotIn("very-specific-path-fragment-xyz", hash_url(url))


class ExtractDomainTests(SimpleTestCase):
    def test_extracts_domain_from_normalized_url(self):
        self.assertEqual(extract_domain("https://example.com/path"), "example.com")


class IsInternalHostTests(SimpleTestCase):
    def test_localhost_is_internal(self):
        self.assertTrue(is_internal_host("localhost"))

    def test_loopback_ipv4_is_internal(self):
        self.assertTrue(is_internal_host("127.0.0.1"))

    def test_private_10_range_is_internal(self):
        self.assertTrue(is_internal_host("10.0.0.5"))

    def test_private_192_168_range_is_internal(self):
        self.assertTrue(is_internal_host("192.168.1.1"))

    def test_private_172_16_range_is_internal(self):
        self.assertTrue(is_internal_host("172.16.0.1"))

    def test_public_172_range_is_not_internal(self):
        self.assertFalse(is_internal_host("172.64.0.1"))

    def test_link_local_is_internal(self):
        self.assertTrue(is_internal_host("169.254.1.1"))

    def test_public_domain_is_not_internal(self):
        self.assertFalse(is_internal_host("example.com"))

    def test_public_ip_is_not_internal(self):
        self.assertFalse(is_internal_host("8.8.8.8"))


class HasEmbeddedCredentialsTests(SimpleTestCase):
    def test_detects_user_and_password(self):
        parsed = urlparse("https://user:pass@example.com/path")
        self.assertTrue(has_embedded_credentials(parsed))

    def test_detects_bare_username(self):
        parsed = urlparse("https://user@example.com/path")
        self.assertTrue(has_embedded_credentials(parsed))

    def test_no_credentials_returns_false(self):
        parsed = urlparse("https://example.com/path")
        self.assertFalse(has_embedded_credentials(parsed))
