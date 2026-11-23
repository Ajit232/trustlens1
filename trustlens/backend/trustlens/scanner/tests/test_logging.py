import logging

from rest_framework.test import APITestCase


class SafeLoggingTests(APITestCase):
    """
    Verifies that processing a URL containing a token/credential-shaped
    value never writes that value into the application log — regardless of
    whether the request succeeds or is rejected before reaching the log
    statement.
    """

    url = "/api/v1/check-url/"

    def test_log_output_never_contains_sensitive_query_value(self):
        distinctive_secret = "unique-secret-value-should-never-be-logged-9f3a"
        with self.assertLogs("scanner", level="INFO") as captured:
            self.client.post(
                self.url,
                {"url": f"https://example.com/reset?token={distinctive_secret}"},
                format="json",
            )
        combined_output = "\n".join(captured.output)
        self.assertNotIn(distinctive_secret, combined_output)

    def test_log_output_never_contains_full_path(self):
        distinctive_path = "very-specific-user-path-9f3a"
        with self.assertLogs("scanner", level="INFO") as captured:
            self.client.post(
                self.url, {"url": f"https://example.com/{distinctive_path}"}, format="json"
            )
        combined_output = "\n".join(captured.output)
        self.assertNotIn(distinctive_path, combined_output)
