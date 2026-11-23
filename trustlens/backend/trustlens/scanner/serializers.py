import re
from urllib.parse import urlparse

from rest_framework import serializers

from .models import URLCheckRecord
from .normalization import has_embedded_credentials, is_internal_host

MAX_URL_LENGTH = 2048

# Free-text-ish but constrained: lowercase letters, digits, underscores only.
# Not a fixed enum, because new caller contexts (e.g. "browser_navigation")
# are expected to be added over time without a backend deploy — but still
# rejects anything that isn't a short identifier-shaped string, so this
# field can never become a place where arbitrary or sensitive text lands.
SOURCE_PATTERN = re.compile(r"^[a-z_]{1,40}$")

# Loosely validates a version string like "0.1.0" or "1.2.3-beta". Purely
# for debugging/analytics correlation — never treated as trusted input for
# any decision.
EXTENSION_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9.\-+]{1,32}$")


class URLCheckRequestSerializer(serializers.Serializer):
    """
    Validates the incoming check-url payload.

    Security decisions enforced here, before any URL is normalized or
    reaches the view:
      - Only http/https schemes are accepted (rejects javascript:, data:,
        file:, etc.).
      - URLs with embedded userinfo credentials (https://user:pass@host/)
        are rejected outright — we don't sanitize-and-continue for these,
        because the presence of embedded credentials is itself a strong
        signal this isn't a normal navigation URL, and there's no reason
        for this service to ever receive or process embedded credentials.
      - URLs pointing at loopback/private/link-local hosts are rejected —
        this service has nothing meaningful to say about internal network
        addresses, and accepting them invites accidental or malicious
        internal-network probing patterns even though the backend never
        actually connects anywhere.
    This view never fetches the submitted URL to check reachability — that
    would turn this endpoint into an SSRF vector. All validation here is
    string/structure-only.
    """

    url = serializers.CharField(max_length=MAX_URL_LENGTH, allow_blank=False)
    source = serializers.CharField(required=False, default="other")
    extension_version = serializers.CharField(required=False, default="unknown", allow_blank=True)

    def validate_source(self, value):
        value = value.strip().lower()
        if not SOURCE_PATTERN.match(value):
            raise serializers.ValidationError(
                "source must be 1-40 lowercase letters/underscores."
            )
        return value

    def validate_extension_version(self, value):
        value = value.strip()
        if value in ("", "unknown"):
            return "unknown"
        if not EXTENSION_VERSION_PATTERN.match(value):
            raise serializers.ValidationError("extension_version has an unexpected format.")
        return value

    def validate_url(self, value):
        value = value.strip()
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            raise serializers.ValidationError("Only http and https URLs are supported.")
        if not parsed.hostname:
            raise serializers.ValidationError("URL must include a host.")
        if has_embedded_credentials(parsed):
            raise serializers.ValidationError(
                "URLs containing embedded credentials are not supported."
            )
        if is_internal_host(parsed.hostname):
            raise serializers.ValidationError(
                "Loopback, private, and link-local addresses are not supported."
            )

        return value


class URLCheckResponseSerializer(serializers.Serializer):
    """Shapes the outgoing verdict in exactly one place."""

    verdict = serializers.ChoiceField(choices=URLCheckRecord.VERDICT_CHOICES)
    risk_score = serializers.IntegerField(min_value=0, max_value=100)
    confidence = serializers.IntegerField(min_value=0, max_value=100)
    reasons = serializers.ListField(child=serializers.CharField())
    normalized_url = serializers.CharField()
    cache_ttl = serializers.IntegerField(min_value=0)
