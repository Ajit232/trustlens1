import logging

from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import URLCheckRecord
from .normalization import extract_domain, hash_url, normalize_url
from .serializers import URLCheckRequestSerializer, URLCheckResponseSerializer
from .throttling import CheckURLRateThrottle

logger = logging.getLogger("scanner")


class CheckURLView(APIView):
    """
    POST /api/v1/check-url/

    Detection is intentionally NOT implemented yet. This view validates
    input, normalizes/sanitizes the URL, extracts a domain and hash for
    storage, and returns a STUBBED verdict of "unknown" with confidence 0
    for every request that passes validation.

    Two distinct failure modes, handled differently on purpose:
      - Malformed/unsupported input (bad scheme, embedded credentials,
        internal host, missing url, etc.) -> serializer raises, the
        exception is turned into a structured 4xx by
        scanner.exceptions.custom_exception_handler. This is a genuine
        client error.
      - A URL that passes validation but something goes wrong while
        normalizing/storing it -> this view catches that, logs a safe
        (no-raw-URL) message, and returns HTTP 200 with verdict="error".
        The extension gets one consistent JSON shape it always has to
        handle, whether or not detection succeeded internally, rather than
        needing separate code paths for "network worked but analysis
        failed" vs "network failed."

    Security decisions baked in even at this stub stage:
    - We never fetch the submitted URL — only string parsing, no SSRF
      surface.
    - We default to "unknown", not "safe" — a stub with no real analysis
      has zero confidence, so it must not claim a URL is safe.
    - The raw URL is never persisted, never logged. Only its hash and
      domain are stored or logged — see the logger.info() call below.
    """

    throttle_classes = [CheckURLRateThrottle]
    throttle_scope = "check_url"

    def post(self, request):
        request_serializer = URLCheckRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)

        raw_url = request_serializer.validated_data["url"]
        source = request_serializer.validated_data["source"]
        extension_version = request_serializer.validated_data["extension_version"]

        try:
            normalized = normalize_url(raw_url)
            domain = extract_domain(normalized)
            url_hash = hash_url(normalized)

            verdict_payload = {
                "verdict": URLCheckRecord.VERDICT_UNKNOWN,
                "risk_score": 0,
                "confidence": 0,
                "reasons": [],
                "normalized_url": normalized,
                "cache_ttl": settings.CHECK_URL_DEFAULT_CACHE_TTL_SECONDS,
            }

            URLCheckRecord.objects.create(
                normalized_url_hash=url_hash,
                domain=domain,
                verdict=verdict_payload["verdict"],
                risk_score=verdict_payload["risk_score"],
                confidence=verdict_payload["confidence"],
                source_context=source,
                extension_version=extension_version,
            )

            # Safe logging: only the hash and bare domain, never the raw or
            # even the normalized URL, and never anything from the query
            # string (which is exactly where tokens/credentials live even
            # after best-effort stripping — this keeps the log line safe
            # even if the deny-list ever misses a new sensitive param name).
            logger.info(
                "check-url processed",
                extra={"domain": domain, "url_hash": url_hash, "verdict": verdict_payload["verdict"]},
            )

        except Exception:
            # Anything unexpected during normalization/storage. Logged
            # without the raw URL — only that *a* failure occurred.
            logger.exception("check-url processing failed")
            return Response(
                {
                    "verdict": URLCheckRecord.VERDICT_ERROR,
                    "risk_score": 0,
                    "confidence": 0,
                    "reasons": ["An internal error occurred while processing this URL."],
                    "normalized_url": raw_url,
                    "cache_ttl": 0,
                }
            )

        response_serializer = URLCheckResponseSerializer(verdict_payload)
        return Response(response_serializer.data)


class HealthView(APIView):
    """GET /api/v1/health/ — unauthenticated liveness check, no sensitive data."""

    def get(self, request):
        return Response({"status": "ok"})
