from rest_framework.throttling import ScopedRateThrottle


class CheckURLRateThrottle(ScopedRateThrottle):
    """
    Rate limit specifically for POST /api/v1/check-url/, separate from the
    general anonymous throttle. Uses DRF's cache-backed throttling — no
    Redis/Celery/queue involved, consistent with the project's constraints.
    The actual rate is set via REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
    ["check_url"] in settings.py, itself read from an env var, so it can be
    tuned per environment without a code change.
    """

    scope = "check_url"
