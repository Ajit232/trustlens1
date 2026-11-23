"""
Structured error responses.

Every error this API returns (validation failures, throttling, not-found,
method-not-allowed, and unexpected 5xxs) is reshaped into one consistent
envelope:

    {
      "error": {
        "code": "validation_error",
        "message": "One or more fields were invalid.",
        "details": { "url": ["Only http and https URLs are supported."] }
      }
    }

so the extension only ever has to parse one error shape, regardless of
which layer produced it.
"""

import logging

from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger("scanner")

_CODE_BY_STATUS = {
    400: "validation_error",
    404: "not_found",
    405: "method_not_allowed",
    429: "rate_limited",
}


def custom_exception_handler(exc, context):
    """
    Wraps DRF's default exception handler. Delegates all status-code
    decisions to DRF/Django (we don't reinvent that), and only reshapes the
    response body into the structured envelope above.

    Security note: this handler never includes exception internals
    (stack traces, exception class names, raw request data) in the
    response body — only DRF's own already-user-safe `detail`/field-error
    content. Anything unexpected is logged server-side (see below) rather
    than echoed to the client.
    """
    response = drf_exception_handler(exc, context)

    if response is None:
        # An exception DRF doesn't know how to handle reached here — this
        # is a genuine bug. Log it server-side with no request body/URL
        # content, and return a generic structured 500 rather than letting
        # a stack trace leak to the client.
        logger.exception("Unhandled exception in API view")
        return None  # Django's own 500 handling takes over; DEBUG=False in
        # production means no traceback is exposed to the client.

    code = _CODE_BY_STATUS.get(response.status_code, "error")

    if isinstance(response.data, dict) and "detail" in response.data and len(response.data) == 1:
        message = str(response.data["detail"])
        details = {}
    else:
        message = "One or more fields were invalid." if response.status_code == 400 else "Request failed."
        details = response.data if isinstance(response.data, dict) else {"errors": response.data}

    response.data = {"error": {"code": code, "message": message, "details": details}}
    return response
