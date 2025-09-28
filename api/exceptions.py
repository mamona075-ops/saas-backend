from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
import logging
import traceback

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom DRF exception handler that:
    - Lets DRF format expected exceptions first
    - Ensures a consistent JSON response shape for clients
    - Logs unexpected exceptions (without leaking sensitive data to clients)
    """
    # Let DRF handle known exceptions first
    response = exception_handler(exc, context)

    if response is not None:
        # If the response contains validation or field errors, include them in an 'errors' key.
        data = response.data
        message = None
        errors = None

        if isinstance(data, dict):
            message = data.get("detail")
            # If there are field-level errors, keep them under errors
            field_errors = {k: v for k, v in data.items() if k != "detail"}
            if field_errors:
                errors = field_errors
        else:
            message = str(data)

        payload = {
            "status": "error",
            "message": message or "Request failed",
        }
        if errors:
            payload["errors"] = errors

        return Response(payload, status=response.status_code)

    # Handle JWT errors explicitly
    if isinstance(exc, (InvalidToken, TokenError)):
        logger.warning("JWT error: %s", exc)
        return Response(
            {"status": "error", "message": "Given token not valid or expired"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Unexpected exception: log full traceback but return a generic message
    tb = traceback.format_exc()
    logger.error("Unhandled exception in request processing: %s\n%s", exc, tb)

    return Response(
        {"status": "error", "message": "Internal server error"},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )