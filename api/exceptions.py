from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

def custom_exception_handler(exc, context):
    # Let DRF handle standard exceptions first
    response = exception_handler(exc, context)

    if response is not None:
        # Wrap DRF responses in your generic format
        return Response({
            "status": "error",
            "message": response.data.get("detail", "An error occurred")
        }, status=response.status_code)

    # Handle JWT errors explicitly
    if isinstance(exc, (InvalidToken, TokenError)):
        return Response(
            {"status": "error", "message": "Given token not valid or expired"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Fallback for unhandled exceptions
    return Response(
        {"status": "error", "message": str(exc)},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
