"""
Middleware that rejects requests bearing a blacklisted access token.

Notes:
- Prefer to perform blacklist checks in the authentication backend so they only run
  when authentication is attempted. This middleware is appropriate if you want
  a simple pre-auth check, but it will run on every request (DB hits).
- Make sure BlacklistedAccessToken.jti is indexed and consider using a cache (Redis)
  to reduce DB load for high-traffic apps.
"""
import logging
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from api.models import BlacklistedAccessToken

logger = logging.getLogger(__name__)

class BlacklistAccessTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = JWTAuthentication()

    def __call__(self, request):
        # Extract the header and raw token using the same helpers the authentication class uses
        header = self.auth.get_header(request)
        if header:
            try:
                raw_token = self.auth.get_raw_token(header)
                if raw_token is None:
                    # No raw token present, let auth flow handle missing token
                    return self.get_response(request)

                validated_token = self.auth.get_validated_token(raw_token)
                jti = validated_token.get("jti")
                if jti:
                    # DB check: consider replacing with cache lookup in production
                    if BlacklistedAccessToken.objects.filter(jti=jti).exists():
                        logger.info("Rejected request with blacklisted token (jti=%s)", jti)
                        return JsonResponse(
                            {"status": "error", "data": {}, "message": "Token blacklisted"},
                            status=401,
                        )
            except (InvalidToken, TokenError) as e:
                logger.info("Invalid/expired token in middleware: %s", e)
                return JsonResponse(
                    {"status": "error", "data": {}, "message": "342342Given token not valid or expired"},
                    status=401,
                )
            except Exception:
                # Catch unexpected errors but do not leak details
                logger.exception("Unexpected error while checking token blacklist")
                # Allow request to proceed if you prefer not to block users on middleware errors,
                # or return a 500 to be strict. Here we proceed.
                return self.get_response(request)

        return self.get_response(request)