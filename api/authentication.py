from datetime import datetime, timezone
import logging

from django.core.cache import cache
from django.utils import timezone as dj_timezone
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from api.models import BlacklistedAccessToken
from django.conf import settings

logger = logging.getLogger(__name__)


class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom JWTAuthentication that enforces an application-level blacklist
    for access tokens (by jti). It uses Django cache to avoid DB lookups on
    every authenticated request.

    Configure in settings:
    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'api.authentication.CustomJWTAuthentication',
            ...
        )
    }
    """

    CACHE_KEY_PREFIX = "blacklisted_jti:"

    def authenticate(self, request):
        """
        Authenticate as normal, then check jti against application blacklist.
        If an access token jti is blacklisted, raise AuthenticationFailed.
        """
        try:
            result = super().authenticate(request)
        except (InvalidToken, TokenError) as e:
            logger.debug("JWT invalid/expired: %s", e)
            raise exceptions.AuthenticationFailed("Given token not valid or expired")

        if result is None:
            return None

        user, validated_token = result

        # Only check JTI for access tokens (validated_token may be RefreshToken too in some flows)
        jti = validated_token.get("jti")
        if not jti:
            return user, validated_token

        cache_key = f"{self.CACHE_KEY_PREFIX}{jti}"

        # 1) consult cache
        is_blacklisted = cache.get(cache_key)
        if is_blacklisted is True:
            logger.info("Rejected request with blacklisted token (jti=%s) (cache)", jti)
            raise exceptions.AuthenticationFailed("Token blacklisted")

        if is_blacklisted is False:
            # explicitly cached as not blacklisted (useful in some flows)
            return user, validated_token

        # 2) cache miss -> check DB
        try:
            exists = BlacklistedAccessToken.objects.filter(jti=jti).exists()
        except Exception:
            # On DB error, log and be conservative: allow request (or you may choose to deny).
            logger.exception(
                "Error while checking BlacklistedAccessToken; allowing authentication to continue"
            )
            # Do not cache negative result on DB error
            return user, validated_token

        # Cache the result. If row contains expires_at, set TTL accordingly
        try:
            row = None
            if exists:
                # If model has expires_at, use it to set TTL; fallback to a default TTL
                row = BlacklistedAccessToken.objects.filter(jti=jti).first()
            ttl = getattr(
                settings, "BLACKLIST_CACHE_DEFAULT_TTL", 60 * 5
            )  # default 5 minutes
            if row and getattr(row, "expires_at", None):
                expires_at = row.expires_at
                # compute seconds
                now = dj_timezone.now()
                secs = int((expires_at - now).total_seconds())
                if secs > 0:
                    ttl = secs
                else:
                    ttl = 0
            cache.set(cache_key, exists, timeout=ttl)
        except Exception:
            # If cache set fails, it's non-fatal; continue
            logger.exception("Failed to set blacklist cache for jti=%s", jti)

        if exists:
            logger.info("Rejected request with blacklisted token (jti=%s) (db)", jti)
            raise exceptions.AuthenticationFailed("Token blacklisted")

        return user, validated_token
