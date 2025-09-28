from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from rest_framework import serializers
from django.conf import settings

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # ✅ Add extra claims
        token["tenant_id"] = getattr(user, "tenant_id", None)
        token["role"] = getattr(user, "role", None)

        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # ✅ Also return claims in response
        data["tenant_id"] = self.user.tenant_id if hasattr(self.user, "tenant_id") else None
        data["role"] = self.user.role if hasattr(self.user, "role") else None
        return data




class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        refresh_str = attrs["refresh"]

        try:
            refresh = RefreshToken(refresh_str)
        except TokenError:
            raise serializers.ValidationError({
                "status": "error",
                "message": "Invalid refresh token",
                "code": 401
            })

        # Extract claims from old refresh
        user_id = refresh.get("user_id")
        tenant_id = refresh.get("tenant_id", None)
        role = refresh.get("role", None)

        # Always issue a new access token
        access_token = refresh.access_token
        access_token["tenant_id"] = tenant_id
        access_token["role"] = role

        data = {
            "access": str(access_token),
            "tenant_id": tenant_id,
            "role": role,
        }

        # Handle refresh rotation
        if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False):
            new_refresh = RefreshToken()
            new_refresh["user_id"] = user_id
            new_refresh["tenant_id"] = tenant_id
            new_refresh["role"] = role

            if settings.SIMPLE_JWT.get("BLACKLIST_AFTER_ROTATION", False):
                try:
                    refresh.blacklist()
                except AttributeError:
                    pass

            data["refresh"] = str(new_refresh)
        else:
            data["refresh"] = str(refresh)

        # ✅ Wrap in generic response
        return {
            "status": "success",
            "data": data,
            "message": "Token refreshed successfully"
        }


