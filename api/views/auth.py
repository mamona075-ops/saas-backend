from django.contrib.auth import get_user_model
from api.serializers.auth import RegisterSerializer, LoginSerializer
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from api.serializers.token import CustomTokenObtainPairSerializer
from api.models import BlacklistedAccessToken
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # generate tokens with custom claims
        token_serializer = CustomTokenObtainPairSerializer.get_token(user)
        refresh = token_serializer
        access = token_serializer.access_token

        return Response({
            "status": "success",
            "data": {
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "tenant_id": user.tenant_id,
                    "role": user.role,
                },
                "refresh": str(refresh),
                "access": str(access)
            },
            "message": "User registered successfully"
        }, status=status.HTTP_201_CREATED)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        # generate tokens with custom claims
        token_serializer = CustomTokenObtainPairSerializer.get_token(user)
        refresh = token_serializer
        access = token_serializer.access_token

        return Response({
            "status": "success",
            "data": {
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "tenant_id": user.tenant_id,
                    "role": user.role,
                },
                "refresh": str(refresh),
                "access": str(access)
            },
            "message": "Login successful"
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    Logout view:
    - Blacklists the provided refresh token via RefreshToken(...).blacklist()
    - Attempts to extract the access token from the Authorization header and blacklist its jti
      in the project's BlacklistedAccessToken model so access is immediately invalidated.
    Behavior notes:
    - If refresh token is rotated by the refresh endpoint, ensure the client uses the latest refresh
      value for logout.
    - If blacklist app or BlacklistedAccessToken model is not configured, adapt accordingly.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        access_blacklisted = False
        refresh_blacklisted = False

        # Attempt to blacklist refresh token (preferred single source for logout)
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                refresh_blacklisted = True
            except (TokenError, InvalidToken) as e:
                logger.info("Refresh token invalid/expired during logout: %s", e)
                # keep going to attempt to blacklist access token if available
            except Exception:
                logger.exception("Unexpected error while blacklisting refresh token")

        # Attempt to extract access token jti from Authorization header and blacklist it
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header and auth_header.lower().startswith("bearer "):
            raw_access = auth_header.split(" ", 1)[1].strip()
            try:
                validated_access = AccessToken(raw_access)
                jti = validated_access.get("jti")
                if jti:
                    BlacklistedAccessToken.objects.get_or_create(jti=jti)
                    access_blacklisted = True
            except (TokenError, InvalidToken) as e:
                logger.info("Access token invalid/expired during logout (Authorization header): %s", e)
            except Exception:
                logger.exception("Unexpected error while blacklisting access token jti")

        # Decide response
        if refresh_blacklisted or access_blacklisted:
            return Response({
                "status": "success",
                "data": {},
                "message": "Logout successfully"
            }, status=status.HTTP_205_RESET_CONTENT)

        # Neither token could be blacklisted (likely invalid/missing)
        return Response({
            "status": "error",
            "data": {},
            "message": "Invalid or expired token"
        }, status=status.HTTP_401_UNAUTHORIZED)