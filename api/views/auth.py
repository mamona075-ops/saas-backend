from django.contrib.auth import get_user_model
from api.serializers.auth import RegisterSerializer, LoginSerializer
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from rest_framework_simplejwt.tokens import AccessToken

from api.serializers.token import CustomTokenObtainPairSerializer
from api.models import BlacklistedAccessToken
# from api.serializers.token import CustomTokenObtainPairSerializer, CustomTokenRefreshSerializer


User = get_user_model()


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # ✅ generate tokens with custom claims
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

        # ✅ generate tokens with custom claims
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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response({
                "status": "error",
                "data": {},
                "message": "Refresh token required",
            }, status=400)

        try:
            # Blacklist refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Blacklist access token if it exists
            access_token = request.auth
            if access_token and hasattr(access_token, "get"):
                jti = access_token.get("jti")
                if jti:
                    BlacklistedAccessToken.objects.get_or_create(jti=jti)

            return Response({
                "status": "success",
                "data": {},
                "message": "Logout successfully",
            }, status=status.HTTP_205_RESET_CONTENT)

        except (TokenError, InvalidToken):
            return Response({
                "status": "error",
                "data": {},
                "message": "Invalid or expired token",
            }, status=status.HTTP_401_UNAUTHORIZED)



