[1mdiff --git a/api/exceptions.py b/api/exceptions.py[m
[1mindex 9b5791b..355a419 100644[m
[1m--- a/api/exceptions.py[m
[1m+++ b/api/exceptions.py[m
[36m@@ -2,27 +2,58 @@[m [mfrom rest_framework.views import exception_handler[m
 from rest_framework.response import Response[m
 from rest_framework import status[m
 from rest_framework_simplejwt.exceptions import InvalidToken, TokenError[m
[32m+[m[32mimport logging[m
[32m+[m[32mimport traceback[m
[32m+[m
[32m+[m[32mlogger = logging.getLogger(__name__)[m
 [m
 def custom_exception_handler(exc, context):[m
[31m-    # Let DRF handle standard exceptions first[m
[32m+[m[32m    """[m
[32m+[m[32m    Custom DRF exception handler that:[m
[32m+[m[32m    - Lets DRF format expected exceptions first[m
[32m+[m[32m    - Ensures a consistent JSON response shape for clients[m
[32m+[m[32m    - Logs unexpected exceptions (without leaking sensitive data to clients)[m
[32m+[m[32m    """[m
[32m+[m[32m    # Let DRF handle known exceptions first[m
     response = exception_handler(exc, context)[m
 [m
     if response is not None:[m
[31m-        # Wrap DRF responses in your generic format[m
[31m-        return Response({[m
[32m+[m[32m        # If the response contains validation or field errors, include them in an 'errors' key.[m
[32m+[m[32m        data = response.data[m
[32m+[m[32m        message = None[m
[32m+[m[32m        errors = None[m
[32m+[m
[32m+[m[32m        if isinstance(data, dict):[m
[32m+[m[32m            message = data.get("detail")[m
[32m+[m[32m            # If there are field-level errors, keep them under errors[m
[32m+[m[32m            field_errors = {k: v for k, v in data.items() if k != "detail"}[m
[32m+[m[32m            if field_errors:[m
[32m+[m[32m                errors = field_errors[m
[32m+[m[32m        else:[m
[32m+[m[32m            message = str(data)[m
[32m+[m
[32m+[m[32m        payload = {[m
             "status": "error",[m
[31m-            "message": response.data.get("detail", "An error occurred")[m
[31m-        }, status=response.status_code)[m
[32m+[m[32m            "message": message or "Request failed",[m
[32m+[m[32m        }[m
[32m+[m[32m        if errors:[m
[32m+[m[32m            payload["errors"] = errors[m
[32m+[m
[32m+[m[32m        return Response(payload, status=response.status_code)[m
 [m
     # Handle JWT errors explicitly[m
     if isinstance(exc, (InvalidToken, TokenError)):[m
[32m+[m[32m        logger.warning("JWT error: %s", exc)[m
         return Response([m
             {"status": "error", "message": "Given token not valid or expired"},[m
             status=status.HTTP_401_UNAUTHORIZED,[m
         )[m
 [m
[31m-    # Fallback for unhandled exceptions[m
[32m+[m[32m    # Unexpected exception: log full traceback but return a generic message[m
[32m+[m[32m    tb = traceback.format_exc()[m
[32m+[m[32m    logger.error("Unhandled exception in request processing: %s\n%s", exc, tb)[m
[32m+[m
     return Response([m
[31m-        {"status": "error", "message": str(exc)},[m
[32m+[m[32m        {"status": "error", "message": "Internal server error"},[m
         status=status.HTTP_500_INTERNAL_SERVER_ERROR,[m
[31m-    )[m
[32m+[m[32m    )[m
\ No newline at end of file[m
[1mdiff --git a/api/middlewares/__pycache__/middleware.cpython-311.pyc b/api/middlewares/__pycache__/middleware.cpython-311.pyc[m
[1mindex b8fe671..2ac6953 100644[m
Binary files a/api/middlewares/__pycache__/middleware.cpython-311.pyc and b/api/middlewares/__pycache__/middleware.cpython-311.pyc differ
[1mdiff --git a/api/middlewares/middleware.py b/api/middlewares/middleware.py[m
[1mindex 6e7e084..5393682 100644[m
[1m--- a/api/middlewares/middleware.py[m
[1m+++ b/api/middlewares/middleware.py[m
[36m@@ -1,15 +1,20 @@[m
[31m-from django.utils.deprecation import MiddlewareMixin[m
[31m-from rest_framework_simplejwt.authentication import JWTAuthentication[m
[31m-from api.models import BlacklistedAccessToken[m
[31m-from django.http import JsonResponse  # ✅ use Django response[m
[31m-[m
[31m-[m
[31m-[m
[31m-# api/middleware.py[m
[32m+[m[32m"""[m
[32m+[m[32mMiddleware that rejects requests bearing a blacklisted access token.[m
[32m+[m
[32m+[m[32mNotes:[m
[32m+[m[32m- Prefer to perform blacklist checks in the authentication backend so they only run[m
[32m+[m[32m  when authentication is attempted. This middleware is appropriate if you want[m
[32m+[m[32m  a simple pre-auth check, but it will run on every request (DB hits).[m
[32m+[m[32m- Make sure BlacklistedAccessToken.jti is indexed and consider using a cache (Redis)[m
[32m+[m[32m  to reduce DB load for high-traffic apps.[m
[32m+[m[32m"""[m
[32m+[m[32mimport logging[m
[32m+[m[32mfrom django.http import JsonResponse[m
 from rest_framework_simplejwt.authentication import JWTAuthentication[m
 from rest_framework_simplejwt.exceptions import InvalidToken, TokenError[m
[31m-from django.http import JsonResponse[m
[32m+[m[32mfrom api.models import BlacklistedAccessToken[m
 [m
[32m+[m[32mlogger = logging.getLogger(__name__)[m
 [m
 class BlacklistAccessTokenMiddleware:[m
     def __init__(self, get_response):[m
[36m@@ -17,106 +22,36 @@[m [mclass BlacklistAccessTokenMiddleware:[m
         self.auth = JWTAuthentication()[m
 [m
     def __call__(self, request):[m
[32m+[m[32m        # Extract the header and raw token using the same helpers the authentication class uses[m
         header = self.auth.get_header(request)[m
[31m-[m
         if header:[m
             try:[m
[31m-                # Extract and validate the token[m
                 raw_token = self.auth.get_raw_token(header)[m
                 if raw_token is None:[m
[31m-                    raise InvalidToken("No raw token found")[m
[32m+[m[32m                    # No raw token present, let auth flow handle missing token[m
[32m+[m[32m                    return self.get_response(request)[m
 [m
                 validated_token = self.auth.get_validated_token(raw_token)[m
                 jti = validated_token.get("jti")[m
[31m-[m
[31m-                # Check if token is blacklisted[m
[31m-                if BlacklistedAccessToken.objects.filter(jti=jti).exists():[m
[31m-                    return JsonResponse([m
[31m-                        {"status": "error", "data": {}, "message": "Token blacklisted"},[m
[31m-                        status=401[m
[31m-                    )[m
[31m-[m
[31m-            except (InvalidToken, TokenError):[m
[31m-                return JsonResponse([m
[31m-                    {"status": "error", "data": {}, "message": "Given token not valid or expired"},[m
[31m-                    status=401[m
[31m-                )[m
[31m-[m
[31m-        # If no token or valid, continue request[m
[31m-        return self.get_response(request)[m
[31m-[m
[31m-[m
[31m-[m
[31m-class BlacklistAccessTokenMiddlewareOLLLLLLDDDD:[m
[31m-    def __init__(self, get_response):[m
[31m-        self.get_response = get_response[m
[31m-        self.auth = JWTAuthentication()[m
[31m-[m
[31m-    def __call__(self, request):[m
[31m-        header = self.auth.get_header(request)[m
[31m-        if header:[m
[31m-            try:[m
[31m-                raw_token = self.auth.get_raw_token(header)[m
[31m-                validated_token = self.auth.get_validated_token(raw_token)[m
[31m-                jti = validated_token.get("jti")[m
[31m-[m
[31m-                if BlacklistedAccessToken.objects.filter(jti=jti).exists():[m
[31m-                    return JsonResponse({"status": "error", "message": "Token blacklisted"}, status=401)[m
[31m-[m
[31m-            except (InvalidToken, TokenError):[m
[31m-                return JsonResponse({"status": "error", "message": "Given token not valid or expired"}, status=401)[m
[31m-[m
[31m-        return self.get_response(request)[m
[31m-[m
[31m-[m
[31m-class BlacklistAccessTokenMiddlewareNewold:[m
[31m-    def __init__(self, get_response):[m
[31m-        self.get_response = get_response[m
[31m-        self.auth = JWTAuthentication()[m
[31m-[m
[31m-    def __call__(self, request):[m
[31m-        header = self.auth.get_header(request)[m
[31m-        if header is not None:[m
[31m-            try:[m
[31m-                raw_token = self.auth.get_raw_token(header)[m
[31m-                if raw_token is not None:[m
[31m-                    validated_token = self.auth.get_validated_token(raw_token)[m
[31m-                    jti = validated_token.get("jti")[m
[31m-[m
[32m+[m[32m                if jti:[m
[32m+[m[32m                    # DB check: consider replacing with cache lookup in production[m
                     if BlacklistedAccessToken.objects.filter(jti=jti).exists():[m
[32m+[m[32m                        logger.info("Rejected request with blacklisted token (jti=%s)", jti)[m
                         return JsonResponse([m
[31m-                            {"status": "error", "message": "Token blacklisted", "code": 401},[m
[31m-                            status=401[m
[32m+[m[32m                            {"status": "error", "data": {}, "message": "Token blacklisted"},[m
[32m+[m[32m                            status=401,[m
                         )[m
[31m-            except (InvalidToken, TokenError):[m
[32m+[m[32m            except (InvalidToken, TokenError) as e:[m
[32m+[m[32m                logger.info("Invalid/expired token in middleware: %s", e)[m
                 return JsonResponse([m
[31m-                    {"status": "error", "message": "Given token not valid or expired", "code": 401},[m
[31m-                    status=401[m
[32m+[m[32m                    {"status": "error", "data": {}, "message": "342342Given token not valid or expired"},[m
[32m+[m[32m                    status=401,[m
                 )[m
[31m-[m
[31m-        return self.get_response(request)[m
[31m-[m
[31m-class BlacklistAccessTokenMiddlewareOLD(MiddlewareMixin):[m
[31m-    def process_request(self, request):[m
[31m-        auth = JWTAuthentication()[m
[31m-        header = auth.get_header(request)[m
[31m-[m
[31m-        if header is None:[m
[31m-            return None  # no auth → skip[m
[31m-[m
[31m-        raw_token = auth.get_raw_token(header)[m
[31m-        if raw_token is None:[m
[31m-            return None[m
[31m-[m
[31m-        validated_token = auth.get_validated_token(raw_token)[m
[31m-[m
[31m-        jti = validated_token.get("jti")[m
[31m-        if BlacklistedAccessToken.objects.filter(jti=jti).exists():[m
[31m-            return JsonResponse([m
[31m-                {"detail": "Token blacklisted"},[m
[31m-                status=401[m
[31m-            )[m
[31m-[m
[31m-            # from rest_framework.response import Response[m
[31m-            # from rest_framework import status[m
[31m-            # return Response({"detail": "Token blacklisted"}, status=status.HTTP_401_UNAUTHORIZED)[m
[32m+[m[32m            except Exception:[m
[32m+[m[32m                # Catch unexpected errors but do not leak details[m
[32m+[m[32m                logger.exception("Unexpected error while checking token blacklist")[m
[32m+[m[32m                # Allow request to proceed if you prefer not to block users on middleware errors,[m
[32m+[m[32m                # or return a 500 to be strict. Here we proceed.[m
[32m+[m[32m                return self.get_response(request)[m
[32m+[m
[32m+[m[32m        return self.get_response(request)[m
\ No newline at end of file[m
[1mdiff --git a/api/models/__pycache__/blacklistaccesstoken.cpython-311.pyc b/api/models/__pycache__/blacklistaccesstoken.cpython-311.pyc[m
[1mindex eae5923..438984b 100644[m
Binary files a/api/models/__pycache__/blacklistaccesstoken.cpython-311.pyc and b/api/models/__pycache__/blacklistaccesstoken.cpython-311.pyc differ
[1mdiff --git a/api/models/blacklistaccesstoken.py b/api/models/blacklistaccesstoken.py[m
[1mindex a80ef80..52cd354 100644[m
[1m--- a/api/models/blacklistaccesstoken.py[m
[1m+++ b/api/models/blacklistaccesstoken.py[m
[36m@@ -1,8 +1,34 @@[m
 from django.db import models[m
 [m
[32m+[m[32m# class BlacklistedAccessToken(models.Model):[m
[32m+[m[32m#     jti = models.CharField(max_length=255, unique=True)  # JWT ID[m
[32m+[m[32m#     created_at = models.DateTimeField(auto_now_add=True)[m
[32m+[m
[32m+[m[32m#     def __str__(self):[m
[32m+[m[32m#         return self.jti[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
 class BlacklistedAccessToken(models.Model):[m
[31m-    jti = models.CharField(max_length=255, unique=True)  # JWT ID[m
[32m+[m[32m    """[m
[32m+[m[32m    Store blacklisted access token JTI values so the app can reject access tokens immediately.[m
[32m+[m[32m    - jti: token identifier (unique)[m
[32m+[m[32m    - created_at: when blacklisted[m
[32m+[m[32m    - expires_at: optional token expiry (helpful for cleanup)[m
[32m+[m[32m    """[m
[32m+[m[32m    jti = models.CharField(max_length=255, unique=True, db_index=True)[m
     created_at = models.DateTimeField(auto_now_add=True)[m
[32m+[m[32m    expires_at = models.DateTimeField(null=True, blank=True)[m
[32m+[m
[32m+[m[32m    class Meta:[m
[32m+[m[32m        ordering = ("-created_at",)[m
[32m+[m[32m        indexes = [[m
[32m+[m[32m            models.Index(fields=["jti"], name="blacklisted_jti_idx"),[m
[32m+[m[32m        ][m
 [m
     def __str__(self):[m
[31m-        return self.jti[m
\ No newline at end of file[m
[32m+[m[32m        return self.jti[m
[1mdiff --git a/api/views/__pycache__/auth.cpython-311.pyc b/api/views/__pycache__/auth.cpython-311.pyc[m
[1mindex 91b865a..ca2c27d 100644[m
Binary files a/api/views/__pycache__/auth.cpython-311.pyc and b/api/views/__pycache__/auth.cpython-311.pyc differ
[1mdiff --git a/api/views/auth.py b/api/views/auth.py[m
[1mindex 086b237..7a2c15e 100644[m
[1m--- a/api/views/auth.py[m
[1m+++ b/api/views/auth.py[m
[36m@@ -5,15 +5,14 @@[m [mfrom rest_framework.response import Response[m
 from rest_framework.views import APIView[m
 from rest_framework.permissions import IsAuthenticated[m
 from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView[m
[31m-from rest_framework_simplejwt.tokens import RefreshToken[m
[32m+[m[32mfrom rest_framework_simplejwt.tokens import RefreshToken, AccessToken[m
 from rest_framework_simplejwt.exceptions import TokenError, InvalidToken[m
 [m
[31m-from rest_framework_simplejwt.tokens import AccessToken[m
[31m-[m
 from api.serializers.token import CustomTokenObtainPairSerializer[m
 from api.models import BlacklistedAccessToken[m
[31m-# from api.serializers.token import CustomTokenObtainPairSerializer, CustomTokenRefreshSerializer[m
[32m+[m[32mimport logging[m
 [m
[32m+[m[32mlogger = logging.getLogger(__name__)[m
 [m
 User = get_user_model()[m
 [m
[36m@@ -26,7 +25,7 @@[m [mclass RegisterView(generics.CreateAPIView):[m
         serializer.is_valid(raise_exception=True)[m
         user = serializer.save()[m
 [m
[31m-        # ✅ generate tokens with custom claims[m
[32m+[m[32m        # generate tokens with custom claims[m
         token_serializer = CustomTokenObtainPairSerializer.get_token(user)[m
         refresh = token_serializer[m
         access = token_serializer.access_token[m
[36m@@ -57,7 +56,7 @@[m [mclass LoginView(generics.GenericAPIView):[m
 [m
         user = serializer.validated_data["user"][m
 [m
[31m-        # ✅ generate tokens with custom claims[m
[32m+[m[32m        # generate tokens with custom claims[m
         token_serializer = CustomTokenObtainPairSerializer.get_token(user)[m
         refresh = token_serializer[m
         access = token_serializer.access_token[m
[36m@@ -80,42 +79,61 @@[m [mclass LoginView(generics.GenericAPIView):[m
 [m
 [m
 class LogoutView(APIView):[m
[32m+[m[32m    """[m
[32m+[m[32m    Logout view:[m
[32m+[m[32m    - Blacklists the provided refresh token via RefreshToken(...).blacklist()[m
[32m+[m[32m    - Attempts to extract the access token from the Authorization header and blacklist its jti[m
[32m+[m[32m      in the project's BlacklistedAccessToken model so access is immediately invalidated.[m
[32m+[m[32m    Behavior notes:[m
[32m+[m[32m    - If refresh token is rotated by the refresh endpoint, ensure the client uses the latest refresh[m
[32m+[m[32m      value for logout.[m
[32m+[m[32m    - If blacklist app or BlacklistedAccessToken model is not configured, adapt accordingly.[m
[32m+[m[32m    """[m
     permission_classes = [IsAuthenticated][m
 [m
     def post(self, request):[m
         refresh_token = request.data.get("refresh")[m
[31m-[m
[31m-        if not refresh_token:[m
[31m-            return Response({[m
[31m-                "status": "error",[m
[31m-                "data": {},[m
[31m-                "message": "Refresh token required",[m
[31m-            }, status=400)[m
[31m-[m
[31m-        try:[m
[31m-            # Blacklist refresh token[m
[31m-            token = RefreshToken(refresh_token)[m
[31m-            token.blacklist()[m
[31m-[m
[31m-            # Blacklist access token if it exists[m
[31m-            access_token = request.auth[m
[31m-            if access_token and hasattr(access_token, "get"):[m
[31m-                jti = access_token.get("jti")[m
[32m+[m[32m        access_blacklisted = False[m
[32m+[m[32m        refresh_blacklisted = False[m
[32m+[m
[32m+[m[32m        # Attempt to blacklist refresh token (preferred single source for logout)[m
[32m+[m[32m        if refresh_token:[m
[32m+[m[32m            try:[m
[32m+[m[32m                token = RefreshToken(refresh_token)[m
[32m+[m[32m                token.blacklist()[m
[32m+[m[32m                refresh_blacklisted = True[m
[32m+[m[32m            except (TokenError, InvalidToken) as e:[m
[32m+[m[32m                logger.info("Refresh token invalid/expired during logout: %s", e)[m
[32m+[m[32m                # keep going to attempt to blacklist access token if available[m
[32m+[m[32m            except Exception:[m
[32m+[m[32m                logger.exception("Unexpected error while blacklisting refresh token")[m
[32m+[m
[32m+[m[32m        # Attempt to extract access token jti from Authorization header and blacklist it[m
[32m+[m[32m        auth_header = request.META.get("HTTP_AUTHORIZATION", "")[m
[32m+[m[32m        if auth_header and auth_header.lower().startswith("bearer "):[m
[32m+[m[32m            raw_access = auth_header.split(" ", 1)[1].strip()[m
[32m+[m[32m            try:[m
[32m+[m[32m                validated_access = AccessToken(raw_access)[m
[32m+[m[32m                jti = validated_access.get("jti")[m
                 if jti:[m
                     BlacklistedAccessToken.objects.get_or_create(jti=jti)[m
[31m-[m
[32m+[m[32m                    access_blacklisted = True[m
[32m+[m[32m            except (TokenError, InvalidToken) as e:[m
[32m+[m[32m                logger.info("Access token invalid/expired during logout (Authorization header): %s", e)[m
[32m+[m[32m            except Exception:[m
[32m+[m[32m                logger.exception("Unexpected error while blacklisting access token jti")[m
[32m+[m
[32m+[m[32m        # Decide response[m
[32m+[m[32m        if refresh_blacklisted or access_blacklisted:[m
             return Response({[m
                 "status": "success",[m
                 "data": {},[m
[31m-                "message": "Logout successfully",[m
[32m+[m[32m                "message": "Logout successfully"[m
             }, status=status.HTTP_205_RESET_CONTENT)[m
 [m
[31m-        except (TokenError, InvalidToken):[m
[31m-            return Response({[m
[31m-                "status": "error",[m
[31m-                "data": {},[m
[31m-                "message": "Invalid or expired token",[m
[31m-            }, status=status.HTTP_401_UNAUTHORIZED)[m
[31m-[m
[31m-[m
[31m-[m
[32m+[m[32m        # Neither token could be blacklisted (likely invalid/missing)[m
[32m+[m[32m        return Response({[m
[32m+[m[32m            "status": "error",[m
[32m+[m[32m            "data": {},[m
[32m+[m[32m            "message": "Invalid or expired token"[m
[32m+[m[32m        }, status=status.HTTP_401_UNAUTHORIZED)[m
\ No newline at end of file[m
[1mdiff --git a/tests/__pycache__/test_auth_flow.cpython-311.pyc b/tests/__pycache__/test_auth_flow.cpython-311.pyc[m
[1mindex 062be35..70fb1da 100644[m
Binary files a/tests/__pycache__/test_auth_flow.cpython-311.pyc and b/tests/__pycache__/test_auth_flow.cpython-311.pyc differ
[1mdiff --git a/tests/test_auth_flow.py b/tests/test_auth_flow.py[m
[1mindex bc97c5b..3e8cc87 100644[m
[1m--- a/tests/test_auth_flow.py[m
[1m+++ b/tests/test_auth_flow.py[m
[36m@@ -3,66 +3,157 @@[m [mfrom rest_framework.test import APIClient[m
 from rest_framework import status[m
 from django.urls import reverse[m
 import json[m
[32m+[m[32mfrom django.contrib.auth import get_user_model[m
 [m
 class AggressiveAuthTests(TestCase):[m
     def setUp(self):[m
         self.client = APIClient()[m
[31m-        # URL endpoints[m
[32m+[m[32m        # URL endpoints (ensure your urls names match these)[m
         self.login_url = reverse("token_obtain_pair")  # your login endpoint[m
         self.refresh_url = reverse("token_refresh")    # your refresh endpoint[m
         self.logout_url = reverse("logout")           # your logout endpoint[m
[31m-        self.me_url = reverse("user-me")                   # your user info endpoint[m
[32m+[m[32m        self.me_url = reverse("user-me")              # your user info endpoint[m
 [m
[31m-        # Test users[m
[31m-        self.user1 = {[m
[31m-            "email": "user1@example.com",[m
[31m-            "password": "password123",[m
[31m-        }[m
[32m+[m[32m        # Test user credentials[m
[32m+[m[32m        self.user_email = "user1@example.com"[m
[32m+[m[32m        self.user_password = "password123"[m
 [m
[31m-    def authenticate(self, email, password="password123"):[m
[32m+[m[32m        # Create a test user (robust to different custom user model signatures)[m
[32m+[m[32m        User = get_user_model()[m
[32m+[m[32m        try:[m
[32m+[m[32m            # Preferred create_user helper[m
[32m+[m[32m            self.user = User.objects.create_user([m
[32m+[m[32m                email=self.user_email,[m
[32m+[m[32m                password=self.user_password[m
[32m+[m[32m            )[m
[32m+[m[32m        except TypeError:[m
[32m+[m[32m            # Fallback if create_user signature differs (e.g., username required)[m
[32m+[m[32m            self.user = User.objects.create([m
[32m+[m[32m                email=self.user_email,[m
[32m+[m[32m                username="user1"[m
[32m+[m[32m            )[m
[32m+[m[32m            self.user.set_password(self.user_password)[m
[32m+[m[32m            self.user.save()[m
[32m+[m
[32m+[m[32m    def _extract_tokens_from_response(self, resp_json):[m
[32m+[m[32m        """[m
[32m+[m[32m        Accept both shapes:[m
[32m+[m[32m        - {"data": {"access": "...", "refresh": "..."}}[m
[32m+[m[32m        - {"access": "...", "refresh": "...", ...}[m
[32m+[m[32m        Return tuple (access, refresh)[m
         """[m
[31m-        Logs in and returns tokens[m
[32m+[m[32m        access = None[m
[32m+[m[32m        refresh = None[m
[32m+[m
[32m+[m[32m        if not isinstance(resp_json, dict):[m
[32m+[m[32m            return None, None[m
[32m+[m
[32m+[m[32m        # Candidate locations in order of preference[m
[32m+[m[32m        candidates = [][m
[32m+[m[32m        candidates.append(resp_json.get("data", {}))[m
[32m+[m[32m        candidates.append(resp_json)[m
[32m+[m
[32m+[m[32m        for candidate in candidates:[m
[32m+[m[32m            if not isinstance(candidate, dict):[m
[32m+[m[32m                continue[m
[32m+[m[32m            if access is None:[m
[32m+[m[32m                access = candidate.get("access")[m
[32m+[m[32m            if refresh is None:[m
[32m+[m[32m                refresh = candidate.get("refresh")[m
[32m+[m[32m            if access or refresh:[m
[32m+[m[32m                # stop if we found at least one token source; prefer this candidate[m
[32m+[m[32m                break[m
[32m+[m
[32m+[m[32m        return access, refresh[m
[32m+[m
[32m+[m[32m    def authenticate(self, email, password=None):[m
         """[m
[32m+[m[32m        Logs in and returns (access, refresh, response)[m
[32m+[m[32m        """[m
[32m+[m[32m        if password is None:[m
[32m+[m[32m            password = self.user_password[m
[32m+[m
         response = self.client.post(self.login_url, data={[m
             "email": email,[m
             "password": password[m
         }, format='json')[m
[31m-        print("Login response:", response.status_code, response.json())[m
[31m-        data = response.json().get("data", {})[m
[31m-        access = data.get("access")[m
[31m-        refresh = data.get("refresh")[m
[31m-        return access, refresh[m
[32m+[m[32m        # Debug print for failing runs[m
[32m+[m[32m        print("Login response:", response.status_code)[m
[32m+[m[32m        try:[m
[32m+[m[32m            resp_json = response.json()[m
[32m+[m[32m            print("Login response JSON:", json.dumps(resp_json))[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            resp_json = {}[m
[32m+[m[32m            print("Login response content (non-json):", response.content.decode() if hasattr(response, "content") else response)[m
[32m+[m
[32m+[m[32m        access, refresh = self._extract_tokens_from_response(resp_json)[m
[32m+[m[32m        return access, refresh, response, resp_json[m
 [m
     def test_full_auth_flow(self):[m
         # --------- LOGIN ---------[m
[31m-        access_token, refresh_token = self.authenticate(self.user1["email"])[m
[31m-        self.assertIsNotNone(access_token, "Access token missing")[m
[31m-        self.assertIsNotNone(refresh_token, "Refresh token missing")[m
[32m+[m[32m        access_token, refresh_token, login_resp, login_json = self.authenticate(self.user_email)[m
[32m+[m[32m        self.assertIsNotNone(login_resp, "No login response")[m
[32m+[m[32m        self.assertTrue([m
[32m+[m[32m            access_token or refresh_token,[m
[32m+[m[32m            f"No tokens found in login response; status={login_resp.status_code}, content={login_resp.content}"[m
[32m+[m[32m        )[m
[32m+[m[32m        # If only one token present, assert the other as needed[m
[32m+[m[32m        self.assertIsNotNone(access_token, f"Access token missing; login content={login_json}")[m
[32m+[m[32m        self.assertIsNotNone(refresh_token, f"Refresh token missing; login content={login_json}")[m
 [m
         # Set credentials for authenticated requests[m
         self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")[m
 [m
         # --------- USER INFO (ME) ---------[m
         response = self.client.get(self.me_url)[m
[31m-        print("UserMe response:", response.status_code, response.json())[m
[32m+[m[32m        print("UserMe response:", response.status_code)[m
[32m+[m[32m        try:[m
[32m+[m[32m            print("UserMe JSON:", response.json())[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            print("UserMe content:", response.content.decode() if hasattr(response, "content") else response)[m
         self.assertEqual(response.status_code, status.HTTP_200_OK)[m
 [m
         # --------- REFRESH TOKEN ---------[m
         response = self.client.post(self.refresh_url, data={"refresh": refresh_token}, format='json')[m
[31m-        print("Refresh response:", response.status_code, response.json())[m
[32m+[m[32m        print("Refresh response:", response.status_code)[m
[32m+[m[32m        try:[m
[32m+[m[32m            refresh_json = response.json()[m
[32m+[m[32m            print("Refresh JSON:", json.dumps(refresh_json))[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            refresh_json = {}[m
[32m+[m[32m            print("Refresh content:", response.content.decode() if hasattr(response, "content") else response)[m
         self.assertEqual(response.status_code, status.HTTP_200_OK)[m
[31m-        refreshed_access = response.json()["data"]["access"][m
[32m+[m[32m        refreshed_access, refreshed_refresh = self._extract_tokens_from_response(refresh_json)[m
[32m+[m[32m        self.assertIsNotNone(refreshed_access, "Refreshed access token missing")[m
[32m+[m
[32m+[m[32m        # IMPORTANT: if the refresh endpoint rotates refresh tokens (ROTATE_REFRESH_TOKENS=True),[m
[32m+[m[32m        # it will return a new refresh token. Update our variable to the latest refresh token[m
[32m+[m[32m        # so logout uses a valid token.[m
[32m+[m[32m        if refreshed_refresh:[m
[32m+[m[32m            refresh_token = refreshed_refresh[m
[32m+[m
         self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refreshed_access}")[m
 [m
         # --------- LOGOUT ---------[m
         response = self.client.post(self.logout_url, data={"refresh": refresh_token}, format='json')[m
         print("========== Logout Debug ==========")[m
         print("Logout response status:", response.status_code)[m
[31m-        print("Logout response JSON:", response.json())[m
[32m+[m[32m        try:[m
[32m+[m[32m            print("Logout response JSON:", response.json())[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            print("Logout response content:", response.content.decode() if hasattr(response, "content") else response)[m
         print("==================================")[m
         self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)[m
 [m
         # --------- ACCESS AFTER LOGOUT ---------[m
         response = self.client.get(self.me_url)[m
[31m-        print("UserMe after logout:", response.status_code, response.json())[m
[31m-        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)[m
[32m+[m[32m        print("UserMe after logout status:", response.status_code)[m
[32m+[m[32m        try:[m
[32m+[m[32m            print("UserMe after logout JSON:", response.json())[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            print("UserMe after logout content:", response.content.decode() if hasattr(response, "content") else response)[m
[32m+[m
[32m+[m[32m        # Expect unauthorized after logout if logout invalidates access tokens as well.[m
[32m+[m[32m        # If your logout only blacklists refresh tokens and access tokens remain valid until expiry,[m
[32m+[m[32m        # adjust this assertion accordingly.[m
[32m+[m[32m        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)[m
\ No newline at end of file[m
