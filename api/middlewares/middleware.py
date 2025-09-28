from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from api.models import BlacklistedAccessToken
from django.http import JsonResponse  # ✅ use Django response



# api/middleware.py
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.http import JsonResponse


class BlacklistAccessTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = JWTAuthentication()

    def __call__(self, request):
        header = self.auth.get_header(request)

        if header:
            try:
                # Extract and validate the token
                raw_token = self.auth.get_raw_token(header)
                if raw_token is None:
                    raise InvalidToken("No raw token found")

                validated_token = self.auth.get_validated_token(raw_token)
                jti = validated_token.get("jti")

                # Check if token is blacklisted
                if BlacklistedAccessToken.objects.filter(jti=jti).exists():
                    return JsonResponse(
                        {"status": "error", "data": {}, "message": "Token blacklisted"},
                        status=401
                    )

            except (InvalidToken, TokenError):
                return JsonResponse(
                    {"status": "error", "data": {}, "message": "Given token not valid or expired"},
                    status=401
                )

        # If no token or valid, continue request
        return self.get_response(request)



class BlacklistAccessTokenMiddlewareOLLLLLLDDDD:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = JWTAuthentication()

    def __call__(self, request):
        header = self.auth.get_header(request)
        if header:
            try:
                raw_token = self.auth.get_raw_token(header)
                validated_token = self.auth.get_validated_token(raw_token)
                jti = validated_token.get("jti")

                if BlacklistedAccessToken.objects.filter(jti=jti).exists():
                    return JsonResponse({"status": "error", "message": "Token blacklisted"}, status=401)

            except (InvalidToken, TokenError):
                return JsonResponse({"status": "error", "message": "Given token not valid or expired"}, status=401)

        return self.get_response(request)


class BlacklistAccessTokenMiddlewareNewold:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = JWTAuthentication()

    def __call__(self, request):
        header = self.auth.get_header(request)
        if header is not None:
            try:
                raw_token = self.auth.get_raw_token(header)
                if raw_token is not None:
                    validated_token = self.auth.get_validated_token(raw_token)
                    jti = validated_token.get("jti")

                    if BlacklistedAccessToken.objects.filter(jti=jti).exists():
                        return JsonResponse(
                            {"status": "error", "message": "Token blacklisted", "code": 401},
                            status=401
                        )
            except (InvalidToken, TokenError):
                return JsonResponse(
                    {"status": "error", "message": "Given token not valid or expired", "code": 401},
                    status=401
                )

        return self.get_response(request)

class BlacklistAccessTokenMiddlewareOLD(MiddlewareMixin):
    def process_request(self, request):
        auth = JWTAuthentication()
        header = auth.get_header(request)

        if header is None:
            return None  # no auth → skip

        raw_token = auth.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = auth.get_validated_token(raw_token)

        jti = validated_token.get("jti")
        if BlacklistedAccessToken.objects.filter(jti=jti).exists():
            return JsonResponse(
                {"detail": "Token blacklisted"},
                status=401
            )

            # from rest_framework.response import Response
            # from rest_framework import status
            # return Response({"detail": "Token blacklisted"}, status=status.HTTP_401_UNAUTHORIZED)
