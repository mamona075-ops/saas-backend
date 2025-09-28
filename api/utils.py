from rest_framework_simplejwt.tokens import AccessToken
from .models import BlacklistedAccessToken

def is_token_blacklisted(token_str: str) -> bool:
    try:
        token = AccessToken(token_str)
        return BlacklistedAccessToken.objects.filter(jti=token["jti"]).exists()
    except Exception:
        return True  # treat invalid tokens as blacklisted
