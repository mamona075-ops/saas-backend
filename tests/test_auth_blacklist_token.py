from django.test import TestCase
from rest_framework.test import APIClient
from django.urls import reverse
from rest_framework import status
from django.contrib.auth import get_user_model
from api.models import BlacklistedAccessToken

class AuthBackendBlacklistTests(TestCase):
    """
    Integration test that verifies the custom authentication backend rejects
    an access token whose jti is present in BlacklistedAccessToken.
    """

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("token_obtain_pair")
        self.me_url = reverse("user-me")
        self.email = "backendtest@example.com"
        self.password = "password123"
        User = get_user_model()
        try:
            self.user = User.objects.create_user(email=self.email, password=self.password)
        except TypeError:
            self.user = User.objects.create(email=self.email, username="backendtest")
            self.user.set_password(self.password)
            self.user.save()

    def _extract_tokens(self, resp_json):
        data = resp_json.get("data") or resp_json
        return data.get("access"), data.get("refresh")

    def test_auth_backend_rejects_blacklisted_access_jti(self):
        # login and get access
        resp = self.client.post(self.login_url, data={"email": self.email, "password": self.password}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        resp_json = resp.json()
        access, refresh = self._extract_tokens(resp_json)
        self.assertIsNotNone(access)

        # call protected endpoint - should work
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        r = self.client.get(self.me_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)

        # parse jti from token (we use rest_framework_simplejwt's token classes)
        from rest_framework_simplejwt.tokens import AccessToken
        validated = AccessToken(access)
        jti = validated.get("jti")

        # blacklist jti and ensure subsequent requests fail
        BlacklistedAccessToken.objects.create(jti=jti)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        r2 = self.client.get(self.me_url)
        self.assertEqual(r2.status_code, status.HTTP_401_UNAUTHORIZED)