from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
import json

class LogoutBlacklistsAccessTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("token_obtain_pair")
        self.refresh_url = reverse("token_refresh")
        self.logout_url = reverse("logout")
        self.me_url = reverse("user-me")

        self.email = "blacklisttest@example.com"
        self.password = "password123"

        User = get_user_model()
        try:
            self.user = User.objects.create_user(email=self.email, password=self.password)
        except TypeError:
            # handle custom user model requiring username
            self.user = User.objects.create(email=self.email, username="blacklisttest")
            self.user.set_password(self.password)
            self.user.save()

    def _extract_tokens(self, resp_json):
        """
        Support both {'access','refresh'} at top-level and {'data': {...}} shape.
        """
        access = None
        refresh = None
        if not isinstance(resp_json, dict):
            return None, None
        candidate = resp_json.get("data") or resp_json
        access = candidate.get("access")
        refresh = candidate.get("refresh")
        return access, refresh

    def test_access_blacklisted_on_logout(self):
        # login -> get tokens
        resp = self.client.post(self.login_url, data={"email": self.email, "password": self.password}, format="json")
        assert resp.status_code == status.HTTP_200_OK, f"login failed: {resp.content}"
        login_json = resp.json()
        access, refresh = self._extract_tokens(login_json)
        self.assertIsNotNone(access)
        self.assertIsNotNone(refresh)

        # use access to call protected endpoint (should work)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = self.client.get(self.me_url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # optionally refresh to rotate if your settings do so, update refresh var if rotated
        resp = self.client.post(self.refresh_url, data={"refresh": refresh}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        ref_json = resp.json()
        new_access, new_refresh = self._extract_tokens(ref_json)
        if new_refresh:
            refresh = new_refresh
        # use the (possibly) refreshed access
        current_access = new_access or access
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {current_access}")

        # logout (this should blacklist both refresh token and the access jti from Authorization header)
        resp = self.client.post(self.logout_url, data={"refresh": refresh}, format="json")
        # expect successful logout (205) if logout blacklists at least one token
        self.assertEqual(resp.status_code, status.HTTP_205_RESET_CONTENT)

        # subsequent access using the same access token should be rejected
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {current_access}")
        resp = self.client.get(self.me_url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)