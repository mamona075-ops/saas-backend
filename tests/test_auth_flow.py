from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
import json
from django.contrib.auth import get_user_model

class AggressiveAuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        # URL endpoints (ensure your urls names match these)
        self.login_url = reverse("token_obtain_pair")  # your login endpoint
        self.refresh_url = reverse("token_refresh")    # your refresh endpoint
        self.logout_url = reverse("logout")           # your logout endpoint
        self.me_url = reverse("user-me")              # your user info endpoint

        # Test user credentials
        self.user_email = "user1@example.com"
        self.user_password = "password123"

        # Create a test user (robust to different custom user model signatures)
        User = get_user_model()
        try:
            # Preferred create_user helper
            self.user = User.objects.create_user(
                email=self.user_email,
                password=self.user_password
            )
        except TypeError:
            # Fallback if create_user signature differs (e.g., username required)
            self.user = User.objects.create(
                email=self.user_email,
                username="user1"
            )
            self.user.set_password(self.user_password)
            self.user.save()

    def _extract_tokens_from_response(self, resp_json):
        """
        Accept both shapes:
        - {"data": {"access": "...", "refresh": "..."}}
        - {"access": "...", "refresh": "...", ...}
        Return tuple (access, refresh)
        """
        access = None
        refresh = None

        if not isinstance(resp_json, dict):
            return None, None

        # Candidate locations in order of preference
        candidates = []
        candidates.append(resp_json.get("data", {}))
        candidates.append(resp_json)

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            if access is None:
                access = candidate.get("access")
            if refresh is None:
                refresh = candidate.get("refresh")
            if access or refresh:
                # stop if we found at least one token source; prefer this candidate
                break

        return access, refresh

    def authenticate(self, email, password=None):
        """
        Logs in and returns (access, refresh, response)
        """
        if password is None:
            password = self.user_password

        response = self.client.post(self.login_url, data={
            "email": email,
            "password": password
        }, format='json')
        # Debug print for failing runs
        print("Login response:", response.status_code)
        try:
            resp_json = response.json()
            print("Login response JSON:", json.dumps(resp_json))
        except Exception:
            resp_json = {}
            print("Login response content (non-json):", response.content.decode() if hasattr(response, "content") else response)

        access, refresh = self._extract_tokens_from_response(resp_json)
        return access, refresh, response, resp_json

    def test_full_auth_flow(self):
        # --------- LOGIN ---------
        access_token, refresh_token, login_resp, login_json = self.authenticate(self.user_email)
        self.assertIsNotNone(login_resp, "No login response")
        self.assertTrue(
            access_token or refresh_token,
            f"No tokens found in login response; status={login_resp.status_code}, content={login_resp.content}"
        )
        # If only one token present, assert the other as needed
        self.assertIsNotNone(access_token, f"Access token missing; login content={login_json}")
        self.assertIsNotNone(refresh_token, f"Refresh token missing; login content={login_json}")

        # Set credentials for authenticated requests
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        # --------- USER INFO (ME) ---------
        response = self.client.get(self.me_url)
        print("UserMe response:", response.status_code)
        try:
            print("UserMe JSON:", response.json())
        except Exception:
            print("UserMe content:", response.content.decode() if hasattr(response, "content") else response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # --------- REFRESH TOKEN ---------
        response = self.client.post(self.refresh_url, data={"refresh": refresh_token}, format='json')
        print("Refresh response:", response.status_code)
        try:
            refresh_json = response.json()
            print("Refresh JSON:", json.dumps(refresh_json))
        except Exception:
            refresh_json = {}
            print("Refresh content:", response.content.decode() if hasattr(response, "content") else response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refreshed_access, refreshed_refresh = self._extract_tokens_from_response(refresh_json)
        self.assertIsNotNone(refreshed_access, "Refreshed access token missing")

        # IMPORTANT: if the refresh endpoint rotates refresh tokens (ROTATE_REFRESH_TOKENS=True),
        # it will return a new refresh token. Update our variable to the latest refresh token
        # so logout uses a valid token.
        if refreshed_refresh:
            refresh_token = refreshed_refresh

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refreshed_access}")

        # --------- LOGOUT ---------
        response = self.client.post(self.logout_url, data={"refresh": refresh_token}, format='json')
        print("========== Logout Debug ==========")
        print("Logout response status:", response.status_code)
        try:
            print("Logout response JSON:", response.json())
        except Exception:
            print("Logout response content:", response.content.decode() if hasattr(response, "content") else response)
        print("==================================")
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

        # --------- ACCESS AFTER LOGOUT ---------
        response = self.client.get(self.me_url)
        print("UserMe after logout status:", response.status_code)
        try:
            print("UserMe after logout JSON:", response.json())
        except Exception:
            print("UserMe after logout content:", response.content.decode() if hasattr(response, "content") else response)

        # Expect unauthorized after logout if logout invalidates access tokens as well.
        # If your logout only blacklists refresh tokens and access tokens remain valid until expiry,
        # adjust this assertion accordingly.
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)