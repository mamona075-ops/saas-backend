from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
import json

class AggressiveAuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        # URL endpoints
        self.login_url = reverse("token_obtain_pair")  # your login endpoint
        self.refresh_url = reverse("token_refresh")    # your refresh endpoint
        self.logout_url = reverse("logout")           # your logout endpoint
        self.me_url = reverse("user-me")                   # your user info endpoint

        # Test users
        self.user1 = {
            "email": "user1@example.com",
            "password": "password123",
        }

    def authenticate(self, email, password="password123"):
        """
        Logs in and returns tokens
        """
        response = self.client.post(self.login_url, data={
            "email": email,
            "password": password
        }, format='json')
        print("Login response:", response.status_code, response.json())
        data = response.json().get("data", {})
        access = data.get("access")
        refresh = data.get("refresh")
        return access, refresh

    def test_full_auth_flow(self):
        # --------- LOGIN ---------
        access_token, refresh_token = self.authenticate(self.user1["email"])
        self.assertIsNotNone(access_token, "Access token missing")
        self.assertIsNotNone(refresh_token, "Refresh token missing")

        # Set credentials for authenticated requests
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        # --------- USER INFO (ME) ---------
        response = self.client.get(self.me_url)
        print("UserMe response:", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # --------- REFRESH TOKEN ---------
        response = self.client.post(self.refresh_url, data={"refresh": refresh_token}, format='json')
        print("Refresh response:", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refreshed_access = response.json()["data"]["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refreshed_access}")

        # --------- LOGOUT ---------
        response = self.client.post(self.logout_url, data={"refresh": refresh_token}, format='json')
        print("========== Logout Debug ==========")
        print("Logout response status:", response.status_code)
        print("Logout response JSON:", response.json())
        print("==================================")
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

        # --------- ACCESS AFTER LOGOUT ---------
        response = self.client.get(self.me_url)
        print("UserMe after logout:", response.status_code, response.json())
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
