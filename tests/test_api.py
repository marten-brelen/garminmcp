import os
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from api import index as api_index


class FakeGarmin:
    def get_activities_by_date(self, start, end, activity_type=None):
        return [{"id": 1}, {"id": 2}, {"id": 3}]


class ApiTests(unittest.TestCase):
    def setUp(self):
        os.environ["REQUIRE_HTTPS"] = "0"
        self.client = TestClient(api_index.app)

    @patch("api.index.resolve_user_id_from_profile")
    @patch("api.index.verify_lens_profile_ownership")
    @patch("api.index.verify_garmin_auth")
    @patch("api.index.start_login", new_callable=AsyncMock)
    def test_auth_start_needs_mfa(
        self,
        mock_start,
        mock_verify_auth,
        mock_verify_profile,
        mock_resolve_user,
    ):
        mock_verify_auth.return_value = {"address": "0xabc", "profileId": "0xprofile"}
        mock_verify_profile.return_value = True
        mock_resolve_user.return_value = "user@example.com"
        mock_start.return_value = {"status": "needs_mfa", "mfa_token": "token-123"}
        resp = self.client.post(
            "/auth/start",
            json={"email": "user@example.com", "password": "secret", "user_id": "user-1"},
            headers={
                "x-medoxie-address": "0xabc",
                "x-medoxie-profile-id": "0xprofile",
                "x-medoxie-timestamp": "0",
                "x-medoxie-message": "dGVzdA==",
                "x-medoxie-signature": "0x0",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "needs_mfa")

    @patch("api.index.resolve_user_id_from_profile")
    @patch("api.index.verify_lens_profile_ownership")
    @patch("api.index.verify_garmin_auth")
    @patch("api.index.get_logged_in_client", new_callable=AsyncMock)
    def test_activities_returns_list(
        self,
        mock_client,
        mock_verify_auth,
        mock_verify_profile,
        mock_resolve_user,
    ):
        mock_verify_auth.return_value = {"address": "0xabc", "profileId": "0xprofile"}
        mock_verify_profile.return_value = True
        mock_resolve_user.return_value = "user@example.com"
        mock_client.return_value = (FakeGarmin(), "token_dir")
        resp = self.client.get(
            "/activities?limit=2",
            headers={
                "x-medoxie-address": "0xabc",
                "x-medoxie-profile-id": "0xprofile",
                "x-medoxie-timestamp": "0",
                "x-medoxie-message": "dGVzdA==",
                "x-medoxie-signature": "0x0",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 2)


if __name__ == "__main__":
    unittest.main()
