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

    @patch("api.index.start_login", new_callable=AsyncMock)
    def test_auth_start_needs_mfa(self, mock_start):
        mock_start.return_value = {"status": "needs_mfa", "mfa_token": "token-123"}
        resp = self.client.post(
            "/auth/start",
            json={"email": "user@example.com", "password": "secret", "user_id": "user-1"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "needs_mfa")

    @patch("api.index.get_logged_in_client", new_callable=AsyncMock)
    def test_activities_returns_list(self, mock_client):
        mock_client.return_value = (FakeGarmin(), "token_dir")
        resp = self.client.get("/activities?user_id=user-1&limit=2")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 2)


if __name__ == "__main__":
    unittest.main()
