
import unittest

from app import create_app


class TestSecurityConfiguration(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=True,
        )
        self.client = self.app.test_client()

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
