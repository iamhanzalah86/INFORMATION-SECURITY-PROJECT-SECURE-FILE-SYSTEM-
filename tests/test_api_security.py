"""JSON API tests: two-step sign-in (MFA), role-based access control, headers."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("AES_KEY_B64", "F2rA60cDlTgz4IStKhqszRY1OHLYlFdDDvrjEkXs88g=")

from app import create_app  # noqa: E402

PW = "correct-horse-battery"


class _ApiCase(unittest.TestCase):
    """Fresh app + database per test; no tests of its own."""

    ENV = {}

    def setUp(self):
        env = {
            "LEGACY_UI": "0",
            "DATABASE_URL": "",
            "STORAGE_BACKEND": "db",
            "LOGIN_MFA": "1",
            "FORCE_HTTPS": "0",
            "HTTPS": "0",
            "ADMIN_EMAILS": "alice@example.com",
        }
        env.update(self.ENV)
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        with mock.patch("app._database_uri", return_value=f"sqlite:///{self.tmp.name}"):
            self.app = create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False

        self.codes = []
        otp = mock.patch(
            "app.otp.send_otp_email",
            side_effect=lambda to, code, *a, **k: self.codes.append(code) or True,
        )
        otp.start()
        self.addCleanup(otp.stop)

    def signup(self, username):
        """Register + verify the email. Returns a client that is NOT signed in."""
        c = self.app.test_client()
        r = c.post("/api/register", json=dict(
            username=username, email=f"{username}@example.com",
            password=PW, confirm_password=PW))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        r = c.post("/api/verify-email", json=dict(otp=self.codes[-1]))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return c

    def signin(self, c, username):
        r = c.post("/api/login", json=dict(username=username, password=PW))
        self.assertTrue(r.get_json().get("mfa_required"), r.get_data(as_text=True))
        r = c.post("/api/login/verify", json=dict(otp=self.codes[-1]))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()["user"]


class ApiSecurityTest(_ApiCase):
    # ---- MFA ---------------------------------------------------------
    def test_password_alone_does_not_sign_in(self):
        c = self.signup("bob")

        r = c.post("/api/login", json=dict(username="bob", password=PW))
        self.assertTrue(r.get_json()["mfa_required"])
        self.assertIsNone(c.get("/api/me").get_json()["user"])
        self.assertEqual(c.get("/api/dashboard").status_code, 401)

        wrong = "000000" if self.codes[-1] != "000000" else "111111"
        r = c.post("/api/login/verify", json=dict(otp=wrong))
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(c.get("/api/me").get_json()["user"])

        r = c.post("/api/login/verify", json=dict(otp=self.codes[-1]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(c.get("/api/me").get_json()["user"]["username"], "bob")

    def test_remembered_device_skips_the_code_but_not_the_password(self):
        c = self.signup("bob")
        c.post("/api/login", json=dict(username="bob", password=PW))
        r = c.post("/api/login/verify", json=dict(otp=self.codes[-1], remember=True))
        self.assertEqual(r.status_code, 200)
        c.post("/api/logout")

        # same browser: password is enough, a wrong password is still refused
        r = c.post("/api/login", json=dict(username="bob", password="wrong-password-123"))
        self.assertEqual(r.status_code, 401)
        r = c.post("/api/login", json=dict(username="bob", password=PW))
        self.assertEqual(r.get_json()["user"]["username"], "bob")

        # a different browser still needs the code
        other = self.app.test_client()
        r = other.post("/api/login", json=dict(username="bob", password=PW))
        self.assertTrue(r.get_json()["mfa_required"])

    def test_code_step_needs_the_password_step_first(self):
        c = self.app.test_client()
        self.assertEqual(c.post("/api/login/verify", json=dict(otp="123456")).status_code, 404)

    # ---- RBAC --------------------------------------------------------
    def test_roles_limit_the_admin_console(self):
        admin, bob = self.signup("alice"), self.signup("bob")
        self.assertEqual(self.signin(admin, "alice")["role"], "admin")
        bob_id = self.signin(bob, "bob")["id"]

        # a normal user is refused, and the attempt is logged
        self.assertEqual(bob.get("/api/admin/overview").status_code, 403)
        self.assertEqual(bob.get("/api/admin/users").status_code, 403)
        events = admin.get("/api/admin/overview").get_json()["events"]
        self.assertIn("ACCESS_DENIED", [e["event_type"] for e in events])

        # admin promotes bob to analyst: monitoring yes, account management no
        r = admin.post(f"/api/admin/users/{bob_id}/role", json=dict(role="analyst"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(bob.get("/api/admin/overview").status_code, 200)
        self.assertEqual(bob.get("/api/admin/users").status_code, 403)
        r = bob.post(f"/api/admin/users/{bob_id}/role", json=dict(role="admin"))
        self.assertEqual(r.status_code, 403)

        # unknown roles are rejected; admins cannot change themselves
        r = admin.post(f"/api/admin/users/{bob_id}/role", json=dict(role="root"))
        self.assertEqual(r.status_code, 400)
        me = admin.get("/api/me").get_json()["user"]["id"]
        r = admin.post(f"/api/admin/users/{me}/role", json=dict(role="user"))
        self.assertEqual(r.status_code, 409)

    def test_first_account_is_admin_and_admin_login_is_staff_only(self):
        first, second = self.signup("carol"), self.signup("dave")  # neither is in ADMIN_EMAILS

        r = second.post("/api/login", json=dict(username="dave", password=PW, portal="admin"))
        self.assertEqual(r.status_code, 403)

        r = first.post("/api/login", json=dict(username="carol", password=PW, portal="admin"))
        self.assertTrue(r.get_json()["mfa_required"])
        r = first.post("/api/login/verify", json=dict(otp=self.codes[-1]))
        self.assertEqual(r.get_json()["user"]["role"], "admin")

        self.assertEqual(self.signin(second, "dave")["role"], "user")  # user login still works

    def test_sharing_is_read_only_and_can_be_revoked(self):
        from io import BytesIO

        owner, friend, stranger = self.signup("alice"), self.signup("bob"), self.signup("eve")
        for client, name in ((owner, "alice"), (friend, "bob"), (stranger, "eve")):
            self.signin(client, name)

        r = owner.post("/api/upload", data={"file": (BytesIO(b"top secret"), "plan.txt")},
                       content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        file_id = r.get_json()["file"]["id"]

        # only the owner can share; unknown users and self are refused
        self.assertEqual(friend.post(f"/api/files/{file_id}/shares", json=dict(user="eve")).status_code, 404)
        self.assertEqual(owner.post(f"/api/files/{file_id}/shares", json=dict(user="nobody")).status_code, 404)
        self.assertEqual(owner.post(f"/api/files/{file_id}/shares", json=dict(user="alice")).status_code, 400)

        r = owner.post(f"/api/files/{file_id}/shares", json=dict(user="bob"))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        share_id = r.get_json()["share"]["id"]
        self.assertEqual(owner.post(f"/api/files/{file_id}/shares", json=dict(user="bob")).status_code, 409)

        # the recipient can list and download it, through the share only
        shared = friend.get("/api/shared").get_json()["shared"]
        self.assertEqual([s["original_filename"] for s in shared], ["plan.txt"])
        r = friend.get(f"/api/shared/{share_id}/download")
        self.assertEqual(r.data, b"top secret")
        self.assertEqual(friend.get(f"/api/files/{file_id}/download").status_code, 404)
        self.assertEqual(friend.delete(f"/api/files/{file_id}").status_code, 404)

        # nobody else can use the share
        self.assertEqual(stranger.get(f"/api/shared/{share_id}/download").status_code, 404)
        self.assertEqual(stranger.get("/api/shared").get_json()["shared"], [])

        # revoking ends access; deleting the file removes remaining shares
        r = owner.delete(f"/api/files/{file_id}/shares/{share_id}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(friend.get(f"/api/shared/{share_id}/download").status_code, 404)

        owner.post(f"/api/files/{file_id}/shares", json=dict(user="eve"))
        self.assertEqual(owner.delete(f"/api/files/{file_id}").status_code, 200)
        self.assertEqual(stranger.get("/api/shared").get_json()["shared"], [])

    def test_disabled_account_is_signed_out_and_cannot_log_in(self):
        admin, bob = self.signup("alice"), self.signup("bob")
        self.signin(admin, "alice")
        bob_id = self.signin(bob, "bob")["id"]

        r = admin.post(f"/api/admin/users/{bob_id}/disabled", json=dict(disabled=True))
        self.assertEqual(r.status_code, 200)

        self.assertIsNone(bob.get("/api/me").get_json()["user"])
        r = bob.post("/api/login", json=dict(username="bob", password=PW))
        self.assertEqual(r.status_code, 403)

    def test_users_only_see_their_own_events(self):
        admin, bob = self.signup("alice"), self.signup("bob")
        self.signin(admin, "alice")
        self.signin(bob, "bob")
        # /api/security-events is always filtered by owner, even for an admin
        for e in admin.get("/api/security-events").get_json()["events"]:
            self.assertNotIn("bob", e["description"])

    # ---- headers -----------------------------------------------------
    def test_security_headers(self):
        r = self.app.test_client().get("/api/csrf")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Strict-Transport-Security", r.headers)  # plain HTTP


class ForceHttpsTest(_ApiCase):
    ENV = {"FORCE_HTTPS": "1"}

    def test_http_is_redirected_and_https_gets_hsts(self):
        c = self.app.test_client()
        r = c.get("/api/csrf")
        self.assertEqual(r.status_code, 308)
        self.assertTrue(r.location.startswith("https://"))

        r = c.get("/api/csrf", headers={"X-Forwarded-Proto": "https"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("max-age=", r.headers["Strict-Transport-Security"])


if __name__ == "__main__":
    unittest.main()
