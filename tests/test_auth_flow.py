"""End-to-end tests: OTP registration, login, reset, upload, tamper, delete."""
import os
import re
import unittest
from unittest import mock

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("AES_KEY_B64", "F2rA60cDlTgz4IStKhqszRY1OHLYlFdDDvrjEkXs88g=")
os.environ["LEGACY_UI"] = "1"
os.environ["DATABASE_URL"] = ""
os.environ["STORAGE_BACKEND"] = "db"

from io import BytesIO  # noqa: E402

from app import create_app, db  # noqa: E402
from app.models import SecureFile  # noqa: E402


def csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class FlowTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        os.environ["DATABASE_URL"] = ""
        with mock.patch("app._database_uri", return_value=f"sqlite:///{self.tmp.name}"):
            self.app = create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.c = self.app.test_client()
        self.codes = []
        patcher = mock.patch(
            "app.otp.send_otp_email",
            side_effect=lambda to, code, *a, **k: self.codes.append(code) or True,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def register(self, user="alice", email="alice@example.com", pw="correct-horse-battery"):
        return self.c.post("/register", data=dict(
            username=user, email=email, password=pw, confirm_password=pw))

    def test_full_flow(self):
        r = self.register()
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.location.endswith("/verify-email"))
        self.assertEqual(len(self.codes), 1)

        # Cannot log in before verification.
        r = self.c.post("/login", data=dict(username="alice", password="correct-horse-battery"))
        self.assertTrue(r.location.endswith("/verify-email"))

        # Wrong then right code.
        r = self.c.post("/verify-email", data=dict(otp="000000"))
        self.assertIn(b"Incorrect code", r.data)
        r = self.c.post("/verify-email", data=dict(otp=self.codes[0]))
        self.assertTrue(r.location.endswith("/login"))

        r = self.c.post("/login", data=dict(username="alice@example.com", password="correct-horse-battery"))
        self.assertTrue(r.location.endswith("/dashboard"))
        self.assertEqual(self.c.get("/dashboard").status_code, 200)
        self.assertEqual(self.c.get("/security-events").status_code, 200)

        # Upload, download, tamper, delete.
        r = self.c.post("/upload", data={"file": (BytesIO(b"top secret"), "a.txt")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        r = self.c.get("/download/1")
        self.assertEqual(r.data, b"top secret")

        with self.app.app_context():
            f = db.session.get(SecureFile, 1)
            blob = bytearray(f.encrypted_blob)
            blob[20] ^= 1
            f.encrypted_blob = bytes(blob)
            db.session.commit()
        r = self.c.get("/download/1")
        self.assertEqual(r.status_code, 302)
        self.assertIn(b"TAMPERED", self.c.get("/dashboard").data.upper())
        self.c.post("/integrity-scan")
        self.c.post("/delete/1")
        with self.app.app_context():
            self.assertIsNone(db.session.get(SecureFile, 1))

    def test_recovery_needs_password_and_otp(self):
        self.register()
        self.c.post("/verify-email", data=dict(otp=self.codes[-1]))
        self.c.post("/login", data=dict(username="alice", password="correct-horse-battery"))
        self.c.post("/upload", data={"file": (BytesIO(b"precious data"), "p.txt")},
                    content_type="multipart/form-data")
        with self.app.app_context():
            f = db.session.get(SecureFile, 1)
            self.assertTrue(f.has_backup)
            blob = bytearray(f.encrypted_blob); blob[20] ^= 1
            f.encrypted_blob = bytes(blob); db.session.commit()
        self.c.get("/download/1")  # flags TAMPERED

        # Wrong password: no OTP is sent.
        n = len(self.codes)
        self.c.post("/recover/1", data=dict(password="wrong-password-xx"))
        self.assertEqual(len(self.codes), n)
        # OTP page is not reachable without the password step.
        r = self.c.get("/recover/1/verify")
        self.assertTrue(r.location.endswith("/recover/1"))

        r = self.c.post("/recover/1", data=dict(password="correct-horse-battery"))
        self.assertTrue(r.location.endswith("/recover/1/verify"))
        self.assertEqual(len(self.codes), n + 1)
        r = self.c.post("/recover/1/verify", data=dict(otp="000000"))
        self.assertIn(b"Incorrect code", r.data)
        r = self.c.post("/recover/1/verify", data=dict(otp=self.codes[-1]))
        self.assertTrue(r.location.endswith("/dashboard"))
        self.assertEqual(self.c.get("/download/1").data, b"precious data")

    def test_recovery_fails_if_backup_also_tampered(self):
        self.register()
        self.c.post("/verify-email", data=dict(otp=self.codes[-1]))
        self.c.post("/login", data=dict(username="alice", password="correct-horse-battery"))
        self.c.post("/upload", data={"file": (BytesIO(b"x" * 50), "p.txt")},
                    content_type="multipart/form-data")
        with self.app.app_context():
            f = db.session.get(SecureFile, 1)
            for col in ("encrypted_blob", "backup_blob"):
                b = bytearray(getattr(f, col)); b[20] ^= 1; setattr(f, col, bytes(b))
            db.session.commit()
        self.c.get("/download/1")
        self.c.post("/recover/1", data=dict(password="correct-horse-battery"))
        self.c.post("/recover/1/verify", data=dict(otp=self.codes[-1]))
        with self.app.app_context():
            self.assertEqual(db.session.get(SecureFile, 1).status, "TAMPERED")

    def test_reset_password(self):
        self.register()
        self.c.post("/verify-email", data=dict(otp=self.codes[-1]))
        self.c.get("/logout")

        # Unknown email: same response, no email sent.
        n = len(self.codes)
        r = self.c.post("/forgot-password", data=dict(email="nobody@example.com"))
        self.assertTrue(r.location.endswith("/reset-password"))
        self.assertEqual(len(self.codes), n)

        r = self.c.post("/forgot-password", data=dict(email="alice@example.com"))
        self.assertEqual(len(self.codes), n + 1)
        r = self.c.post("/reset-password", data=dict(
            otp=self.codes[-1], password="a-brand-new-password", confirm_password="a-brand-new-password"))
        self.assertTrue(r.location.endswith("/login"))
        r = self.c.post("/login", data=dict(username="alice", password="a-brand-new-password"))
        self.assertTrue(r.location.endswith("/dashboard"))

    def test_otp_lockout_and_duplicates(self):
        self.register()
        for i in range(5):
            r = self.c.post("/verify-email", data=dict(otp="111111"))
        self.assertIn(b"Too many incorrect attempts", r.data)
        # The real code no longer works once locked out.
        r = self.c.post("/verify-email", data=dict(otp=self.codes[0]))
        self.assertIn(b"No active code", r.data)
        # Short passwords rejected.
        r = self.register(user="bob", email="bob@example.com", pw="short")
        self.assertIn(b"at least 12", r.data)

    def test_csrf_enforced(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.assertEqual(self.c.post("/login", data={}).status_code, 400)

    def test_dashboard_requires_login(self):
        self.assertEqual(self.c.get("/dashboard").status_code, 302)


if __name__ == "__main__":
    unittest.main()
