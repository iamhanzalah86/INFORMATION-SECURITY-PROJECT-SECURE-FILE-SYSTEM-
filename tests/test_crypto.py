
import unittest

from app.crypto import encrypt_bytes, decrypt_bytes


class TestAESGCM(unittest.TestCase):

    def test_encrypt_and_decrypt(self):
        original = b"Confidential Information Security Project File"

        encrypted = encrypt_bytes(original)

        self.assertNotEqual(encrypted, original)
        self.assertEqual(decrypt_bytes(encrypted), original)

    def test_each_encryption_uses_a_fresh_nonce(self):
        original = b"Test document"

        encrypted1 = encrypt_bytes(original)
        encrypted2 = encrypt_bytes(original)

        self.assertNotEqual(encrypted1[:12], encrypted2[:12])

    def test_tampering_is_rejected(self):
        original = b"Sensitive document contents"

        encrypted = bytearray(encrypt_bytes(original))

        # Modify the first ciphertext byte after the 12-byte nonce.
        encrypted[12] ^= 1

        with self.assertRaises(ValueError):
            decrypt_bytes(bytes(encrypted))

    def test_wrong_key_is_rejected(self):
        original = b"Confidential data"
        encrypted = encrypt_bytes(original)

        from app.crypto import load_aes_key
        import os

        correct_key = load_aes_key()
        wrong_key = bytes(byte ^ 1 for byte in correct_key)

        # Temporarily substitute a different valid AES-256 key.
        import base64

        os.environ["AES_KEY_B64"] = base64.b64encode(
            wrong_key
        ).decode("ascii")

        try:
            with self.assertRaises(ValueError):
                decrypt_bytes(encrypted)
        finally:
            os.environ["AES_KEY_B64"] = base64.b64encode(
                correct_key
            ).decode("ascii")


class TestEnvelopeEncryption(unittest.TestCase):
    """Per-file data keys wrapped by the master key, and key rotation."""

    def _with_keys(self, current, old=None):
        import os
        from unittest import mock

        env = {"AES_KEY_B64": current, "AES_KEY_OLD_B64": old or ""}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        return patcher

    @staticmethod
    def _new_key():
        import base64
        import os

        return base64.b64encode(os.urandom(32)).decode("ascii")

    def test_files_written_before_envelope_encryption_still_open(self):
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from app.crypto import load_aes_key

        nonce = os.urandom(12)
        legacy = nonce + AESGCM(load_aes_key()).encrypt(nonce, b"old file", None)

        self.assertEqual(decrypt_bytes(legacy), b"old file")

    def test_key_header_cannot_be_moved_to_another_file(self):
        from app.crypto import WRAP_LEN

        first = encrypt_bytes(b"A" * 40)
        second = encrypt_bytes(b"B" * 40)

        with self.assertRaises(ValueError):
            decrypt_bytes(first[:WRAP_LEN] + second[WRAP_LEN:])

    def test_rotation_keeps_old_files_readable(self):
        from app.crypto import rewrap_bytes

        old_key, new_key = self._new_key(), self._new_key()

        first = self._with_keys(old_key)
        encrypted = encrypt_bytes(b"written with the old key")
        first.stop()

        second = self._with_keys(new_key)  # rotated, old key forgotten
        with self.assertRaises(ValueError):
            decrypt_bytes(encrypted)
        second.stop()

        self._with_keys(new_key, old=old_key)  # rotated, old key kept for reading
        self.assertEqual(decrypt_bytes(encrypted), b"written with the old key")

        rewrapped = rewrap_bytes(encrypted)
        self._with_keys(new_key)  # after re-wrapping the old key is not needed
        self.assertEqual(decrypt_bytes(rewrapped), b"written with the old key")


if __name__ == "__main__":
    unittest.main()
