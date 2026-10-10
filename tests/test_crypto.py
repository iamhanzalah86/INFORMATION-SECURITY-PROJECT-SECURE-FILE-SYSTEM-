
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


if __name__ == "__main__":
    unittest.main()
