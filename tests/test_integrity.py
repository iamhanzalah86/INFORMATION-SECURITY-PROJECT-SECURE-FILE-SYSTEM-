
import tempfile
import unittest
from pathlib import Path

from app.integrity import (
    calculate_sha256,
    verify_file_integrity,
)


class TestFileIntegrity(unittest.TestCase):

    def test_unchanged_file_passes(self):
        original = b"Confidential project document."

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.bin"
            path.write_bytes(original)

            expected_hash = calculate_sha256(original)

            valid, reason = verify_file_integrity(
                path, expected_hash
            )

            self.assertTrue(valid)
            self.assertEqual(reason, "OK")

    def test_modified_file_fails(self):
        original = b"Original encrypted bytes."
        modified = b"Modified encrypted bytes."

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.bin"
            path.write_bytes(modified)

            expected_hash = calculate_sha256(original)

            valid, reason = verify_file_integrity(
                path, expected_hash
            )

            self.assertFalse(valid)
            self.assertEqual(reason, "HASH_MISMATCH")

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.bin"

            valid, reason = verify_file_integrity(
                path, "somehash"
            )

            self.assertFalse(valid)
            self.assertEqual(reason, "MISSING")

    def test_missing_expected_hash_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.bin"
            path.write_bytes(b"Encrypted bytes")

            valid, reason = verify_file_integrity(path, "")

            self.assertFalse(valid)
            self.assertEqual(reason, "HASH_MISMATCH")


if __name__ == "__main__":
    unittest.main()
