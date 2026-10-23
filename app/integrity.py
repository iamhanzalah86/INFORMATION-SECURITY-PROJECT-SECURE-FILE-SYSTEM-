
import hashlib
import hmac
from pathlib import Path


def calculate_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_file_integrity(
    file_path: Path,
    expected_hash: str,
) -> tuple[bool, str]:
    """
    Verify a stored file against its expected SHA-256 hash.

    Returns:
        (True, "OK") when the file matches.
        (False, reason) when missing, unreadable, or modified.
    """
    try:
        data = file_path.read_bytes()
    except FileNotFoundError:
        return False, "MISSING"
    except OSError:
        return False, "UNREADABLE"

    actual_hash = calculate_sha256(data)

    if not expected_hash or not hmac.compare_digest(
        actual_hash, expected_hash
    ):
        return False, "HASH_MISMATCH"

    return True, "OK"


def verify_data_integrity(data: bytes, expected_hash: str) -> bool:
    """Compare in-memory encrypted bytes with the stored SHA-256."""
    if not expected_hash:
        return False
    return hmac.compare_digest(calculate_sha256(data), expected_hash)
