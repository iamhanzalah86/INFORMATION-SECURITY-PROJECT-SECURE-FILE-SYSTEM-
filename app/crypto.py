
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_aes_key():
    """Load and validate the AES-256 key from the environment."""
    encoded_key = os.environ.get("AES_KEY_B64")

    if not encoded_key:
        raise RuntimeError("AES_KEY_B64 is missing from the environment.")

    try:
        key = base64.b64decode(encoded_key, validate=True)
    except Exception as exc:
        raise RuntimeError("AES_KEY_B64 is not valid Base64.") from exc

    if len(key) != 32:
        raise RuntimeError("AES-256 requires exactly 32 key bytes.")

    return key


def encrypt_bytes(plaintext):
    """Encrypt bytes using AES-256-GCM."""
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")

    key = load_aes_key()

    # A fresh, random 12-byte nonce for each encryption.
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    # The result contains ciphertext followed by a 16-byte tag.
    ciphertext_and_tag = aesgcm.encrypt(
        nonce,
        plaintext,
        None
    )

    # Store nonce || ciphertext || authentication tag.
    return nonce + ciphertext_and_tag


def decrypt_bytes(encrypted_data):
    """Decrypt data and reject modifications using GCM authentication."""
    if not isinstance(encrypted_data, bytes):
        raise TypeError("Encrypted data must be bytes.")

    # 12-byte nonce + at least a 16-byte authentication tag.
    if len(encrypted_data) < 28:
        raise ValueError("Encrypted data is too short.")

    key = load_aes_key()

    nonce = encrypted_data[:12]
    ciphertext_and_tag = encrypted_data[12:]

    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(
            nonce,
            ciphertext_and_tag,
            None
        )
    except InvalidTag as exc:
        raise ValueError(
            "Integrity verification failed: data may have been modified "
            "or the encryption key is incorrect."
        ) from exc
