"""AES-256-GCM file encryption with envelope encryption (per-file data keys).

Key hierarchy
-------------
* Master key (KEK): ``AES_KEY_B64`` in the environment. It never touches file
  contents; it only wraps data keys.
* Data key (DEK): a fresh random 256-bit key for every encryption. The DEK is
  wrapped (AES-256-GCM) by the master key and stored in front of the ciphertext.

Stored layout (envelope format)::

    wrap_nonce(12) | wrapped_dek(32 + 16 tag) | data_nonce(12) | ciphertext | tag(16)

The wrapped-key header is also fed into the data encryption as associated data,
so a header from one file cannot be attached to the ciphertext of another.

Key rotation
------------
Put the new key in ``AES_KEY_B64`` and move the previous one(s) to
``AES_KEY_OLD_B64`` (comma separated). New files use the new key; older files
still open because their data keys are unwrapped with the old key.

Backward compatibility
----------------------
Files stored before envelope encryption (``nonce | ciphertext | tag`` encrypted
directly with the master key) are still readable.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
WRAP_LEN = NONCE_LEN + KEY_LEN + TAG_LEN          # 60 bytes
ENVELOPE_MIN = WRAP_LEN + NONCE_LEN + TAG_LEN     # 88 bytes
LEGACY_MIN = NONCE_LEN + TAG_LEN                  # 28 bytes
_WRAP_AAD = b"securevault:dek:v1"

_ERROR = (
    "Integrity verification failed: data may have been modified "
    "or the encryption key is incorrect."
)


def _decode_key(encoded, name):
    try:
        key = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{name} is not valid Base64.") from exc

    if len(key) != KEY_LEN:
        raise RuntimeError("AES-256 requires exactly 32 key bytes.")

    return key


def load_aes_key():
    """Load and validate the current AES-256 master key from the environment."""
    encoded_key = os.environ.get("AES_KEY_B64")

    if not encoded_key:
        raise RuntimeError("AES_KEY_B64 is missing from the environment.")

    return _decode_key(encoded_key, "AES_KEY_B64")


def load_old_keys():
    """Previous master keys (AES_KEY_OLD_B64, comma separated), newest first."""
    raw = os.environ.get("AES_KEY_OLD_B64", "")
    return [
        _decode_key(part.strip(), "AES_KEY_OLD_B64")
        for part in raw.split(",")
        if part.strip()
    ]


def _master_keys():
    return [load_aes_key()] + load_old_keys()


def encrypt_bytes(plaintext):
    """Encrypt bytes with a fresh data key, wrapped by the master key."""
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")

    master = load_aes_key()

    # 1. A new random data key for this file only.
    data_key = AESGCM.generate_key(bit_length=256)

    # 2. Wrap (encrypt) the data key with the master key.
    wrap_nonce = os.urandom(NONCE_LEN)
    header = wrap_nonce + AESGCM(master).encrypt(wrap_nonce, data_key, _WRAP_AAD)

    # 3. Encrypt the file with the data key; the header is authenticated too.
    data_nonce = os.urandom(NONCE_LEN)
    ciphertext_and_tag = AESGCM(data_key).encrypt(data_nonce, plaintext, header)

    return header + data_nonce + ciphertext_and_tag


def _decrypt_envelope(encrypted_data, master):
    """Return the plaintext, or None if this is not an envelope under `master`."""
    if len(encrypted_data) < ENVELOPE_MIN:
        return None

    header = encrypted_data[:WRAP_LEN]
    try:
        data_key = AESGCM(master).decrypt(
            header[:NONCE_LEN], header[NONCE_LEN:], _WRAP_AAD
        )
    except InvalidTag:
        return None  # not wrapped with this master key (or legacy format)

    data_nonce = encrypted_data[WRAP_LEN:WRAP_LEN + NONCE_LEN]
    try:
        return AESGCM(data_key).decrypt(
            data_nonce, encrypted_data[WRAP_LEN + NONCE_LEN:], header
        )
    except InvalidTag as exc:
        # The key header is genuine but the contents were changed.
        raise ValueError(_ERROR) from exc


def _decrypt_legacy(encrypted_data, master):
    """Pre-envelope format: nonce | ciphertext | tag, directly under the master key."""
    try:
        return AESGCM(master).decrypt(
            encrypted_data[:NONCE_LEN], encrypted_data[NONCE_LEN:], None
        )
    except InvalidTag:
        return None


def decrypt_bytes(encrypted_data):
    """Decrypt data and reject modifications using GCM authentication."""
    if not isinstance(encrypted_data, bytes):
        raise TypeError("Encrypted data must be bytes.")

    # 12-byte nonce + at least a 16-byte authentication tag.
    if len(encrypted_data) < LEGACY_MIN:
        raise ValueError("Encrypted data is too short.")

    keys = _master_keys()

    for master in keys:
        plaintext = _decrypt_envelope(encrypted_data, master)
        if plaintext is not None:
            return plaintext

    for master in keys:
        plaintext = _decrypt_legacy(encrypted_data, master)
        if plaintext is not None:
            return plaintext

    raise ValueError(_ERROR)


def rewrap_bytes(encrypted_data):
    """Re-encrypt stored data under the current master key (used after rotation).

    The result has different bytes, so the caller must also update the stored
    SHA-256 fingerprint of the file.
    """
    return encrypt_bytes(decrypt_bytes(encrypted_data))
