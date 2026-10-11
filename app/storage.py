"""Where the encrypted bytes live: local disk, or the database (Vercel)."""

from pathlib import Path

from flask import current_app


def _disk_dir():
    project_root = Path(current_app.root_path).parent
    storage_dir = project_root / "storage" / "encrypted"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir


def _use_db():
    return current_app.config["STORAGE_BACKEND"] == "db"


def _safe_name(record):
    name = record.encrypted_filename
    if not name or Path(name).name != name:
        raise ValueError("Invalid stored filename.")
    return name


def write_encrypted(record, data):
    """Persist encrypted bytes for a (not yet committed) SecureFile."""
    if _use_db():
        record.encrypted_blob = data
        return
    with (_disk_dir() / _safe_name(record)).open("xb") as fh:
        fh.write(data)


def read_encrypted(record):
    """Return the stored encrypted bytes. Raises FileNotFoundError if missing."""
    if _use_db():
        blob = record.encrypted_blob
        if blob is None:
            raise FileNotFoundError("blob missing")
        return bytes(blob)
    return (_disk_dir() / _safe_name(record)).read_bytes()


def delete_encrypted(record):
    if _use_db():
        record.encrypted_blob = None
        return
    try:
        (_disk_dir() / _safe_name(record)).unlink(missing_ok=True)
    except (OSError, ValueError):
        current_app.logger.exception("Could not delete encrypted file")
