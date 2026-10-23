"""Where the encrypted bytes live: local disk, or the database (Vercel).

Every file has a primary copy and a backup copy (used for recovery).
"""

from pathlib import Path

from flask import current_app


def _root():
    return Path(current_app.root_path).parent / "storage"


def _disk_dir(kind="encrypted"):
    d = _root() / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def _use_db():
    return current_app.config["STORAGE_BACKEND"] == "db"


def _safe_name(record):
    name = record.encrypted_filename
    if not name or Path(name).name != name:
        raise ValueError("Invalid stored filename.")
    return name


def write_encrypted(record, data):
    """Persist primary + backup copies for a (not yet committed) SecureFile."""
    if _use_db():
        record.encrypted_blob = data
        record.backup_blob = data
    else:
        with (_disk_dir() / _safe_name(record)).open("xb") as fh:
            fh.write(data)
        with (_disk_dir("backup") / _safe_name(record)).open("xb") as fh:
            fh.write(data)
    record.has_backup = True


def read_encrypted(record):
    """Return the primary encrypted bytes. Raises FileNotFoundError if missing."""
    if _use_db():
        blob = record.encrypted_blob
        if blob is None:
            raise FileNotFoundError("blob missing")
        return bytes(blob)
    return (_disk_dir() / _safe_name(record)).read_bytes()


def read_backup(record):
    """Return the backup bytes. Raises FileNotFoundError if there is none."""
    if _use_db():
        blob = record.backup_blob
        if blob is None:
            raise FileNotFoundError("no backup")
        return bytes(blob)
    return (_disk_dir("backup") / _safe_name(record)).read_bytes()


def replace_primary(record, data):
    """Overwrite the primary copy (used by recovery)."""
    if _use_db():
        record.encrypted_blob = data
    else:
        (_disk_dir() / _safe_name(record)).write_bytes(data)


def delete_encrypted(record):
    if _use_db():
        record.encrypted_blob = None
        record.backup_blob = None
        return
    for kind in ("encrypted", "backup"):
        try:
            (_disk_dir(kind) / _safe_name(record)).unlink(missing_ok=True)
        except (OSError, ValueError):
            current_app.logger.exception("Could not delete encrypted file")
