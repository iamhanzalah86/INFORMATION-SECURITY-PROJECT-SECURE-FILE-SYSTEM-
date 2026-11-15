from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import false

from app import db


def utcnow():
    """Naive UTC timestamp (consistent across SQLite and Postgres)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    # Role-based access control: "user" | "analyst" | "admin" (see app/rbac.py).
    role = db.Column(db.String(20), nullable=False, default="user", server_default="user")
    # Set by an administrator to block an account without deleting its data.
    disabled = db.Column(db.Boolean, nullable=False, default=False, server_default=false())
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    files = db.relationship("SecureFile", backref="owner", lazy=True)
    security_events = db.relationship("SecurityEvent", backref="user", lazy=True)

    @property
    def is_active(self):  # used by Flask-Login
        return not self.disabled


class SecureFile(db.Model):
    __tablename__ = "secure_files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    encryption_algorithm = db.Column(
        db.String(50), nullable=False, default="AES-256-GCM"
    )
    status = db.Column(db.String(30), nullable=False, default="SECURE")
    uploaded_at = db.Column(db.DateTime, default=utcnow)

    # Encrypted bytes, only used when STORAGE_BACKEND=db. Deferred so that
    # listing files never loads the blobs.
    encrypted_blob = db.deferred(db.Column(db.LargeBinary, nullable=True))

    # Second encrypted copy used for password + OTP recovery.
    has_backup = db.Column(db.Boolean, nullable=False, default=False)
    backup_blob = db.deferred(db.Column(db.LargeBinary, nullable=True))

    security_events = db.relationship("SecurityEvent", backref="file", lazy=True)
    # Deleting a file also removes every share of it.
    shares = db.relationship(
        "FileShare", backref="file", lazy=True, cascade="all, delete-orphan"
    )
    links = db.relationship(
        "ShareLink", backref="file", lazy=True, cascade="all, delete-orphan"
    )


class ShareLink(db.Model):
    """A secret link that lets whoever opens it (after signing in) read one file.

    Only the SHA-256 hash of the token is stored, so someone who reads the
    database still cannot rebuild a working link.
    """

    __tablename__ = "share_links"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("secure_files.id"), nullable=False, index=True
    )
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    uses = db.Column(db.Integer, nullable=False, default=0)


class FileShare(db.Model):
    """Read-only access to one file, granted by its owner to another user."""

    __tablename__ = "file_shares"
    __table_args__ = (
        db.UniqueConstraint("file_id", "recipient_id", name="uq_share_file_recipient"),
    )

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("secure_files.id"), nullable=False, index=True
    )
    recipient_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    recipient = db.relationship("User", foreign_keys=[recipient_id])


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey("secure_files.id"), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow)


class OtpCode(db.Model):
    """One-time passcodes sent by email (registration / password reset)."""

    __tablename__ = "otp_codes"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    purpose = db.Column(db.String(20), nullable=False)  # REGISTER | RESET
    code_hash = db.Column(db.String(64), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    used = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
