from datetime import datetime, timezone

from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    files = db.relationship(
        "SecureFile",
        backref="owner",
        lazy=True
    )

    security_events = db.relationship(
        "SecurityEvent",
        backref="user",
        lazy=True
    )


class SecureFile(db.Model):
    __tablename__ = "secure_files"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    encrypted_filename = db.Column(
        db.String(255),
        nullable=False
    )

    file_size = db.Column(
        db.Integer,
        nullable=False
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=False
    )

    encryption_algorithm = db.Column(
        db.String(50),
        nullable=False,
        default="AES-256-GCM"
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="SECURE"
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    security_events = db.relationship(
        "SecurityEvent",
        backref="file",
        lazy=True
    )


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("secure_files.id"),
        nullable=True
    )

    event_type = db.Column(
        db.String(50),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )