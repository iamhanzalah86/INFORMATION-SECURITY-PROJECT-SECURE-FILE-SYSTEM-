"""JSON API used by the React frontend (frontend/).

It reuses the exact same models, OTP, crypto, storage and integrity code as the
original server-rendered routes (app/routes.py), so behaviour and security rules
are unchanged. CSRF protection stays ON: the frontend reads a token from
GET /api/csrf and sends it back in the X-CSRFToken header.
"""

import hashlib
import os
import uuid
from datetime import timedelta
from functools import wraps
from io import BytesIO

from flask import Blueprint, current_app, jsonify, request, send_file, session
from flask_login import current_user, login_user, logout_user
from flask_wtf.csrf import generate_csrf
from sqlalchemy import func, or_, select
from werkzeug.utils import secure_filename

from app import db
from app.auth import hash_password, verify_password
from app.crypto import decrypt_bytes, encrypt_bytes
from app.integrity import verify_data_integrity
from app.models import SecureFile, SecurityEvent, User, utcnow
from app.otp import (
    PURPOSE_RECOVER,
    PURPOSE_REGISTER,
    PURPOSE_RESET,
    issue_otp,
    verify_otp,
)
from app.routes import (
    EMAIL_RE,
    LOGIN_MAX_FAILS,
    LOGIN_WINDOW_MINUTES,
    USERNAME_RE,
    check_password_rules,
    log_event,
    mask_email,
)
from app.storage import (
    delete_encrypted,
    read_backup,
    read_encrypted,
    replace_primary,
    write_encrypted,
)

api = Blueprint("api", __name__, url_prefix="/api")


# --------------------------------------------------
# helpers
# --------------------------------------------------

def err(message, status=400, **extra):
    return jsonify(error=message, **extra), status


def login_required_api(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return err("Please log in to access this page.", 401, unauthorized=True)
        return fn(*args, **kwargs)

    return wrapper


def body():
    """JSON body as a dict (empty dict when missing / invalid)."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def iso(dt):
    return dt.isoformat() if dt else None


def user_json(user):
    return {"id": user.id, "username": user.username, "email": user.email}


def file_json(f):
    return {
        "id": f.id,
        "original_filename": f.original_filename,
        "sha256_hash": f.sha256_hash,
        "file_size": f.file_size,
        "status": f.status,
        "uploaded_at": iso(f.uploaded_at),
        "has_backup": bool(f.has_backup),
    }


def event_json(e):
    return {
        "id": e.id,
        "event_type": e.event_type,
        "description": e.description,
        "file_id": e.file_id,
        "timestamp": iso(e.timestamp),
    }


def dev_tools_enabled():
    """Demo-only helpers (e.g. simulate tampering). Off unless DEV_TOOLS=1 in .env."""
    return os.environ.get("DEV_TOOLS", "0").strip() == "1"


def own_file(file_id):
    return db.session.scalar(
        select(SecureFile).where(
            SecureFile.id == file_id, SecureFile.user_id == current_user.id
        )
    )


def not_recoverable(f):
    """Error response when a file can't be recovered, else None."""
    if f.status != "TAMPERED":
        return err("This file is not marked as tampered.", 409, redirect=True)
    if not f.has_backup:
        return err(
            "No backup exists for this file (it was uploaded before backups "
            "were enabled). Delete it and upload the original again.",
            409,
            redirect=True,
        )
    return None


# --------------------------------------------------
# errors -> JSON
# --------------------------------------------------

@api.app_errorhandler(400)
def _bad_request(e):
    if request.path.startswith("/api/"):
        name = e.__class__.__name__
        desc = getattr(e, "description", "Bad request.")
        return err(desc, 400, csrf=(name == "CSRFError"))
    return e


@api.app_errorhandler(413)
def _too_large(e):
    if request.path.startswith("/api/"):
        mb = current_app.config["MAX_UPLOAD_BYTES"] / (1024 * 1024)
        return err(f"File exceeds the {mb:g} MB upload limit.", 413)
    return e


# --------------------------------------------------
# session / csrf
# --------------------------------------------------

@api.get("/csrf")
def csrf_token():
    return jsonify(token=generate_csrf())


@api.get("/me")
def me():
    if current_user.is_authenticated:
        return jsonify(user=user_json(current_user))
    return jsonify(user=None)


# --------------------------------------------------
# registration + email verification
# --------------------------------------------------

@api.post("/register")
def register():
    if current_user.is_authenticated:
        return err("You are already logged in.", 409)

    d = body()
    username = str(d.get("username", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    password = str(d.get("password", ""))
    confirm = str(d.get("confirm_password", ""))

    if not username or not email or not password:
        return err("Username, email and password are required.")
    if not USERNAME_RE.match(username):
        return err("Username must be 3-30 characters: letters, numbers, . _ -")
    if len(email) > 255 or not EMAIL_RE.match(email):
        return err("Please enter a valid email address.")
    problem = check_password_rules(password, confirm)
    if problem:
        return err(problem)

    matches = db.session.scalars(
        select(User).where(
            or_(func.lower(User.username) == username.lower(), User.email == email)
        )
    ).all()

    if any(u.is_verified for u in matches):
        taken_email = any(u.is_verified and u.email == email for u in matches)
        return err(
            "An account with this email already exists."
            if taken_email
            else "Username is already registered."
        )

    for stale in matches:  # unverified leftovers can be replaced
        db.session.delete(stale)
    db.session.flush()

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_verified=False,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Registration failed")
        return err("Registration failed. Please try again.", 500)

    ok, message = issue_otp(email, PURPOSE_REGISTER, username)
    session["verify_email"] = email
    if not ok:
        message += " You can resend the code below."
    return jsonify(
        otp_sent=ok, message=message, masked_email=mask_email(email)
    )


def _pending_verify_user():
    email = session.get("verify_email")
    user = db.session.scalar(select(User).where(User.email == email)) if email else None
    return email, user


@api.get("/verify-email")
def verify_email_status():
    email, user = _pending_verify_user()
    if user is None or user.is_verified:
        session.pop("verify_email", None)
        if user is not None and user.is_verified:
            return err("Email already verified. Please log in.", 409, goto="login")
        return err("Please register first.", 404, goto="register")
    return jsonify(
        masked_email=mask_email(email), ttl=current_app.config["OTP_TTL_MINUTES"]
    )


@api.post("/verify-email")
def verify_email():
    email, user = _pending_verify_user()
    if user is None or user.is_verified:
        session.pop("verify_email", None)
        return err("Please register first.", 404, goto="register")

    ok, message = verify_otp(email, PURPOSE_REGISTER, str(body().get("otp", "")))
    if not ok:
        return err(message)

    user.is_verified = True
    log_event("ACCOUNT_VERIFIED", f"Email verified for {user.username}.", user_id=user.id)
    db.session.commit()
    session.pop("verify_email", None)
    return jsonify(message="Email verified! You can now log in.")


@api.post("/verify-email/resend")
def verify_email_resend():
    email, user = _pending_verify_user()
    if user is None or user.is_verified:
        return err("Please register first.", 404, goto="register")
    ok, message = issue_otp(email, PURPOSE_REGISTER, user.username)
    return jsonify(ok=ok, message=message)


# --------------------------------------------------
# login / logout
# --------------------------------------------------

@api.post("/login")
def login():
    if current_user.is_authenticated:
        return jsonify(user=user_json(current_user))

    d = body()
    identifier = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))

    user = db.session.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == identifier.lower(),
                User.email == identifier.lower(),
            )
        )
    )

    if user is not None:  # brute-force throttle per account
        since = utcnow() - timedelta(minutes=LOGIN_WINDOW_MINUTES)
        fails = db.session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(
                SecurityEvent.user_id == user.id,
                SecurityEvent.event_type == "LOGIN_FAILED",
                SecurityEvent.timestamp >= since,
            )
        )
        if fails >= LOGIN_MAX_FAILS:
            return err(
                "Too many failed attempts. Try again in a few minutes "
                "or reset your password.",
                429,
            )

    if user and verify_password(user.password_hash, password):
        if not user.is_verified:
            session["verify_email"] = user.email
            ok, message = issue_otp(user.email, PURPOSE_REGISTER, user.username)
            return jsonify(
                verify_required=True,
                otp_sent=ok,
                masked_email=mask_email(user.email),
                message="Please verify your email first. "
                + (message if ok else "Use the resend button below."),
            )

        login_user(user)
        user.last_login_at = utcnow()
        log_event("LOGIN_SUCCESS", "Signed in successfully.", user_id=user.id)
        db.session.commit()
        return jsonify(user=user_json(user))

    if user:
        log_event(
            "LOGIN_FAILED",
            "Failed sign-in attempt (wrong password).",
            user_id=user.id,
        )
        db.session.commit()
    return err("Invalid username or password.", 401)


@api.post("/logout")
@login_required_api
def logout():
    log_event("LOGOUT", "Signed out.", user_id=current_user.id)
    db.session.commit()
    logout_user()
    return jsonify(message="You have been logged out.")


# --------------------------------------------------
# forgot / reset password
# --------------------------------------------------

@api.post("/forgot-password")
def forgot_password():
    if current_user.is_authenticated:
        return err("You are already logged in.", 409)

    email = str(body().get("email", "")).strip().lower()
    if not EMAIL_RE.match(email):
        return err("Please enter a valid email address.")

    user = db.session.scalar(
        select(User).where(User.email == email, User.is_verified.is_(True))
    )
    if user is not None:
        ok, _ = issue_otp(email, PURPOSE_RESET, user.username)
        if ok:
            log_event(
                "PASSWORD_RESET_REQUESTED",
                "A password reset code was emailed.",
                user_id=user.id,
            )
            db.session.commit()

    session["reset_email"] = email  # same response whether or not the account exists
    return jsonify(
        message="If an account exists for that email, a 6-digit code has been sent.",
        masked_email=mask_email(email),
    )


@api.get("/reset-password")
def reset_password_status():
    email = session.get("reset_email")
    if not email:
        return err("Request a reset code first.", 404, goto="forgot")
    return jsonify(
        masked_email=mask_email(email), ttl=current_app.config["OTP_TTL_MINUTES"]
    )


@api.post("/reset-password")
def reset_password():
    email = session.get("reset_email")
    if not email:
        return err("Request a reset code first.", 404, goto="forgot")

    d = body()
    problem = check_password_rules(str(d.get("password", "")), str(d.get("confirm_password", "")))
    if problem:
        return err(problem)

    user = db.session.scalar(
        select(User).where(User.email == email, User.is_verified.is_(True))
    )
    ok, message = verify_otp(email, PURPOSE_RESET, str(d.get("otp", "")))
    if not ok or user is None:
        return err(message if not ok else "Invalid or expired code.")

    user.password_hash = hash_password(str(d.get("password", "")))
    log_event("PASSWORD_RESET", "Password was reset using an emailed code.", user_id=user.id)
    db.session.execute(  # clear the failed-login lockout counter
        SecurityEvent.__table__.update()
        .where(
            SecurityEvent.user_id == user.id,
            SecurityEvent.event_type == "LOGIN_FAILED",
        )
        .values(event_type="LOGIN_FAILED_CLEARED")
    )
    db.session.commit()
    session.pop("reset_email", None)
    return jsonify(message="Password updated. You can now log in.")


@api.post("/reset-password/resend")
def reset_password_resend():
    email = session.get("reset_email")
    if not email:
        return err("Request a reset code first.", 404, goto="forgot")
    user = db.session.scalar(
        select(User).where(User.email == email, User.is_verified.is_(True))
    )
    if user is not None:
        issue_otp(email, PURPOSE_RESET, user.username)
    return jsonify(
        ok=True,
        message="If an account exists for that email, a new code has been sent.",
    )


# --------------------------------------------------
# dashboard
# --------------------------------------------------

@api.get("/dashboard")
@login_required_api
def dashboard():
    files = db.session.scalars(
        select(SecureFile)
        .where(SecureFile.user_id == current_user.id)
        .order_by(SecureFile.uploaded_at.desc())
    ).all()
    tampered = sum(1 for f in files if f.status == "TAMPERED")

    last_scan = db.session.scalar(
        select(SecurityEvent.timestamp)
        .where(
            SecurityEvent.user_id == current_user.id,
            SecurityEvent.event_type == "INTEGRITY_SCAN",
        )
        .order_by(SecurityEvent.id.desc())
        .limit(1)
    )
    recent = db.session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.id.desc())
        .limit(6)
    ).all()

    # events per day for the last 7 days (UTC) -> small activity chart
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=6)
    rows = db.session.execute(
        select(SecurityEvent.timestamp, SecurityEvent.event_type).where(
            SecurityEvent.user_id == current_user.id,
            SecurityEvent.timestamp >= start,
        )
    ).all()
    buckets = {
        (start + timedelta(days=i)).date(): {"total": 0, "alerts": 0} for i in range(7)
    }
    for ts, etype in rows:
        b = buckets.get(ts.date())
        if b is None:
            continue
        b["total"] += 1
        if "TAMPER" in etype or etype in ("LOGIN_FAILED", "RECOVERY_FAILED"):
            b["alerts"] += 1
    activity = [
        {"date": d.isoformat(), "total": v["total"], "alerts": v["alerts"]}
        for d, v in buckets.items()
    ]

    return jsonify(
        files=[file_json(f) for f in files],
        stats={
            "total": len(files),
            "secure": len(files) - tampered,
            "tampered": tampered,
            "size": sum(f.file_size for f in files),
            "last_scan": iso(last_scan),
            "last_upload": iso(max((f.uploaded_at for f in files), default=None)),
        },
        recent_events=[event_json(e) for e in recent],
        activity=activity,
        max_mb=current_app.config["MAX_UPLOAD_BYTES"] / (1024 * 1024),
        dev_tools=dev_tools_enabled(),
    )


# --------------------------------------------------
# upload / download / delete
# --------------------------------------------------

@api.post("/upload")
@login_required_api
def upload_file():
    max_bytes = current_app.config["MAX_UPLOAD_BYTES"]
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return err("Please select a file to upload.")

    original_filename = secure_filename(uploaded.filename)
    if not original_filename:
        return err("Invalid filename.")

    plaintext = uploaded.stream.read(max_bytes + 1)
    if len(plaintext) > max_bytes:
        return err(f"File exceeds the {max_bytes / (1024 * 1024):g} MB upload limit.", 413)
    if not plaintext:
        return err("Empty files are not allowed.")

    record = None
    try:
        encrypted = encrypt_bytes(plaintext)
        integrity_hash = hashlib.sha256(encrypted).hexdigest()
        record = SecureFile(
            user_id=current_user.id,
            original_filename=original_filename,
            encrypted_filename=f"{uuid.uuid4().hex}.bin",
            file_size=len(plaintext),
            sha256_hash=integrity_hash,
            encryption_algorithm="AES-256-GCM",
            status="SECURE",
        )
        write_encrypted(record, encrypted)
        db.session.add(record)
        db.session.flush()
        log_event(
            "FILE_UPLOADED",
            f"Encrypted file uploaded: {original_filename}. "
            f"Stored SHA-256: {integrity_hash}",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        if record is not None:
            delete_encrypted(record)
        current_app.logger.exception("Secure file upload failed")
        return err("Upload failed. Check the application logs.", 500)

    return jsonify(
        message=f"'{original_filename}' was encrypted and stored securely.",
        file=file_json(record),
    )


@api.get("/files/<int:file_id>/download")
@login_required_api
def download_file(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)

    def record_tampering(reason):
        try:
            record.status = "TAMPERED"
            log_event(
                "FILE_TAMPERING_DETECTED",
                f"Integrity verification failed for {record.original_filename}: {reason}",
                user_id=current_user.id,
                file_id=record.id,
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to record tampering event")

    try:
        encrypted = read_encrypted(record)
    except (FileNotFoundError, ValueError):
        record_tampering("Encrypted file is missing from storage.")
        return err("Security alert: the stored file is missing. Download blocked.", 409)
    except OSError:
        current_app.logger.exception("Could not read encrypted file %s", record.id)
        return err("Unable to read the stored file.", 500)

    if not verify_data_integrity(encrypted, record.sha256_hash):
        record_tampering("Stored SHA-256 hash does not match.")
        current_app.logger.warning("Possible file tampering detected for record %s", record.id)
        return err(
            "SECURITY ALERT: File integrity check failed. The download has been blocked.",
            409,
        )

    try:
        plaintext = decrypt_bytes(encrypted)
    except (ValueError, TypeError):
        record_tampering("AES-GCM authentication failed after hash verification.")
        return err(
            "Security alert: file authentication failed. The download has been blocked.",
            409,
        )

    if record.status != "TAMPERED":
        record.status = "SECURE"
    log_event(
        "FILE_DOWNLOADED",
        f"Verified and downloaded {record.original_filename}.",
        user_id=current_user.id,
        file_id=record.id,
    )
    db.session.commit()

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=record.original_filename,
        mimetype="application/octet-stream",
    )


@api.delete("/files/<int:file_id>")
@login_required_api
def delete_file(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    name = record.original_filename
    try:
        delete_encrypted(record)
        log_event("FILE_DELETED", f"File deleted: {name}.", user_id=current_user.id)
        db.session.execute(
            SecurityEvent.__table__.update()
            .where(SecurityEvent.file_id == record.id)
            .values(file_id=None)
        )
        db.session.delete(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("File deletion failed")
        return err("Could not delete the file.", 500)
    return jsonify(message=f"'{name}' was permanently deleted.")


# --------------------------------------------------
# integrity scan
# --------------------------------------------------

@api.post("/integrity-scan")
@login_required_api
def integrity_scan():
    files = db.session.scalars(
        select(SecureFile).where(SecureFile.user_id == current_user.id)
    ).all()

    checked = secure_count = issue_count = 0
    for record in files:
        try:
            data = read_encrypted(record)
            if verify_data_integrity(data, record.sha256_hash):
                valid, reason = True, "OK"
            else:
                valid, reason = False, "HASH_MISMATCH"
        except (FileNotFoundError, ValueError):
            valid, reason = False, "MISSING"
        except OSError:
            valid, reason = False, "UNREADABLE"

        checked += 1
        if valid:
            secure_count += 1
            if record.status != "TAMPERED":
                record.status = "SECURE"
        else:
            issue_count += 1
            was_tampered = record.status == "TAMPERED"
            record.status = "TAMPERED"
            if not was_tampered:
                log_event(
                    "FILE_TAMPERING_DETECTED",
                    f"Integrity scan detected {reason} for {record.original_filename}.",
                    user_id=current_user.id,
                    file_id=record.id,
                )

    log_event(
        "INTEGRITY_SCAN",
        f"Integrity scan: {checked} checked, {secure_count} verified, {issue_count} issue(s).",
        user_id=current_user.id,
    )
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Integrity scan could not be saved")
        return err("Unable to save integrity scan results.", 500)

    return jsonify(
        message=f"Integrity scan completed: {checked} checked, "
        f"{secure_count} verified, {issue_count} issue(s).",
        issues=issue_count,
    )


# --------------------------------------------------
# recover a tampered file (password + emailed OTP)
# --------------------------------------------------

@api.get("/files/<int:file_id>")
@login_required_api
def get_file(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404, redirect=True)
    blocked = not_recoverable(record)
    if blocked:
        return blocked
    return jsonify(file=file_json(record))


@api.post("/files/<int:file_id>/recover")
@login_required_api
def recover_start(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404, redirect=True)
    blocked = not_recoverable(record)
    if blocked:
        return blocked

    since = utcnow() - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    fails = db.session.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(
            SecurityEvent.user_id == current_user.id,
            SecurityEvent.event_type == "RECOVERY_FAILED",
            SecurityEvent.timestamp >= since,
        )
    )
    if fails >= LOGIN_MAX_FAILS:
        return err("Too many failed recovery attempts. Try again later.", 429)

    if not verify_password(current_user.password_hash, str(body().get("password", ""))):
        log_event(
            "RECOVERY_FAILED",
            f"Wrong password while trying to recover {record.original_filename}.",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
        return err("Incorrect password.", 401)

    ok, message = issue_otp(current_user.email, PURPOSE_RECOVER, current_user.username)
    if ok or message.startswith("Please wait"):
        session["recover_file"] = record.id
        return jsonify(
            masked_email=mask_email(current_user.email),
            message=message if ok else "A code was already sent. Check your email.",
            category="success" if ok else "info",
        )
    return err(message)


@api.post("/files/<int:file_id>/recover/verify")
@login_required_api
def recover_verify(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404, redirect=True)
    blocked = not_recoverable(record)
    if blocked:
        return blocked

    if session.get("recover_file") != record.id:
        return err("Confirm your password first.", 409, restart=True)

    ok, message = verify_otp(current_user.email, PURPOSE_RECOVER, str(body().get("otp", "")))
    if not ok:
        return err(message)

    session.pop("recover_file", None)

    try:  # the backup is only trusted if AES-GCM authentication succeeds
        backup = read_backup(record)
        decrypt_bytes(backup)
    except (FileNotFoundError, ValueError, TypeError, OSError):
        log_event(
            "RECOVERY_FAILED",
            f"Backup of {record.original_filename} is missing or damaged.",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
        return err(
            "The backup copy is also damaged, so this file cannot be restored. "
            "Delete it and upload the original again.",
            409,
            redirect=True,
        )

    try:
        replace_primary(record, backup)
        record.sha256_hash = hashlib.sha256(backup).hexdigest()
        record.status = "SECURE"
        log_event(
            "FILE_RECOVERED",
            f"{record.original_filename} was restored from its verified "
            f"backup after password + email OTP confirmation.",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("File recovery failed")
        return err("Recovery failed. Please try again.", 500, redirect=True)

    return jsonify(message=f"'{record.original_filename}' was restored and verified.")


# --------------------------------------------------
# security events
# --------------------------------------------------

@api.get("/security-events")
@login_required_api
def security_events():
    events = db.session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.id.desc())
        .limit(200)
    ).all()
    return jsonify(events=[event_json(e) for e in events])


# --------------------------------------------------
# DEMO ONLY: simulate tampering (enabled with DEV_TOOLS=1)
# --------------------------------------------------

@api.post("/dev/tamper/<int:file_id>")
@login_required_api
def dev_tamper(file_id):
    if not dev_tools_enabled():
        return err("Not found.", 404)
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    try:
        data = bytearray(read_encrypted(record))
        if not data:
            return err("Stored file is empty.", 409)
        data[len(data) // 2] ^= 0xFF  # flip one byte in the primary copy
        replace_primary(record, bytes(data))  # the backup copy is left untouched
        log_event(
            "DEMO_TAMPER",
            f"[DEMO] Stored copy of {record.original_filename} was modified on purpose "
            f"to test tamper detection.",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
    except (FileNotFoundError, ValueError, OSError):
        db.session.rollback()
        return err("Could not modify the stored file.", 500)
    return jsonify(
        message=f"Demo: '{record.original_filename}' was modified on disk. "
        f"Run an integrity scan or try a download to see it detected."
    )
