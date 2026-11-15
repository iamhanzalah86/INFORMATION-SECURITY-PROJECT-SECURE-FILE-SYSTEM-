"""JSON API used by the React frontend (frontend/).

It reuses the exact same models, OTP, crypto, storage and integrity code as the
original server-rendered routes (app/routes.py), so behaviour and security rules
are unchanged. CSRF protection stays ON: the frontend reads a token from
GET /api/csrf and sends it back in the X-CSRFToken header.
"""

import hashlib
import hmac
import os
import secrets
import uuid
from datetime import timedelta
from functools import wraps
from io import BytesIO

from flask import Blueprint, current_app, jsonify, request, send_file, session
from flask_login import current_user, login_user, logout_user
from flask_wtf.csrf import generate_csrf
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import func, or_, select
from werkzeug.utils import secure_filename

from app import db
from app.auth import hash_password, verify_password
from app.crypto import decrypt_bytes, encrypt_bytes
from app.integrity import verify_data_integrity
from app.models import FileShare, SecureFile, SecurityEvent, ShareLink, User, utcnow
from app.otp import (
    PURPOSE_LOGIN,
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
from app.rbac import PERMISSIONS, ROLE_ADMIN, ROLE_ANALYST, ROLES, roles_required
from app.storage import (
    delete_encrypted,
    read_backup,
    read_encrypted,
    replace_primary,
    write_encrypted,
)

api = Blueprint("api", __name__, url_prefix="/api")

# Event types that count as alerts (besides anything containing "TAMPER").
ALERT_EVENTS = ("LOGIN_FAILED", "RECOVERY_FAILED", "MFA_FAILED", "ACCESS_DENIED")


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
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


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
    # The first verified account (or one listed in ADMIN_EMAILS) is the administrator.
    no_admin_yet = not db.session.scalar(
        select(func.count()).select_from(User).where(User.role == ROLE_ADMIN)
    )
    if no_admin_yet or user.email in current_app.config["ADMIN_EMAILS"]:
        user.role = ROLE_ADMIN
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
    admin_portal = str(d.get("portal", "")).strip().lower() == "admin"

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

        if user.disabled:
            log_event(
                "LOGIN_FAILED",
                "Sign-in blocked: this account is disabled.",
                user_id=user.id,
            )
            db.session.commit()
            return err(
                "This account has been disabled. Contact an administrator.", 403
            )

        if admin_portal and user.role not in (ROLE_ADMIN, ROLE_ANALYST):
            # Right password, but this is not a staff account.
            log_event(
                "ACCESS_DENIED",
                "Blocked: a normal user account tried the admin login.",
                user_id=user.id,
            )
            db.session.commit()
            return err(
                "This account does not have admin access. Use the User login.", 403
            )

        if current_app.config["LOGIN_MFA"] and _device_is_trusted(user):
            # This browser passed the emailed-code step recently ("remember this device").
            return _finish_login(
                user, "Signed in with password on a remembered device (code skipped)."
            )

        if current_app.config["LOGIN_MFA"]:
            # Step 2 of 2: the password was right, now prove access to the inbox.
            ok, message = issue_otp(user.email, PURPOSE_LOGIN, user.username)
            if not ok and not message.startswith("Please wait"):
                return err(message, 503)
            session["mfa_user"] = user.id
            return jsonify(
                mfa_required=True,
                otp_sent=ok,
                masked_email=mask_email(user.email),
                message="Enter the 6-digit code we emailed you to finish signing in."
                if ok
                else "A code was sent a moment ago. Check your email, or resend it "
                "in a minute.",
            )

        return _finish_login(user, "Signed in successfully.")

    if user:
        log_event(
            "LOGIN_FAILED",
            "Failed sign-in attempt (wrong password).",
            user_id=user.id,
        )
        db.session.commit()
    return err("Invalid username or password.", 401)


# ---- "Remember this device": skip the emailed code for 30 days ----------
# The browser keeps a signed, HttpOnly cookie. It only ever replaces the code
# step (the password is always required), it is tied to one account, it expires,
# and it stops working as soon as that account's password changes.
TRUST_COOKIE = "sv_trusted"
TRUST_DAYS = 30


def _trust_serializer():
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"], salt="trusted-device-v1"
    )


def _password_fingerprint(user):
    return hashlib.sha256(user.password_hash.encode("utf-8")).hexdigest()[:32]


def _device_is_trusted(user):
    token = request.cookies.get(TRUST_COOKIE)
    if not token:
        return False
    try:
        data = _trust_serializer().loads(token, max_age=TRUST_DAYS * 86400)
    except BadSignature:  # also raised when the token has expired
        return False
    return (
        isinstance(data, dict)
        and data.get("uid") == user.id
        and hmac.compare_digest(str(data.get("pw", "")), _password_fingerprint(user))
    )


def _trust_device(response, user):
    token = _trust_serializer().dumps(
        {"uid": user.id, "pw": _password_fingerprint(user)}
    )
    response.set_cookie(
        TRUST_COOKIE,
        token,
        max_age=TRUST_DAYS * 86400,
        httponly=True,
        samesite="Lax",
        secure=current_app.config["SESSION_COOKIE_SECURE"],
        path="/api",
    )
    return response


def _finish_login(user, description):
    login_user(user)
    user.last_login_at = utcnow()
    log_event("LOGIN_SUCCESS", description, user_id=user.id)
    db.session.commit()
    return jsonify(user=user_json(user))


def _pending_mfa_user():
    """The account that passed the password step and still owes a code."""
    user_id = session.get("mfa_user")
    user = db.session.get(User, user_id) if user_id else None
    if user is None or user.disabled or not user.is_verified:
        session.pop("mfa_user", None)
        return None
    return user


@api.get("/login/verify")
def login_verify_status():
    user = _pending_mfa_user()
    if user is None:
        return err("Please log in first.", 404, goto="login")
    return jsonify(
        masked_email=mask_email(user.email), ttl=current_app.config["OTP_TTL_MINUTES"]
    )


@api.post("/login/verify")
def login_verify():
    user = _pending_mfa_user()
    if user is None:
        return err("Please log in first.", 404, goto="login")

    ok, message = verify_otp(user.email, PURPOSE_LOGIN, str(body().get("otp", "")))
    if not ok:
        log_event(
            "MFA_FAILED",
            "Wrong or expired sign-in code after a correct password.",
            user_id=user.id,
        )
        db.session.commit()
        return err(message)

    session.pop("mfa_user", None)
    remember = bool(body().get("remember"))
    if remember:
        log_event(
            "DEVICE_TRUSTED",
            f"This browser will skip the sign-in code for {TRUST_DAYS} days.",
            user_id=user.id,
        )
    response = _finish_login(user, "Signed in with password + emailed code (MFA).")
    return _trust_device(response, user) if remember else response


@api.post("/login/resend")
def login_resend():
    user = _pending_mfa_user()
    if user is None:
        return err("Please log in first.", 404, goto="login")
    ok, message = issue_otp(user.email, PURPOSE_LOGIN, user.username)
    return jsonify(ok=ok, message=message)


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
        if "TAMPER" in etype or etype in ALERT_EVENTS:
            b["alerts"] += 1
    activity = [
        {"date": d.isoformat(), "total": v["total"], "alerts": v["alerts"]}
        for d, v in buckets.items()
    ]

    share_counts = dict(
        db.session.execute(
            select(FileShare.file_id, func.count())
            .join(SecureFile, SecureFile.id == FileShare.file_id)
            .where(SecureFile.user_id == current_user.id)
            .group_by(FileShare.file_id)
        ).all()
    )

    return jsonify(
        files=[dict(file_json(f), shared_with=share_counts.get(f.id, 0)) for f in files],
        shared=_shared_with_me(),
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
    return _send_verified(record)


def _send_verified(record, shared=False):
    """Verify integrity, decrypt and send a file.

    `shared=True` means the signed-in user is a recipient, not the owner. The
    same checks run either way; tamper alerts always go to the owner.
    """

    def record_tampering(reason):
        try:
            record.status = "TAMPERED"
            log_event(
                "FILE_TAMPERING_DETECTED",
                f"Integrity verification failed for {record.original_filename}: {reason}",
                user_id=record.user_id,
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
    if shared:
        log_event(
            "FILE_DOWNLOADED",
            f"Verified and downloaded {record.original_filename} "
            f"(shared by {record.owner.username}).",
            user_id=current_user.id,
            file_id=record.id,
        )
        log_event(
            "FILE_SHARE_DOWNLOADED",
            f"{current_user.username} downloaded your shared file "
            f"{record.original_filename}.",
            user_id=record.user_id,
            file_id=record.id,
        )
    else:
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
# sharing: the owner gives another user read-only access to one file
# --------------------------------------------------

def _share_json(share):
    return {
        "id": share.id,
        "username": share.recipient.username,
        "created_at": iso(share.created_at),
    }


def _shared_with_me():
    shares = db.session.scalars(
        select(FileShare)
        .where(FileShare.recipient_id == current_user.id)
        .order_by(FileShare.id.desc())
    ).all()
    return [
        {
            "share_id": s.id,
            "original_filename": s.file.original_filename,
            "file_size": s.file.file_size,
            "status": s.file.status,
            "owner": s.file.owner.username,
            "shared_at": iso(s.created_at),
        }
        for s in shares
    ]


def _my_incoming_share(share_id):
    return db.session.scalar(
        select(FileShare).where(
            FileShare.id == share_id, FileShare.recipient_id == current_user.id
        )
    )


@api.get("/files/<int:file_id>/shares")
@login_required_api
def list_shares(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    return jsonify(shares=[_share_json(s) for s in record.shares])


@api.post("/files/<int:file_id>/shares")
@login_required_api
def share_file(file_id):
    record = own_file(file_id)  # only the owner can share
    if record is None:
        return err("File not found.", 404)
    if record.status == "TAMPERED":
        return err("Recover this file before sharing it.", 409)

    who = str(body().get("user", "")).strip()
    if not who:
        return err("Enter a username or email.")

    target = db.session.scalar(
        select(User).where(
            or_(func.lower(User.username) == who.lower(), User.email == who.lower()),
            User.is_verified.is_(True),
            User.disabled.is_(False),
        )
    )
    if target is None:
        return err("No active account found with that username or email.", 404)
    if target.id == current_user.id:
        return err("You already own this file.")

    already = db.session.scalar(
        select(FileShare).where(
            FileShare.file_id == record.id, FileShare.recipient_id == target.id
        )
    )
    if already is not None:
        return err(f"Already shared with {target.username}.", 409)

    share = FileShare(file_id=record.id, recipient_id=target.id)
    db.session.add(share)
    log_event(
        "FILE_SHARED",
        f"{record.original_filename} was shared with {target.username} (read-only).",
        user_id=current_user.id,
        file_id=record.id,
    )
    log_event(
        "FILE_RECEIVED",
        f"{current_user.username} shared {record.original_filename} with you.",
        user_id=target.id,
        file_id=record.id,
    )
    db.session.commit()
    return jsonify(
        message=f"Shared with {target.username}. They can download it, not change it.",
        share=_share_json(share),
    )


@api.delete("/files/<int:file_id>/shares/<int:share_id>")
@login_required_api
def revoke_share(file_id, share_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    share = db.session.scalar(
        select(FileShare).where(
            FileShare.id == share_id, FileShare.file_id == record.id
        )
    )
    if share is None:
        return err("Share not found.", 404)

    name = share.recipient.username
    log_event(
        "FILE_SHARE_REVOKED",
        f"Access of {name} to {record.original_filename} was removed.",
        user_id=current_user.id,
        file_id=record.id,
    )
    db.session.delete(share)
    db.session.commit()
    return jsonify(message=f"{name} can no longer open this file.")


@api.get("/shared")
@login_required_api
def shared_with_me():
    return jsonify(shared=_shared_with_me())


@api.get("/shared/<int:share_id>/download")
@login_required_api
def download_shared(share_id):
    share = _my_incoming_share(share_id)
    if share is None:
        return err("File not found.", 404)
    return _send_verified(share.file, shared=True)


@api.delete("/shared/<int:share_id>")
@login_required_api
def leave_share(share_id):
    share = _my_incoming_share(share_id)
    if share is None:
        return err("File not found.", 404)
    name = share.file.original_filename
    db.session.delete(share)
    db.session.commit()
    return jsonify(message=f"'{name}' was removed from your shared files.")


# --------------------------------------------------
# share links: anyone who opens the link and signs in gets read-only access
# --------------------------------------------------
LINK_DAYS = (1, 7, 30)


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _link_json(link):
    return {
        "id": link.id,
        "created_at": iso(link.created_at),
        "expires_at": iso(link.expires_at),
        "uses": link.uses,
    }


def _live_link(token):
    """The link for this token if it exists and has not expired, else None."""
    token = str(token or "")
    if not 20 <= len(token) <= 200:
        return None
    link = db.session.scalar(
        select(ShareLink).where(ShareLink.token_hash == _token_hash(token))
    )
    if link is None or link.expires_at <= utcnow():
        return None
    return link


@api.get("/files/<int:file_id>/links")
@login_required_api
def list_links(file_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    now = utcnow()
    return jsonify(links=[_link_json(x) for x in record.links if x.expires_at > now])


@api.post("/files/<int:file_id>/links")
@login_required_api
def create_link(file_id):
    record = own_file(file_id)  # only the owner can create a link
    if record is None:
        return err("File not found.", 404)
    if record.status == "TAMPERED":
        return err("Recover this file before sharing it.", 409)

    try:
        days = int(body().get("days", 7))
    except (TypeError, ValueError):
        days = 0
    if days not in LINK_DAYS:
        return err("Choose 1, 7 or 30 days.")

    token = secrets.token_urlsafe(32)  # 256 bits of randomness; shown to the owner once
    link = ShareLink(
        file_id=record.id,
        token_hash=_token_hash(token),
        expires_at=utcnow() + timedelta(days=days),
    )
    db.session.add(link)
    log_event(
        "FILE_LINK_CREATED",
        f"A read-only share link for {record.original_filename} was created "
        f"(valid {days} day{'s' if days != 1 else ''}).",
        user_id=current_user.id,
        file_id=record.id,
    )
    db.session.commit()
    return jsonify(
        message="Link created. Copy it now; it is shown only once.",
        token=token,
        link=_link_json(link),
    )


@api.delete("/files/<int:file_id>/links/<int:link_id>")
@login_required_api
def revoke_link(file_id, link_id):
    record = own_file(file_id)
    if record is None:
        return err("File not found.", 404)
    link = db.session.scalar(
        select(ShareLink).where(ShareLink.id == link_id, ShareLink.file_id == record.id)
    )
    if link is None:
        return err("Link not found.", 404)
    log_event(
        "FILE_LINK_REVOKED",
        f"A share link for {record.original_filename} was turned off.",
        user_id=current_user.id,
        file_id=record.id,
    )
    db.session.delete(link)
    db.session.commit()
    return jsonify(message="Link turned off. People who already opened it keep access until you remove them.")


@api.get("/share-links/<token>")
def link_info(token):
    """Public: what a link points to, so the page can invite a visitor to sign in."""
    link = _live_link(token)
    if link is None:
        return err("This link is not valid any more.", 404)
    return jsonify(
        filename=link.file.original_filename,
        owner=link.file.owner.username,
        expires_at=iso(link.expires_at),
    )


@api.post("/share-links/<token>/claim")
@login_required_api
def claim_link(token):
    link = _live_link(token)
    if link is None:
        return err("This link is not valid any more.", 404)

    record = link.file
    if record.user_id == current_user.id:
        return jsonify(message="This is your own file.", own=True)

    already = db.session.scalar(
        select(FileShare).where(
            FileShare.file_id == record.id, FileShare.recipient_id == current_user.id
        )
    )
    if already is None:
        db.session.add(FileShare(file_id=record.id, recipient_id=current_user.id))
        link.uses += 1
        log_event(
            "FILE_LINK_USED",
            f"{current_user.username} opened your share link for "
            f"{record.original_filename} and now has read-only access.",
            user_id=record.user_id,
            file_id=record.id,
        )
        log_event(
            "FILE_RECEIVED",
            f"You opened a share link from {record.owner.username} for "
            f"{record.original_filename}.",
            user_id=current_user.id,
            file_id=record.id,
        )
        db.session.commit()
    return jsonify(
        message=f"'{record.original_filename}' from {record.owner.username} is now "
        f"in your shared files (read-only)."
    )


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
# administration (RBAC: see app/rbac.py)
# --------------------------------------------------

def _admin_user_json(u, file_count):
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "disabled": bool(u.disabled),
        "is_verified": bool(u.is_verified),
        "files": file_count,
        "created_at": iso(u.created_at),
        "last_login_at": iso(u.last_login_at),
    }


@api.get("/admin/overview")
@roles_required(ROLE_ANALYST, ROLE_ADMIN)
def admin_overview():
    """System-wide monitoring: totals and the latest events of every account."""
    since = utcnow() - timedelta(hours=24)

    def count(model, *conditions):
        return db.session.scalar(
            select(func.count()).select_from(model).where(*conditions)
        )

    alert_filter = or_(
        SecurityEvent.event_type.like("%TAMPER%"),
        SecurityEvent.event_type.in_(ALERT_EVENTS),
    )
    rows = db.session.execute(
        select(SecurityEvent, User.username)
        .outerjoin(User, SecurityEvent.user_id == User.id)
        .order_by(SecurityEvent.id.desc())
        .limit(200)
    ).all()

    events = []
    for event, username in rows:
        item = event_json(event)
        item["username"] = username or "—"
        events.append(item)

    return jsonify(
        stats={
            "users": count(User),
            "disabled": count(User, User.disabled.is_(True)),
            "files": count(SecureFile),
            "tampered": count(SecureFile, SecureFile.status == "TAMPERED"),
            "events_24h": count(SecurityEvent, SecurityEvent.timestamp >= since),
            "alerts_24h": count(
                SecurityEvent, SecurityEvent.timestamp >= since, alert_filter
            ),
        },
        events=events,
        permissions=PERMISSIONS,
    )


@api.get("/admin/users")
@roles_required(ROLE_ADMIN)
def admin_users():
    users = db.session.scalars(select(User).order_by(User.id)).all()
    counts = dict(
        db.session.execute(
            select(SecureFile.user_id, func.count()).group_by(SecureFile.user_id)
        ).all()
    )
    return jsonify(
        users=[_admin_user_json(u, counts.get(u.id, 0)) for u in users],
        roles=list(ROLES),
    )


def _other_user(user_id):
    """Target account of an admin action; admins cannot change themselves."""
    if user_id == current_user.id:
        return None, err("You cannot change your own account here.", 409)
    target = db.session.get(User, user_id)
    if target is None:
        return None, err("User not found.", 404)
    return target, None


@api.post("/admin/users/<int:user_id>/role")
@roles_required(ROLE_ADMIN)
def admin_set_role(user_id):
    target, problem = _other_user(user_id)
    if problem:
        return problem

    role = str(body().get("role", "")).strip().lower()
    if role not in ROLES:
        return err("Unknown role.")

    if role != target.role:
        old = target.role
        target.role = role
        log_event(
            "ROLE_CHANGED",
            f"Role of {target.username} changed from {old} to {role} "
            f"by {current_user.username}.",
            user_id=target.id,
        )
        db.session.commit()
    return jsonify(message=f"{target.username} is now '{role}'.")


@api.post("/admin/users/<int:user_id>/disabled")
@roles_required(ROLE_ADMIN)
def admin_set_disabled(user_id):
    target, problem = _other_user(user_id)
    if problem:
        return problem

    disabled = bool(body().get("disabled"))
    if disabled != bool(target.disabled):
        target.disabled = disabled
        log_event(
            "ACCOUNT_DISABLED" if disabled else "ACCOUNT_ENABLED",
            f"Account {target.username} was {'disabled' if disabled else 're-enabled'} "
            f"by {current_user.username}.",
            user_id=target.id,
        )
        db.session.commit()
    return jsonify(
        message=f"{target.username} was {'disabled' if disabled else 're-enabled'}."
    )


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
