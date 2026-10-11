import hashlib
import re
import uuid
from datetime import timedelta
from io import BytesIO

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy import func, or_, select
from werkzeug.utils import secure_filename

from app import db
from app.auth import MAX_PASSWORD_BYTES, hash_password, verify_password
from app.crypto import decrypt_bytes, encrypt_bytes
from app.integrity import verify_data_integrity
from app.models import OtpCode, SecureFile, SecurityEvent, User, utcnow
from app.otp import (
    PURPOSE_REGISTER,
    PURPOSE_RESET,
    issue_otp,
    verify_otp,
)
from app.storage import delete_encrypted, read_encrypted, write_encrypted

main = Blueprint("main", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_MINUTES = 15


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def log_event(event_type, description, user_id=None, file_id=None):
    """Add a security event to the session (caller commits)."""
    db.session.add(
        SecurityEvent(
            user_id=user_id,
            file_id=file_id,
            event_type=event_type,
            description=description,
        )
    )


def check_password_rules(password, confirm=None):
    """Return an error message or None."""
    if len(password) < 12:
        return "Password must contain at least 12 characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return "Password is too long (maximum 72 bytes)."
    if confirm is not None and password != confirm:
        return "Passwords do not match."
    return None


def human_size(num):
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{int(num)} B" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024


@main.app_template_filter("filesize")
def filesize_filter(value):
    return human_size(value)


@main.app_context_processor
def inject_globals():
    return {"app_name": current_app.config["APP_NAME"]}


def mask_email(email):
    name, _, domain = email.partition("@")
    if len(name) <= 2:
        masked = name[:1] + "*"
    else:
        masked = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked}@{domain}"


# --------------------------------------------------
# HOME
# --------------------------------------------------

@main.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


@main.route("/healthz")
def healthz():
    return jsonify(status="ok")


# --------------------------------------------------
# REGISTRATION (with email OTP)
# --------------------------------------------------

@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"username": username, "email": email}

        error = None
        if not username or not email or not password:
            error = "Username, email and password are required."
        elif not USERNAME_RE.match(username):
            error = "Username must be 3-30 characters: letters, numbers, . _ -"
        elif len(email) > 255 or not EMAIL_RE.match(email):
            error = "Please enter a valid email address."
        else:
            error = check_password_rules(password, confirm)

        if error:
            flash(error, "error")
            return render_template("register.html", form=form)

        matches = db.session.scalars(
            select(User).where(
                or_(
                    func.lower(User.username) == username.lower(),
                    User.email == email,
                )
            )
        ).all()

        if any(u.is_verified for u in matches):
            taken_email = any(u.is_verified and u.email == email for u in matches)
            flash(
                "An account with this email already exists."
                if taken_email
                else "Username is already registered.",
                "error",
            )
            return render_template("register.html", form=form)

        # Unverified leftovers (never completed OTP) can be replaced.
        for stale in matches:
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
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html", form=form)

        ok, message = issue_otp(email, PURPOSE_REGISTER, username)
        session["verify_email"] = email

        if not ok:
            flash(message + " You can resend the code below.", "error")
        else:
            flash(message, "success")
        return redirect(url_for("main.verify_email"))

    return render_template("register.html", form={})


@main.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    email = session.get("verify_email")
    user = (
        db.session.scalar(select(User).where(User.email == email))
        if email
        else None
    )

    if user is None or user.is_verified:
        session.pop("verify_email", None)
        if user is not None and user.is_verified:
            flash("Email already verified. Please log in.", "info")
            return redirect(url_for("main.login"))
        flash("Please register first.", "error")
        return redirect(url_for("main.register"))

    if request.method == "POST":
        ok, message = verify_otp(
            email, PURPOSE_REGISTER, request.form.get("otp", "")
        )
        if not ok:
            flash(message, "error")
        else:
            user.is_verified = True
            log_event(
                "ACCOUNT_VERIFIED",
                f"Email verified for {user.username}.",
                user_id=user.id,
            )
            db.session.commit()
            session.pop("verify_email", None)
            flash("Email verified! You can now log in.", "success")
            return redirect(url_for("main.login"))

    return render_template(
        "verify_otp.html",
        mode="register",
        masked_email=mask_email(email),
        ttl=current_app.config["OTP_TTL_MINUTES"],
        resend_url=url_for("main.verify_email_resend"),
    )


@main.route("/verify-email/resend", methods=["POST"])
def verify_email_resend():
    email = session.get("verify_email")
    user = (
        db.session.scalar(select(User).where(User.email == email))
        if email
        else None
    )
    if user is None or user.is_verified:
        return redirect(url_for("main.register"))

    ok, message = issue_otp(email, PURPOSE_REGISTER, user.username)
    flash(message, "success" if ok else "error")
    return redirect(url_for("main.verify_email"))


# --------------------------------------------------
# LOGIN / LOGOUT
# --------------------------------------------------

@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.session.scalar(
            select(User).where(
                or_(
                    func.lower(User.username) == identifier.lower(),
                    User.email == identifier.lower(),
                )
            )
        )

        # Basic brute-force throttle per account.
        if user is not None:
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
                flash(
                    "Too many failed attempts. Try again in a few minutes "
                    "or reset your password.",
                    "error",
                )
                return render_template("login.html", identifier=identifier)

        if user and verify_password(user.password_hash, password):
            if not user.is_verified:
                session["verify_email"] = user.email
                ok, message = issue_otp(
                    user.email, PURPOSE_REGISTER, user.username
                )
                flash(
                    "Please verify your email first. "
                    + (message if ok else "Use the resend button below."),
                    "info" if ok else "error",
                )
                return redirect(url_for("main.verify_email"))

            login_user(user)
            user.last_login_at = utcnow()
            log_event("LOGIN_SUCCESS", "Signed in successfully.", user_id=user.id)
            db.session.commit()
            return redirect(url_for("main.dashboard"))

        if user:
            log_event(
                "LOGIN_FAILED",
                "Failed sign-in attempt (wrong password).",
                user_id=user.id,
            )
            db.session.commit()

        flash("Invalid username or password.", "error")
        return render_template("login.html", identifier=identifier)

    return render_template("login.html", identifier="")


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("LOGOUT", "Signed out.", user_id=current_user.id)
    db.session.commit()
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.login"))


# --------------------------------------------------
# FORGOT / RESET PASSWORD (with email OTP)
# --------------------------------------------------

@main.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "error")
            return render_template("forgot_password.html", email=email)

        user = db.session.scalar(
            select(User).where(User.email == email, User.is_verified.is_(True))
        )
        if user is not None:
            ok, message = issue_otp(email, PURPOSE_RESET, user.username)
            if ok:
                log_event(
                    "PASSWORD_RESET_REQUESTED",
                    "A password reset code was emailed.",
                    user_id=user.id,
                )
                db.session.commit()

        # Same response whether or not the account exists (no enumeration).
        session["reset_email"] = email
        flash(
            "If an account exists for that email, a 6-digit code has been sent.",
            "info",
        )
        return redirect(url_for("main.reset_password"))

    return render_template("forgot_password.html", email="")


@main.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    email = session.get("reset_email")
    if not email:
        return redirect(url_for("main.forgot_password"))

    if request.method == "POST":
        code = request.form.get("otp", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = check_password_rules(password, confirm)
        if error:
            flash(error, "error")
        else:
            user = db.session.scalar(
                select(User).where(User.email == email, User.is_verified.is_(True))
            )
            ok, message = verify_otp(email, PURPOSE_RESET, code)

            if not ok or user is None:
                flash(message if not ok else "Invalid or expired code.", "error")
            else:
                user.password_hash = hash_password(password)
                log_event(
                    "PASSWORD_RESET",
                    "Password was reset using an emailed code.",
                    user_id=user.id,
                )
                # Clear the failed-login lockout counter.
                db.session.execute(
                    SecurityEvent.__table__.update()
                    .where(
                        SecurityEvent.user_id == user.id,
                        SecurityEvent.event_type == "LOGIN_FAILED",
                    )
                    .values(event_type="LOGIN_FAILED_CLEARED")
                )
                db.session.commit()
                session.pop("reset_email", None)
                flash("Password updated. You can now log in.", "success")
                return redirect(url_for("main.login"))

    return render_template(
        "verify_otp.html",
        mode="reset",
        masked_email=mask_email(email),
        ttl=current_app.config["OTP_TTL_MINUTES"],
        resend_url=url_for("main.reset_password_resend"),
    )


@main.route("/reset-password/resend", methods=["POST"])
def reset_password_resend():
    email = session.get("reset_email")
    if not email:
        return redirect(url_for("main.forgot_password"))

    user = db.session.scalar(
        select(User).where(User.email == email, User.is_verified.is_(True))
    )
    if user is not None:
        issue_otp(email, PURPOSE_RESET, user.username)

    flash("If an account exists for that email, a new code has been sent.", "info")
    return redirect(url_for("main.reset_password"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@main.route("/dashboard")
@login_required
def dashboard():
    files = db.session.scalars(
        select(SecureFile)
        .where(SecureFile.user_id == current_user.id)
        .order_by(SecureFile.uploaded_at.desc())
    ).all()

    total_size = sum(f.file_size for f in files)
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

    recent_events = db.session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.id.desc())
        .limit(6)
    ).all()

    stats = {
        "total": len(files),
        "secure": len(files) - tampered,
        "tampered": tampered,
        "size": human_size(total_size),
        "last_scan": last_scan,
    }

    return render_template(
        "dashboard.html",
        files=files,
        stats=stats,
        recent_events=recent_events,
        max_mb=current_app.config["MAX_UPLOAD_BYTES"] / (1024 * 1024),
    )


# --------------------------------------------------
# SECURE FILE UPLOAD
# --------------------------------------------------

@main.route("/upload", methods=["POST"])
@login_required
def upload_file():
    max_bytes = current_app.config["MAX_UPLOAD_BYTES"]
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        flash("Please select a file to upload.", "error")
        return redirect(url_for("main.dashboard"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        flash("Invalid filename.", "error")
        return redirect(url_for("main.dashboard"))

    # Read at most max_bytes + 1 so oversized files are rejected
    # without loading an unlimited file into memory.
    plaintext = uploaded_file.stream.read(max_bytes + 1)

    if len(plaintext) > max_bytes:
        flash(
            f"File exceeds the {max_bytes / (1024 * 1024):g} MB upload limit.",
            "error",
        )
        return redirect(url_for("main.dashboard"))

    if not plaintext:
        flash("Empty files are not allowed.", "error")
        return redirect(url_for("main.dashboard"))

    file_record = None

    try:
        # Encrypt before anything is persisted.
        encrypted_data = encrypt_bytes(plaintext)

        # SHA-256 over the exact stored (encrypted) bytes.
        integrity_hash = hashlib.sha256(encrypted_data).hexdigest()

        file_record = SecureFile(
            user_id=current_user.id,
            original_filename=original_filename,
            encrypted_filename=f"{uuid.uuid4().hex}.bin",
            file_size=len(plaintext),
            sha256_hash=integrity_hash,
            encryption_algorithm="AES-256-GCM",
            status="SECURE",
        )
        write_encrypted(file_record, encrypted_data)

        db.session.add(file_record)
        db.session.flush()

        log_event(
            "FILE_UPLOADED",
            f"Encrypted file uploaded: {original_filename}. "
            f"Stored SHA-256: {integrity_hash}",
            user_id=current_user.id,
            file_id=file_record.id,
        )
        db.session.commit()

    except Exception:
        db.session.rollback()

        if file_record is not None:
            delete_encrypted(file_record)

        current_app.logger.exception("Secure file upload failed")
        flash("Upload failed. Check the application logs.", "error")
        return redirect(url_for("main.dashboard"))

    flash(f"'{original_filename}' was encrypted and stored securely.", "success")
    return redirect(url_for("main.dashboard"))


# --------------------------------------------------
# SECURE DOWNLOAD AND TAMPER DETECTION
# --------------------------------------------------

def _own_file_or_404(file_id):
    record = db.session.scalar(
        select(SecureFile).where(
            SecureFile.id == file_id,
            SecureFile.user_id == current_user.id,
        )
    )
    if record is None:
        abort(404)
    return record


@main.route("/download/<int:file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    file_record = _own_file_or_404(file_id)

    def record_tampering(reason):
        try:
            file_record.status = "TAMPERED"
            log_event(
                "FILE_TAMPERING_DETECTED",
                f"Integrity verification failed for "
                f"{file_record.original_filename}: {reason}",
                user_id=current_user.id,
                file_id=file_record.id,
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to record tampering event")

    try:
        encrypted_data = read_encrypted(file_record)
    except (FileNotFoundError, ValueError):
        record_tampering("Encrypted file is missing from storage.")
        flash(
            "Security alert: the stored file is missing. Download blocked.",
            "error",
        )
        return redirect(url_for("main.dashboard"))
    except OSError:
        current_app.logger.exception(
            "Could not read encrypted file %s", file_record.id
        )
        flash("Unable to read the stored file.", "error")
        return redirect(url_for("main.dashboard"))

    # Verify stored bytes before attempting decryption.
    if not verify_data_integrity(encrypted_data, file_record.sha256_hash):
        record_tampering("Stored SHA-256 hash does not match.")
        current_app.logger.warning(
            "Possible file tampering detected for record %s", file_record.id
        )
        flash(
            "SECURITY ALERT: File integrity check failed. "
            "The download has been blocked.",
            "error",
        )
        return redirect(url_for("main.dashboard"))

    try:
        plaintext = decrypt_bytes(encrypted_data)
    except (ValueError, TypeError):
        record_tampering("AES-GCM authentication failed after hash verification.")
        flash(
            "Security alert: file authentication failed. "
            "The download has been blocked.",
            "error",
        )
        return redirect(url_for("main.dashboard"))

    # A previous TAMPERED status is never cleared automatically.
    if file_record.status != "TAMPERED":
        file_record.status = "SECURE"

    log_event(
        "FILE_DOWNLOADED",
        f"Verified and downloaded {file_record.original_filename}.",
        user_id=current_user.id,
        file_id=file_record.id,
    )
    db.session.commit()

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=file_record.original_filename,
        mimetype="application/octet-stream",
    )


# --------------------------------------------------
# DELETE FILE
# --------------------------------------------------

@main.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    file_record = _own_file_or_404(file_id)
    name = file_record.original_filename

    try:
        delete_encrypted(file_record)
        log_event(
            "FILE_DELETED",
            f"File deleted: {name}.",
            user_id=current_user.id,
        )
        # Keep earlier events for this file but detach them from the row.
        db.session.execute(
            SecurityEvent.__table__.update()
            .where(SecurityEvent.file_id == file_record.id)
            .values(file_id=None)
        )
        db.session.delete(file_record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("File deletion failed")
        flash("Could not delete the file.", "error")
        return redirect(url_for("main.dashboard"))

    flash(f"'{name}' was permanently deleted.", "success")
    return redirect(url_for("main.dashboard"))


# --------------------------------------------------
# MANUAL INTEGRITY SCAN
# --------------------------------------------------

@main.route("/integrity-scan", methods=["POST"])
@login_required
def integrity_scan():
    files = db.session.scalars(
        select(SecureFile).where(SecureFile.user_id == current_user.id)
    ).all()

    checked = secure_count = issue_count = 0

    for file_record in files:
        try:
            data = read_encrypted(file_record)
            if verify_data_integrity(data, file_record.sha256_hash):
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
            if file_record.status != "TAMPERED":
                file_record.status = "SECURE"
        else:
            issue_count += 1
            was_already_tampered = file_record.status == "TAMPERED"
            file_record.status = "TAMPERED"

            if not was_already_tampered:
                log_event(
                    "FILE_TAMPERING_DETECTED",
                    f"Integrity scan detected {reason} for "
                    f"{file_record.original_filename}.",
                    user_id=current_user.id,
                    file_id=file_record.id,
                )

    log_event(
        "INTEGRITY_SCAN",
        f"Integrity scan: {checked} checked, {secure_count} verified, "
        f"{issue_count} issue(s).",
        user_id=current_user.id,
    )

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Integrity scan could not be saved")
        flash("Unable to save integrity scan results.", "error")
        return redirect(url_for("main.dashboard"))

    flash(
        f"Integrity scan completed: {checked} checked, "
        f"{secure_count} verified, {issue_count} issue(s).",
        "success" if issue_count == 0 else "error",
    )
    return redirect(url_for("main.dashboard"))


# --------------------------------------------------
# SECURITY EVENT REVIEW
# --------------------------------------------------

@main.route("/security-events")
@login_required
def security_events():
    events = db.session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.id.desc())
        .limit(200)
    ).all()

    return render_template("security_events.html", events=events)
