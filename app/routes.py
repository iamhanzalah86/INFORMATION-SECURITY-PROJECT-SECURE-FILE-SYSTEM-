from app.integrity import verify_file_integrity
import hmac
from io import BytesIO
from flask import abort
from flask import send_file
from app.crypto import encrypt_bytes, decrypt_bytes
import hashlib
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user,
)
from sqlalchemy import select, func
from werkzeug.utils import secure_filename

from app import db
from app.models import User, SecureFile, SecurityEvent
from app.auth import hash_password, verify_password
from app.crypto import encrypt_bytes


main = Blueprint("main", __name__)

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MiB


def encrypted_storage_path():
    """Return the absolute path of encrypted file storage."""
    project_root = Path(current_app.root_path).parent
    storage_dir = project_root / "storage" / "encrypted"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir


# --------------------------------------------------
# HOME
# --------------------------------------------------

@main.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    return render_template("index.html")


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if len(username) > 100:
            flash("Username must be 100 characters or fewer.", "error")
            return render_template("register.html")

        if len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
            return render_template("register.html")

        existing_user = db.session.scalar(
            select(User).where(User.username == username)
        )

        if existing_user:
            flash("Username is already registered.", "error")
            return render_template("register.html")

        user = User(
            username=username,
            password_hash=hash_password(password),
        )

        db.session.add(user)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Registration failed")
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.session.scalar(
            select(User).where(User.username == username)
        )

        if user and verify_password(user.password_hash, password):
            login_user(user)
            return redirect(url_for("main.dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@main.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.login"))


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

    return render_template("dashboard.html", files=files)


# --------------------------------------------------
# SECURE FILE UPLOAD
# --------------------------------------------------

@main.route("/upload", methods=["POST"])
@login_required
def upload_file():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        flash("Please select a file to upload.", "error")
        return redirect(url_for("main.dashboard"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        flash("Invalid filename.", "error")
        return redirect(url_for("main.dashboard"))

    # Read at most MAX_FILE_SIZE + 1 bytes so oversized files
    # can be rejected without loading an unlimited file into memory.
    plaintext = uploaded_file.stream.read(MAX_FILE_SIZE + 1)

    if len(plaintext) > MAX_FILE_SIZE:
        flash("File exceeds the 16 MiB upload limit.", "error")
        return redirect(url_for("main.dashboard"))

    if not plaintext:
        flash("Empty files are not allowed.", "error")
        return redirect(url_for("main.dashboard"))

    encrypted_path = None

    try:
        # Encrypt before writing anything to persistent storage.
        encrypted_data = encrypt_bytes(plaintext)

        # SHA-256 is calculated over the exact stored encrypted bytes.
        integrity_hash = hashlib.sha256(encrypted_data).hexdigest()

        # Use an unpredictable physical filename.
        encrypted_filename = f"{uuid.uuid4().hex}.bin"
        storage_dir = encrypted_storage_path()
        encrypted_path = storage_dir / encrypted_filename

        # Exclusive creation avoids accidentally overwriting a file.
        with encrypted_path.open("xb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        file_record = SecureFile(
            user_id=current_user.id,
            original_filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_size=len(plaintext),
            sha256_hash=integrity_hash,
            encryption_algorithm="AES-256-GCM",
            status="SECURE",
        )

        db.session.add(file_record)
        db.session.flush()

        event = SecurityEvent(
            user_id=current_user.id,
            file_id=file_record.id,
            event_type="FILE_UPLOADED",
            description=(
                f"Encrypted file uploaded: {original_filename}. "
                f"Stored SHA-256: {integrity_hash}"
            ),
        )

        db.session.add(event)
        db.session.commit()

    except Exception:
        db.session.rollback()

        # Remove a newly written file if database storage failed.
        if encrypted_path is not None:
            try:
                encrypted_path.unlink(missing_ok=True)
            except OSError:
                current_app.logger.exception(
                    "Could not clean up an incomplete encrypted upload"
                )

        current_app.logger.exception("Secure file upload failed")
        flash("Upload failed. Check the application logs.", "error")
        return redirect(url_for("main.dashboard"))

    flash("File encrypted and uploaded successfully.", "success")
    return redirect(url_for("main.dashboard"))

# --------------------------------------------------
# SECURE DOWNLOAD AND TAMPER DETECTION
# --------------------------------------------------

@main.route("/download/<int:file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    # Users can access only their own files.
    file_record = db.session.scalar(
        select(SecureFile).where(
            SecureFile.id == file_id,
            SecureFile.user_id == current_user.id,
        )
    )

    if file_record is None:
        abort(404)

    # Never allow a database filename to escape the storage directory.
    stored_name = file_record.encrypted_filename

    if not stored_name or Path(stored_name).name != stored_name:
        current_app.logger.error(
            "Invalid stored filename for file record %s",
            file_record.id,
        )
        abort(404)

    encrypted_path = encrypted_storage_path() / stored_name

    def record_tampering(reason):
        file_record.status = "TAMPERED"

        event = SecurityEvent(
            user_id=current_user.id,
            file_id=file_record.id,
            event_type="FILE_TAMPERING_DETECTED",
            description=(
                f"Integrity verification failed for "
                f"{file_record.original_filename}: {reason}"
            ),
        )

        db.session.add(event)
        db.session.commit()

    # A missing encrypted file is also an integrity/security incident.
    try:
        encrypted_data = encrypted_path.read_bytes()
    except FileNotFoundError:
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

    # Verify the stored bytes before attempting decryption.
    actual_hash = hashlib.sha256(encrypted_data).hexdigest()
    expected_hash = file_record.sha256_hash or ""

    if not hmac.compare_digest(actual_hash, expected_hash):
        try:
            record_tampering("Stored SHA-256 hash does not match.")
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Failed to record a file tampering event"
            )

        current_app.logger.warning(
            "Possible file tampering detected for record %s",
            file_record.id,
        )

        flash(
            "SECURITY ALERT: File integrity check failed. "
            "The download has been blocked.",
            "error",
        )
        return redirect(url_for("main.dashboard"))

    # Only decrypt after the SHA-256 check passes.
    try:
        plaintext = decrypt_bytes(encrypted_data)
    except (ValueError, TypeError):
        try:
            record_tampering(
                "AES-GCM authentication failed after hash verification."
            )
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Failed to record an encryption verification event"
            )

        current_app.logger.warning(
            "Decryption/authentication failed for file record %s",
            file_record.id,
        )
        flash(
            "Security alert: file authentication failed. "
            "The download has been blocked.",
            "error",
        )
        return redirect(url_for("main.dashboard"))

    # Restore the normal status after a successful integrity check.
    # Do not automatically clear a previous tampering status:
    # an administrator should investigate that incident.
    if file_record.status != "TAMPERED":
        file_record.status = "SECURE"
        db.session.commit()

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=file_record.original_filename,
        mimetype="application/octet-stream",
    )

# --------------------------------------------------
# MANUAL INTEGRITY SCAN
# --------------------------------------------------

@main.route("/integrity-scan", methods=["POST"])
@login_required
def integrity_scan():
    # Scan only files belonging to the logged-in user.
    files = db.session.scalars(
        select(SecureFile).where(
            SecureFile.user_id == current_user.id
        )
    ).all()

    storage_dir = encrypted_storage_path()
    checked = 0
    secure_count = 0
    issue_count = 0

    for file_record in files:
        stored_name = file_record.encrypted_filename

        if (
            not stored_name
            or Path(stored_name).name != stored_name
        ):
            valid = False
            reason = "INVALID_STORED_FILENAME"
        else:
            stored_path = storage_dir / stored_name
            valid, reason = verify_file_integrity(
                stored_path,
                file_record.sha256_hash or "",
            )

        checked += 1

        if valid:
            secure_count += 1

            # Preserve prior tampering alerts for investigation.
            if file_record.status != "TAMPERED":
                file_record.status = "SECURE"

        else:
            issue_count += 1
            was_already_tampered = (
                file_record.status == "TAMPERED"
            )

            file_record.status = "TAMPERED"

            # Avoid creating a duplicate event on every scan
            # for a file that is already marked TAMPERED.
            if not was_already_tampered:
                event = SecurityEvent(
                    user_id=current_user.id,
                    file_id=file_record.id,
                    event_type="FILE_TAMPERING_DETECTED",
                    description=(
                        f"Integrity scan detected {reason} for "
                        f"{file_record.original_filename}."
                    ),
                )
                db.session.add(event)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Integrity scan could not be saved"
        )
        flash("Unable to save integrity scan results.", "error")
        return redirect(url_for("main.dashboard"))

    flash(
        f"Integrity scan completed: {checked} checked, "
        f"{secure_count} verified, {issue_count} issue(s).",
        "success" if issue_count == 0 else "error",
    )

    return redirect(url_for("main.dashboard"))


# --------------------------------------------------
# DATABASE TEST
# --------------------------------------------------

@main.route("/database-test")
@login_required
def database_test():
    return jsonify({
        "database": "connected",
        "users_table": db.session.scalar(
            select(func.count()).select_from(User)
        ),
        "files_table": db.session.scalar(
            select(func.count()).select_from(SecureFile)
        ),
        "security_events_table": db.session.scalar(
            select(func.count()).select_from(SecurityEvent)
        ),
    })

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

    return render_template(
        "security_events.html",
        events=events,
    )
