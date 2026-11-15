import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, redirect, request
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# Load environment variables from the project root .env file (local use).
# On Vercel the variables come from the project settings instead.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Initialize extensions.
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

ON_VERCEL = bool(os.environ.get("VERCEL"))


def _database_uri():
    """Postgres from DATABASE_URL when set, otherwise local SQLite."""
    url = os.environ.get("DATABASE_URL", "").strip()

    if url:
        # Neon / Heroku style URLs use "postgres://"; SQLAlchemy needs
        # an explicit driver.
        if url.startswith("postgres://"):
            url = "postgresql+psycopg2://" + url[len("postgres://"):]
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        return url

    if ON_VERCEL:
        # Vercel's filesystem is read-only except /tmp, and /tmp is wiped.
        # This only exists so the site boots; configure DATABASE_URL.
        return "sqlite:////tmp/secure_files.db"

    return "sqlite:///secure_files.db"


def create_app():
    app = Flask(__name__)

    # ---- Security configuration ------------------------------------
    secret_key = os.environ.get("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is missing. Configure it in the project .env file "
            "(or in the Vercel environment variables)."
        )

    # HTTPS=1 makes `python run.py` serve over TLS with a self-signed certificate.
    local_https = os.environ.get("HTTPS", "0").strip() == "1"
    default_secure = "true" if (ON_VERCEL or local_https) else "false"
    secure_cookie = os.environ.get(
        "SESSION_COOKIE_SECURE", default_secure
    ).strip().lower()

    if secure_cookie not in {"true", "false"}:
        raise RuntimeError("SESSION_COOKIE_SECURE must be true or false.")

    # Vercel rejects request bodies above ~4.5 MB, so cap uploads lower there.
    default_mb = "4" if ON_VERCEL else "16"
    try:
        max_upload_mb = float(os.environ.get("MAX_UPLOAD_MB", default_mb))
    except ValueError:
        raise RuntimeError("MAX_UPLOAD_MB must be a number.")

    app.config["SECRET_KEY"] = secret_key
    app.config["MAX_UPLOAD_BYTES"] = int(max_upload_mb * 1024 * 1024)
    # Allow a little overhead for multipart framing.
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_BYTES"] + 64 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = secure_cookie == "true"
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600

    # Redirect plain HTTP to HTTPS (on by default when deployed or with HTTPS=1).
    force_https = os.environ.get(
        "FORCE_HTTPS", "1" if (ON_VERCEL or local_https) else "0"
    ).strip() == "1"
    app.config["FORCE_HTTPS"] = force_https

    # Second factor at sign-in: password, then a 6-digit emailed code.
    app.config["LOGIN_MFA"] = os.environ.get("LOGIN_MFA", "1").strip() != "0"

    # Accounts with these emails become administrators (comma separated).
    app.config["ADMIN_EMAILS"] = {
        e.strip().lower()
        for e in os.environ.get("ADMIN_EMAILS", "").split(",")
        if e.strip()
    }

    # ---- Email / OTP configuration ---------------------------------
    app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", "587"))
    app.config["SMTP_USER"] = os.environ.get("SMTP_USER", "").strip()
    app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "").replace(" ", "")
    app.config["MAIL_FROM"] = os.environ.get(
        "MAIL_FROM", app.config["SMTP_USER"]
    ).strip()
    app.config["APP_NAME"] = os.environ.get("APP_NAME", "SecureVault")
    app.config["OTP_TTL_MINUTES"] = int(os.environ.get("OTP_TTL_MINUTES", "10"))
    app.config["OTP_MAX_ATTEMPTS"] = 5
    app.config["OTP_RESEND_SECONDS"] = 60

    # ---- Database / storage ----------------------------------------
    app.config["SQLALCHEMY_DATABASE_URI"] = _database_uri()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # "disk" keeps encrypted files in storage/encrypted (local / Docker).
    # "db" keeps the encrypted bytes in the database (needed on Vercel).
    default_backend = "db" if (ON_VERCEL or os.environ.get("DATABASE_URL")) else "disk"
    backend = os.environ.get("STORAGE_BACKEND", default_backend).strip().lower()

    if backend not in {"disk", "db"}:
        raise RuntimeError("STORAGE_BACKEND must be 'disk' or 'db'.")

    app.config["STORAGE_BACKEND"] = backend

    # ---- Extensions -------------------------------------------------
    csrf.init_app(app)
    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"

    from app.models import (  # noqa: F401
        FileShare, OtpCode, SecureFile, SecurityEvent, ShareLink, User,
    )

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None
        # A disabled account is signed out on its very next request.
        if user is not None and user.disabled:
            return None
        return user

    # JSON API used by the React frontend (frontend/).
    from app.api import api
    app.register_blueprint(api)

    if os.environ.get("LEGACY_UI", "0").strip() == "1":
        # Original server-rendered Jinja pages (kept for reference / tests).
        from app.routes import main
        app.register_blueprint(main)
    else:
        # React app built into frontend/dist.
        from app.spa import spa
        app.register_blueprint(spa)

    legacy_ui = os.environ.get("LEGACY_UI", "0").strip() == "1"

    def _is_https():
        # Behind a proxy (Vercel, nginx) the original scheme is in this header.
        forwarded = request.headers.get("X-Forwarded-Proto", "")
        return request.is_secure or forwarded.split(",")[0].strip() == "https"

    @app.before_request
    def enforce_https():
        if app.config["FORCE_HTTPS"] and not _is_https() and request.path != "/healthz":
            return redirect(request.url.replace("http://", "https://", 1), code=308)
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"
        )
        if _is_https():
            # Browsers remember to use HTTPS only for this site for one year.
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if not legacy_ui:
            # Only our own scripts, styles and API may load; no framing, no plugins.
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self'; object-src 'none'; "
                "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            )
        # Authenticated pages must not be cached by the browser.
        if "Cache-Control" not in response.headers and not (
            response.mimetype in ("text/css", "application/javascript", "text/javascript")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Create tables if they do not exist.
    with app.app_context():
        db.create_all()
        _add_missing_columns()
        _promote_admins(app)

    return app


def _add_missing_columns():
    """Tiny migration: add columns introduced after the first deployment."""
    from sqlalchemy import inspect, text

    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    is_pg = db.engine.dialect.name == "postgresql"
    false = "FALSE" if is_pg else "0"
    wanted = {
        "secure_files": {
            "has_backup": f"BOOLEAN NOT NULL DEFAULT {false}",
            "backup_blob": "BYTEA" if is_pg else "BLOB",
        },
        "users": {
            "role": "VARCHAR(20) NOT NULL DEFAULT 'user'",
            "disabled": f"BOOLEAN NOT NULL DEFAULT {false}",
        },
    }

    with db.engine.begin() as conn:
        for table, columns in wanted.items():
            if table not in tables:
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def _promote_admins(app):
    """Make sure the system has an administrator.

    * Accounts listed in ADMIN_EMAILS (optional) always get the admin role.
    * If there is still no administrator, the oldest verified account becomes
      one, so the very first person to register runs the system.
    """
    from sqlalchemy import func, select

    from app.models import User

    changed = False
    emails = app.config["ADMIN_EMAILS"]
    if emails:
        for user in db.session.scalars(
            select(User).where(User.email.in_(emails), User.role != "admin")
        ).all():
            user.role = "admin"
            changed = True
        if changed:
            db.session.flush()

    admins = db.session.scalar(
        select(func.count()).select_from(User).where(User.role == "admin")
    )
    if not admins:
        first = db.session.scalar(
            select(User)
            .where(User.is_verified.is_(True), User.disabled.is_(False))
            .order_by(User.id)
            .limit(1)
        )
        if first is not None:
            first.role = "admin"
            changed = True

    if changed:
        db.session.commit()
