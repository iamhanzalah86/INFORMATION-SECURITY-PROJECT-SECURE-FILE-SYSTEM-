import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
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

    default_secure = "true" if ON_VERCEL else "false"
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

    from app.models import User, SecureFile, SecurityEvent, OtpCode  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None

    from app.routes import main
    app.register_blueprint(main)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
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

    return app


def _add_missing_columns():
    """Tiny migration: add columns introduced after the first deployment."""
    from sqlalchemy import inspect, text

    insp = inspect(db.engine)
    if "secure_files" not in insp.get_table_names():
        return

    existing = {c["name"] for c in insp.get_columns("secure_files")}
    is_pg = db.engine.dialect.name == "postgresql"
    wanted = {
        "has_backup": "BOOLEAN NOT NULL DEFAULT " + ("FALSE" if is_pg else "0"),
        "backup_blob": "BYTEA" if is_pg else "BLOB",
    }

    with db.engine.begin() as conn:
        for name, ddl in wanted.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE secure_files ADD COLUMN {name} {ddl}"))
