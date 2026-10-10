
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


# Load environment variables from the project root .env file.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


# Initialize extensions.
db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)

    # Flask session security.
    secret_key = os.environ.get("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is missing. Configure it in the project .env file."
        )

    app.config["SECRET_KEY"] = secret_key
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    # SQLite database.
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_files.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize database.
    db.init_app(app)

    # Initialize authentication.
    login_manager.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message = "Please log in to access this page."

    # Load the authenticated user from the database.
    from app.models import User, SecureFile, SecurityEvent

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None

    # Register application routes.
    from app.routes import main
    app.register_blueprint(main)

    # Create database tables if they do not exist.
    with app.app_context():
        db.create_all()

    return app
