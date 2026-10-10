
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, jsonify
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from sqlalchemy import select

from app import db
from app.models import User, SecureFile, SecurityEvent
from app.auth import hash_password, verify_password

main = Blueprint("main", __name__)


@main.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


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
            flash("That username is already registered.", "error")
            return render_template("register.html")

        user = User(
            username=username,
            password_hash=hash_password(password)
        )

        db.session.add(user)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


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


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.login"))


@main.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@main.route("/database-test")
@login_required
def database_test():
    return jsonify({
        "database": "connected",
        "users_table": db.session.scalar(
            select(db.func.count()).select_from(User)
        ),
        "files_table": db.session.scalar(
            select(db.func.count()).select_from(SecureFile)
        ),
        "security_events_table": db.session.scalar(
            select(db.func.count()).select_from(SecurityEvent)
        )
    })
