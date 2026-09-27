from flask import Blueprint, render_template

from app import db
from app.models import User, SecureFile, SecurityEvent

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/database-test")
def database_test():
    return {
        "database": "connected",
        "users_table": User.query.count(),
        "files_table": SecureFile.query.count(),
        "security_events_table": SecurityEvent.query.count()
    }