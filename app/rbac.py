"""Role-based access control (RBAC).

Roles, from least to most privileged:

* ``user``     End user. Sees and manages only their own files and events.
* ``analyst``  Security analyst. Read-only view of system-wide security events.
* ``admin``    Security administrator. Analyst view, plus managing accounts
               (assign roles, disable / enable users).

No role can read another user's files: the vault endpoints always filter by the
signed-in owner, whatever the role (least privilege + privacy).
"""

from functools import wraps

from flask import jsonify, request
from flask_login import current_user

from app import db

ROLE_USER = "user"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ROLES = (ROLE_USER, ROLE_ANALYST, ROLE_ADMIN)

# What each role is allowed to do (used by the API and shown in the admin page).
PERMISSIONS = {
    ROLE_USER: [
        "Own files: upload, download, scan, recover, delete",
        "Share own files read-only; download files shared with them",
        "Own security events",
    ],
    ROLE_ANALYST: ["Everything a user can do", "View system-wide security events (read-only)"],
    ROLE_ADMIN: [
        "Everything an analyst can do",
        "Assign roles",
        "Disable / enable accounts",
    ],
}


def roles_required(*roles):
    """Allow the endpoint only for signed-in users holding one of `roles`."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return (
                    jsonify(error="Please log in to access this page.", unauthorized=True),
                    401,
                )
            if current_user.role not in roles:
                # Imported here to avoid a circular import with app.routes.
                from app.routes import log_event

                log_event(
                    "ACCESS_DENIED",
                    f"Blocked: role '{current_user.role}' tried to open {request.path}.",
                    user_id=current_user.id,
                )
                db.session.commit()
                return jsonify(error="You do not have permission to do that."), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator
