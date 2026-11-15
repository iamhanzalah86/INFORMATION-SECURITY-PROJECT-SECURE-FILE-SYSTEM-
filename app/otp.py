"""Email one-time passcodes: generation, storage (hashed), verification."""

import hashlib
import hmac
import secrets
from datetime import timedelta

from flask import current_app
from sqlalchemy import select

from app import db
from app.mailer import send_otp_email
from app.models import OtpCode, utcnow

PURPOSE_REGISTER = "REGISTER"
PURPOSE_RESET = "RESET"
PURPOSE_RECOVER = "RECOVER"
PURPOSE_LOGIN = "LOGIN"  # second factor at sign-in


def _hash_code(email, purpose, code):
    key = current_app.config["SECRET_KEY"].encode()
    msg = f"{email}|{purpose}|{code}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def seconds_until_resend(email, purpose):
    """Seconds the caller must still wait before another code is allowed."""
    last = db.session.scalar(
        select(OtpCode)
        .where(OtpCode.email == email, OtpCode.purpose == purpose)
        .order_by(OtpCode.id.desc())
        .limit(1)
    )
    if last is None:
        return 0
    wait = current_app.config["OTP_RESEND_SECONDS"]
    elapsed = (utcnow() - last.created_at).total_seconds()
    return max(0, int(wait - elapsed))


def issue_otp(email, purpose, username=""):
    """Create and email a fresh 6-digit code.

    Returns (ok, message). Never stores the plaintext code.
    """
    wait = seconds_until_resend(email, purpose)
    if wait > 0:
        return False, f"Please wait {wait}s before requesting another code."

    code = f"{secrets.randbelow(10 ** 6):06d}"
    ttl = current_app.config["OTP_TTL_MINUTES"]

    # Invalidate older unused codes for this email + purpose.
    for old in db.session.scalars(
        select(OtpCode).where(
            OtpCode.email == email,
            OtpCode.purpose == purpose,
            OtpCode.used.is_(False),
        )
    ):
        old.used = True

    now = utcnow()
    db.session.add(
        OtpCode(
            email=email,
            purpose=purpose,
            code_hash=_hash_code(email, purpose, code),
            created_at=now,
            expires_at=now + timedelta(minutes=ttl),
        )
    )
    db.session.commit()

    sent = send_otp_email(email, code, purpose, username, ttl)
    if not sent:
        return False, "We could not send the email. Please try again shortly."
    return True, "A 6-digit verification code was sent to your email."


def verify_otp(email, purpose, code):
    """Check a submitted code. Returns (ok, message)."""
    code = (code or "").strip()
    otp = db.session.scalar(
        select(OtpCode)
        .where(
            OtpCode.email == email,
            OtpCode.purpose == purpose,
            OtpCode.used.is_(False),
        )
        .order_by(OtpCode.id.desc())
        .limit(1)
    )

    if otp is None:
        return False, "No active code. Please request a new one."

    if utcnow() > otp.expires_at:
        otp.used = True
        db.session.commit()
        return False, "That code has expired. Please request a new one."

    if otp.attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
        otp.used = True
        db.session.commit()
        return False, "Too many incorrect attempts. Please request a new code."

    if not (code.isdigit() and len(code) == 6) or not hmac.compare_digest(
        otp.code_hash, _hash_code(email, purpose, code)
    ):
        otp.attempts += 1
        db.session.commit()
        left = current_app.config["OTP_MAX_ATTEMPTS"] - otp.attempts
        if left <= 0:
            otp.used = True
            db.session.commit()
            return False, "Too many incorrect attempts. Please request a new code."
        return False, f"Incorrect code. {left} attempt(s) left."

    otp.used = True
    db.session.commit()
    return True, "Verified."
