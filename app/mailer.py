"""SMTP email sending (works with Gmail app passwords, Brevo, Resend SMTP...)."""

import smtplib
import ssl
from email.message import EmailMessage
from html import escape

from flask import current_app

from app import ON_VERCEL

SUBJECTS = {
    "REGISTER": "Verify your email",
    "RESET": "Reset your password",
<<<<<<< HEAD
    "RECOVER": "Confirm file recovery",
=======
>>>>>>> a95b8c077877d22109b41fd7e821d111f0e3c230
}
INTRO = {
    "REGISTER": "Use this code to verify your email and finish creating your account.",
    "RESET": "Use this code to reset your password.",
<<<<<<< HEAD
    "RECOVER": "Use this code to confirm restoring a tampered file from its backup.",
=======
>>>>>>> a95b8c077877d22109b41fd7e821d111f0e3c230
}


def _html(app_name, code, purpose, username, ttl):
    name = escape(username or "there")
    return f"""\
<!doctype html>
<html><body style="margin:0;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="480" cellpadding="0" cellspacing="0"
             style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #e2e8f0;">
        <tr><td style="background:linear-gradient(135deg,#0f766e,#0e7490);padding:24px 28px;color:#fff;">
          <div style="font-size:20px;font-weight:700;">&#128274; {escape(app_name)}</div>
        </td></tr>
        <tr><td style="padding:28px;color:#0f172a;">
          <p style="margin:0 0 8px;font-size:16px;">Hi {name},</p>
          <p style="margin:0 0 20px;font-size:15px;color:#475569;line-height:1.5;">{INTRO[purpose]}</p>
          <div style="text-align:center;margin:24px 0;">
            <div style="display:inline-block;padding:14px 26px;border-radius:12px;background:#f0fdfa;
                        border:1px dashed #14b8a6;font-size:34px;letter-spacing:10px;font-weight:700;color:#0f766e;
                        font-family:Consolas,Menlo,monospace;">{code}</div>
          </div>
          <p style="margin:0 0 6px;font-size:14px;color:#475569;">This code expires in <b>{ttl} minutes</b>.</p>
          <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.5;">
            If you didn't request this, you can safely ignore this email &mdash; nobody can use the code without access to your inbox.
            Never share this code with anyone.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""


def send_otp_email(to_email, code, purpose, username, ttl):
    """Send the OTP. Returns True on success."""
    cfg = current_app.config
    app_name = cfg["APP_NAME"]

    if not (cfg["SMTP_USER"] and cfg["SMTP_PASSWORD"]):
        # Local development without SMTP: show the code in the server log.
        current_app.logger.warning(
            "SMTP is not configured. OTP for %s (%s): %s", to_email, purpose, code
        )
        # On a deployed site this is a misconfiguration, so report failure.
        return not ON_VERCEL

    msg = EmailMessage()
    msg["Subject"] = f"{code} is your {app_name} code - {SUBJECTS[purpose]}"
    msg["From"] = f"{app_name} <{cfg['MAIL_FROM'] or cfg['SMTP_USER']}>"
    msg["To"] = to_email
    msg.set_content(
        f"Hi {username or 'there'},\n\n{INTRO[purpose]}\n\n"
        f"    {code}\n\nThis code expires in {ttl} minutes.\n"
        "If you didn't request it, ignore this email."
    )
    msg.add_alternative(_html(app_name, code, purpose, username, ttl), subtype="html")

    try:
        if cfg["SMTP_PORT"] == 465:
            with smtplib.SMTP_SSL(
                cfg["SMTP_HOST"], 465, timeout=15,
                context=ssl.create_default_context(),
            ) as s:
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as s:
                s.starttls(context=ssl.create_default_context())
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
                s.send_message(msg)
        return True
    except Exception:
        current_app.logger.exception("Failed to send OTP email")
        return False
