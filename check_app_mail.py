import os
from pathlib import Path
import smtplib, ssl

# Does a system env var exist BEFORE .env is loaded? (it would override .env)
print("System env SMTP_PASSWORD set before .env load:", bool(os.environ.get("SMTP_PASSWORD")))
print("System env SMTP_USER set before .env load:    ", bool(os.environ.get("SMTP_USER")))

from app import create_app, PROJECT_ROOT
print("Looking for .env at:", PROJECT_ROOT / ".env")
print(".env exists:", (PROJECT_ROOT / ".env").exists())
print("Files named like .env here:", [p.name for p in Path(PROJECT_ROOT).glob(".env*")])

app = create_app()
c = app.config
print("SMTP_HOST:", c["SMTP_HOST"], "| SMTP_PORT:", c["SMTP_PORT"], type(c["SMTP_PORT"]).__name__)
print("SMTP_USER:", repr(c["SMTP_USER"]))
pw = c["SMTP_PASSWORD"]
print("SMTP_PASSWORD length:", len(pw), "(a Gmail app password should be exactly 16)")
print("Contains quotes:", ('"' in pw) or ("'" in pw))

try:
    with smtplib.SMTP(c["SMTP_HOST"], c["SMTP_PORT"], timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(c["SMTP_USER"], pw)
    print("RESULT: LOGIN OK with the app's config")
except Exception as e:
    print("RESULT: FAILED ->", repr(e))