# SecureVault — Tamper-Aware Secure File Management System

Flask app that encrypts every uploaded file with **AES-256-GCM**, stores a **SHA-256** fingerprint, and re-verifies it on every download / integrity scan. Accounts are protected with **email OTP verification** (registration + forgot password), bcrypt hashing, CSRF protection and login throttling.

## Features
- Register with email → 6-digit OTP (hashed in DB, 10 min expiry, 5 attempts, 60 s resend cooldown)
- Forgot password → OTP by email → set new password (no account enumeration)
- Login with username **or** email, brute-force lockout (5 fails / 15 min)
- Encrypted upload, verified download, delete, one-click integrity scan
- Security event audit log (uploads, downloads, tamper alerts, logins, resets)
- Responsive dashboard with light/dark theme

## Run locally
```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env              # then fill in the values
python run.py                     # http://127.0.0.1:5000
```
If `SMTP_USER` / `SMTP_PASSWORD` are empty, OTP codes are printed in the terminal instead of emailed — handy for development.

### Gmail SMTP (free)
1. Turn on **2-Step Verification** on the Google account.
2. Create an **App password**: https://myaccount.google.com/apppasswords
3. Put it in `.env` as `SMTP_PASSWORD`, and your Gmail address as `SMTP_USER`.

## Tests
```bash
python -m unittest discover -s tests -t .
```

## Deploy on Vercel (free)
Vercel's filesystem is temporary, so on Vercel the app uses a free **Postgres** database (Neon) and keeps the encrypted bytes in it (`STORAGE_BACKEND=db`, automatic when `DATABASE_URL` is set).

1. **Database** – create a free project at https://neon.tech, copy the connection string.
2. **GitHub** – push this folder to a new GitHub repo (`.env` and `.venv` are git-ignored).
3. **Vercel** – https://vercel.com → *Add New → Project* → import the repo (Framework preset: *Other*).
4. **Environment variables** (Project → Settings → Environment Variables):

| Name | Value |
|---|---|
| `SECRET_KEY` | long random string (`python -c "import secrets;print(secrets.token_hex(32))"`) |
| `AES_KEY_B64` | 32-byte base64 key — **never change it later or old files can't be decrypted** |
| `DATABASE_URL` | Neon connection string |
| `SMTP_HOST` / `SMTP_PORT` | `smtp.gmail.com` / `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | Gmail address / app password |
| `APP_NAME` | optional, e.g. `SecureVault` |

5. **Deploy**. You get a free `https://<project>.vercel.app` domain.

Vercel limits request bodies to ~4.5 MB, so uploads are capped at 4 MB there (`MAX_UPLOAD_MB`).

## Project layout
```
api/index.py        Vercel entry point        app/otp.py       OTP generation/verification
vercel.json         routes everything to it   app/mailer.py    SMTP + HTML email
app/routes.py       all routes                app/storage.py   disk / database storage backends
app/crypto.py       AES-256-GCM               app/integrity.py SHA-256 verification
```
