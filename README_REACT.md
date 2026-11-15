# SecureVault – Flask API + React frontend

```
app/api.py        NEW  JSON API (same logic, models, OTP, crypto as before)
app/spa.py        NEW  serves the built React app
frontend/         NEW  React (Vite) – all your HTML pages, same CSS/UI
app/routes.py          original Jinja routes (only active with LEGACY_UI=1, used by tests)
```

## 1. One-time setup
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env        (then fill SECRET_KEY and AES_KEY_B64)
cd frontend && npm install && cd ..
```

## 2a. Development (hot reload)
Run `start-dev.bat` (or two terminals: `python run.py` and `cd frontend && npm run dev`)
and open **http://localhost:5173**. Vite forwards `/api` to Flask on port 5000.

## 2b. Single server (production-style)
Run `build-frontend.bat`, then `python run.py` and open **http://127.0.0.1:5000**.

## Notes
- Without SMTP settings the 6-digit codes are printed in the Flask terminal.
- CSRF protection is still on: the React app fetches a token from `/api/csrf`.
- Tests: `python -m unittest discover -s tests -t .` (they use the original Jinja routes).
- Vercel: build the frontend first (`npm run build` in `frontend`) and make sure
  `frontend/dist` is deployed (remove it from `.vercelignore`/`.gitignore` if listed).
- Windows "Application Control policy" error: `frontend/package.json` already swaps
  Rollup/esbuild for their WebAssembly builds, so no blocked native binaries are used.

## Demo tools (optional)
Add `DEV_TOOLS=1` to `.env` and restart Flask. Each file then shows a **Tamper** button that
corrupts the stored copy on disk (the backup stays intact), so you can run an integrity scan
live, see the red alert and use **Recover**. Leave it at `0` in production.

## Security controls added for the CCP

| Control | What it does | Where |
|---|---|---|
| Two-step sign-in (MFA) | After a correct password, a 6-digit emailed code is required. Wrong codes are logged as `MFA_FAILED`. | `app/api.py` (`/api/login`, `/api/login/verify`) |
| Remember this device | Optional tick on the code screen. A signed, HttpOnly cookie lets that browser skip the code for 30 days. The password is still required, and the cookie stops working when the password changes. Logged as `DEVICE_TRUSTED`. | `app/api.py` (`_device_is_trusted`) |
| Role-based access control | Roles `user`, `analyst`, `admin`. Analysts see system-wide security events (read-only). Admins also assign roles and disable accounts. Nobody can open another user's files. Blocked attempts are logged as `ACCESS_DENIED`. | `app/rbac.py`, Admin tab in the dock |
| File sharing | An owner can give another existing user read-only access to a file and remove it again. Recipients download through the same integrity check; they cannot change, delete or re-share. Events: `FILE_SHARED`, `FILE_RECEIVED`, `FILE_SHARE_DOWNLOADED`, `FILE_SHARE_REVOKED`. | `app/api.py` (sharing section), `FileShare` in `app/models.py` |
| Envelope encryption | Every file gets its own random AES-256 key, wrapped by the master key. Files stored before this change still open. | `app/crypto.py` |
| Key rotation | Put the new key in `AES_KEY_B64` and the previous one in `AES_KEY_OLD_B64`. Old files stay readable, new files use the new key. | `app/crypto.py`, `.env.example` |
| HTTPS + headers | Optional HTTPS redirect, HSTS, Content-Security-Policy, Permissions-Policy. | `app/__init__.py` |

### Administrator account and the two logins
- The **first account that registers** becomes the administrator automatically. If accounts
  already exist and none is an admin, the oldest verified one is promoted when the server starts.
- The login page has two tabs: **User login** and **Admin login**. Admin login only accepts
  analyst / admin accounts and opens the Admin console; a normal account is refused and the
  attempt is logged as `ACCESS_DENIED`.
- More admins or analysts are assigned from the Admin console. `ADMIN_EMAILS` in `.env` is optional.

### Local HTTPS (for the demo)
Set `HTTPS=1` in `.env`, run `build-frontend.bat`, then `python run.py` and open
**https://127.0.0.1:5000** (accept the self-signed certificate warning once).
Use `HTTPS=0` when working with `start-dev.bat`.

### New settings in `.env`
`LOGIN_MFA` (default 1), `ADMIN_EMAILS`, `HTTPS`, `FORCE_HTTPS`, `AES_KEY_OLD_B64` — see `.env.example`.

### Tests
`python -m unittest discover -s tests -t .` now also runs `tests/test_api_security.py`
(two-step sign-in, roles, disabled accounts, headers) and the envelope/rotation cases in `tests/test_crypto.py`.
