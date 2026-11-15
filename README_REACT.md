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
