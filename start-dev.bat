@echo off
REM Starts Flask (API) and the React dev server in two windows.
start "SecureVault API" cmd /k "python run.py"
cd frontend
start "SecureVault UI" cmd /k "npm run dev"
echo.
echo Open http://localhost:5173
