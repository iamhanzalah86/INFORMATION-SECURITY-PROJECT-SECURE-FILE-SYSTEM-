@echo off
REM Builds the React app into frontend\dist. Flask then serves it at http://127.0.0.1:5000
cd frontend
call npm install
call npm run build
cd ..
echo.
echo Done. Now run:  python run.py   and open http://127.0.0.1:5000
