@echo off
title ShareSafe Privacy Studio Server
cd /d "%~dp0"
echo ===================================================
echo   ShareSafe - Sovereign Privacy Studio
echo   Starting server at: http://127.0.0.1:5000
echo ===================================================
start "" cmd /c "ping 127.0.0.1 -n 2 >nul & start http://127.0.0.1:5000"
python app.py
pause
