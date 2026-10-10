@echo off
title ShareSafe Server
cd /d "%~dp0"
echo ===================================================
echo   ShareSafe - Starting Web Application...
echo   Open your browser at: http://127.0.0.1:5000
echo ===================================================
start http://127.0.0.1:5000
python app.py
pause
