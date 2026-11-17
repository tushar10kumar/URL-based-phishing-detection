@echo off
title PhishShield - URL Phishing Detection ML System
cd /d "%~dp0"
echo =======================================================
echo    PhishShield: URL Phishing Detection ML
echo =======================================================
echo.
echo Opening Web Dashboard in your browser...
start http://127.0.0.1:5000
echo.
echo Starting Flask Server...
python app.py
pause
