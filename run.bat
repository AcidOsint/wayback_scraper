@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on this computer.
    echo Install it from https://python.org/downloads and check
    echo the "Add python.exe to PATH" box during install.
    echo Then run this file again.
    pause
    exit /b 1
)

python archive_wayback.py
pause