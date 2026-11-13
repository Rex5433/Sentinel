@echo off
setlocal
cd /d "%~dp0"
title Sentinel V5.5 - Roar Cyber ^| Team 84
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "scripts\launch.py" %*
) else (
    python "scripts\launch.py" %*
)
set "sentinel_exit=%errorlevel%"
if not "%sentinel_exit%"=="0" (
    echo.
    echo Sentinel could not start. Review the error above.
    echo Python 3.11 or newer must be installed and available on PATH.
    pause
)
exit /b %sentinel_exit%
