@echo off
REM ============================================================
REM  ECDAT Launcher
REM  Double-click this file to start the app in your browser.
REM  Place this .bat file in the SAME folder as app.py,
REM  algorithm_patcher.py, and the other project files.
REM ============================================================

title ECDAT - Enterprise Cryptographic Discovery & Analysis Tool

echo.
echo ============================================================
echo   ECDAT - Starting up, please wait...
echo ============================================================
echo.

REM --------------------------------------------------------
REM Step 1: Check that Python is installed
REM --------------------------------------------------------
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found on this computer.
    echo.
    echo Please install Python first:
    echo   1. Go to https://www.python.org/downloads/
    echo   2. Download and run the installer.
    echo   3. IMPORTANT: On the first install screen, check the box
    echo      that says "Add Python to PATH" before clicking Install.
    echo   4. After installing, double-click this file again.
    echo.
    pause
    exit /b 1
)

REM --------------------------------------------------------
REM Step 2: Make sure we're running from the project folder
REM --------------------------------------------------------
cd /d "%~dp0"

if not exist "app.py" (
    echo [ERROR] app.py was not found in this folder:
    echo   %~dp0
    echo.
    echo Make sure this .bat file is in the SAME folder as app.py,
    echo algorithm_patcher.py, and the rest of the project files,
    echo then double-click it again.
    echo.
    pause
    exit /b 1
)

REM --------------------------------------------------------
REM Step 3: Install required packages (only downloads what's
REM missing; safe to run every time, does nothing if already
REM installed)
REM --------------------------------------------------------
echo Checking required packages (streamlit, pandas, plotly)...
python -m pip install --quiet --disable-pip-version-check streamlit>=1.30 pandas>=2.0 plotly>=5.15

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Could not install required packages.
    echo Please check your internet connection and try again.
    echo.
    pause
    exit /b 1
)

REM --------------------------------------------------------
REM Step 4: Launch the app - this opens automatically in your
REM default web browser. Keep this black window open while you
REM use the app; closing it will stop the app.
REM --------------------------------------------------------
echo.
echo Starting ECDAT... your browser will open automatically.
echo (Keep this window open while using the app. Close it to stop.)
echo.

python -m streamlit run app.py

pause
