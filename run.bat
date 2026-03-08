@echo off
cls
echo 🔐 Login Attempt Monitoring System
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed.
    pause
    exit /b 1
)

echo ✓ Python found

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt > nul 2>&1

REM Create necessary directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs

echo.
echo ✓ Setup complete!
echo.
echo 🚀 Starting application...
echo 📊 Dashboard: http://localhost:5000
echo.

REM Run the application
python app.py

pause
