@echo off
REM Installation script for Advanced Web Crawler & Vulnerability Scanner (Windows)
REM This script installs the required Python dependencies

echo ==========================================
echo Advanced Web Crawler & Vulnerability Scanner
echo Installation Script (Windows)
echo ==========================================

REM Check if Python 3 is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python 3 is not installed. Please install Python 3.7 or higher first.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo %PYTHON_VERSION% found

REM Check if pip is installed
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: pip is not installed. Please install pip first.
    pause
    exit /b 1
)

echo Installing Python dependencies...

REM Install requirements
if exist "requirements.txt" (
    echo Installing from requirements.txt...
    python -m pip install -r requirements.txt
    if %errorlevel% equ 0 (
        echo [+] Dependencies installed successfully!
    ) else (
        echo [-] Failed to install dependencies. Please check your Python/pip installation.
        pause
        exit /b 1
    )
) else (
    echo Error: requirements.txt not found in current directory.
    pause
    exit /b 1
)

REM Verify installation
echo Verifying installation...
python -c "import aiohttp; import bs4; from bs4 import BeautifulSoup; print('[+] aiohttp available'); print('[+] beautifulsoup4 available'); print('[+] All dependencies verified!')" 2>nul
if %errorlevel% neq 0 (
    echo [-] Verification failed. Some dependencies may not be installed correctly.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Installation completed successfully!
echo.
echo Usage examples:
echo   python web.py https://example.com -d 3
echo   python web.py https://example.com --enable-vuln-scan --vuln-types sqli xss
echo.
echo Run 'python web.py --help' for more options.
echo ==========================================

pause
