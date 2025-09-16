#!/bin/bash

# Installation script for Advanced Web Crawler & Vulnerability Scanner
# This script installs the required Python dependencies

echo "=========================================="
echo "Advanced Web Crawler & Vulnerability Scanner"
echo "Installation Script"
echo "=========================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.7 or higher first."
    exit 1
fi

echo "Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "Error: pip is not installed. Please install pip first."
    exit 1
fi

echo "Installing Python dependencies..."

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing from requirements.txt..."
    pip3 install -r requirements.txt
    if [ $? -eq 0 ]; then
        echo "✓ Dependencies installed successfully!"
    else
        echo "✗ Failed to install dependencies. Please check your Python/pip installation."
        exit 1
    fi
else
    echo "Error: requirements.txt not found in current directory."
    exit 1
fi

# Verify installation
echo "Verifying installation..."
python3 -c "
import aiohttp
import bs4
from bs4 import BeautifulSoup
print('✓ aiohttp version:', aiohttp.__version__)
print('✓ beautifulsoup4 available')
print('✓ All dependencies verified!')
"

echo ""
echo "=========================================="
echo "Installation completed successfully!"
echo ""
echo "Usage examples:"
echo "  python3 web.py https://example.com -d 3"
echo "  python3 web.py https://example.com --enable-vuln-scan --vuln-types sqli xss"
echo ""
echo "Run 'python3 web.py --help' for more options."
echo "=========================================="
