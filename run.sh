#!/bin/bash

echo "🔐 Login Attempt Monitoring System"
echo "===================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

echo "✓ Python found"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Create necessary directories
mkdir -p data logs

echo ""
echo "✓ Setup complete!"
echo ""
echo "🚀 Starting application..."
echo "📊 Dashboard: http://localhost:5000"
echo ""

# Run the application
python app.py
