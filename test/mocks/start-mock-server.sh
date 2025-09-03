#!/bin/bash

# Mock MCP Server Setup and Start Script

echo "🚀 Setting up Mock MCP Server for Security Testing"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
else
    python3 -m pip install -r requirements.txt
fi

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed successfully"

# Make the script executable
chmod +x mock-mcp-server.py

# Start the server
echo ""
echo "🔥 Starting Mock MCP Server in VULNERABLE mode..."
echo "⚠️  WARNING: This server contains intentional security vulnerabilities!"
echo "   Only use for testing the MCP Security Scanner."
echo ""

python3 mock-mcp-server.py --host 0.0.0.0 --port 8000 --verbose
