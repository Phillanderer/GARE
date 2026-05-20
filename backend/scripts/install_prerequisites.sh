#!/bin/bash
# Install prerequisites for Ghidra Agentic RE Pipeline smoke test

set -e

echo "======================================"
echo "Installing Prerequisites"
echo "======================================"
echo ""

# Check if running in WSL
if grep -qi microsoft /proc/version; then
    echo "✓ Detected WSL2 environment"
    echo ""
fi

# Install jq
echo "[1/2] Installing jq (JSON processor)..."
if command -v jq &> /dev/null; then
    echo "  ✓ jq already installed: $(jq --version)"
else
    sudo apt-get update
    sudo apt-get install -y jq
    echo "  ✓ jq installed successfully"
fi
echo ""

# Check Docker Desktop integration
echo "[2/2] Checking Docker..."
if command -v docker &> /dev/null; then
    echo "  ✓ Docker is accessible"
    docker --version
    docker compose version || docker-compose --version
else
    echo "  ⚠ Docker not accessible in WSL2"
    echo ""
    echo "Docker Desktop is installed on Windows but WSL integration is not enabled."
    echo ""
    echo "To enable Docker in WSL2:"
    echo "  1. Open Docker Desktop on Windows"
    echo "  2. Go to Settings → Resources → WSL Integration"
    echo "  3. Enable integration for your WSL2 distro (Ubuntu)"
    echo "  4. Click 'Apply & Restart'"
    echo "  5. Wait for Docker Desktop to restart"
    echo "  6. Run this script again to verify"
    echo ""
    exit 1
fi
echo ""

echo "======================================"
echo "✓ All prerequisites installed!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Get your LLM API key (local or cloud-based)"
echo "  2. Configure .env file: cp .env.example .env"
echo "  3. Edit .env and set API_KEY"
echo "  4. Run smoke test: ./scripts/smoke_test.sh /bin/ls"
echo ""
