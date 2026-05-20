#!/bin/bash
# GARE Launcher - Ghidra Agentic Reverse Engineering Pipeline
# Run this script to configure and start GARE.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/config/.env"
ENV_EXAMPLE="$SCRIPT_DIR/config/.env.example"
DOCKER_DIR="$SCRIPT_DIR/docker"

echo ""
echo "============================================"
echo "  GARE - Ghidra Agentic RE Pipeline"
echo "  Launcher"
echo "============================================"
echo ""

# Step 1: Check Docker
echo "[1/4] Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo ""
    echo "  ERROR: Docker is not installed or not in PATH."
    echo ""
    echo "  Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    echo "  After installing, ensure Docker is running and try again."
    echo ""
    exit 1
fi

if ! docker info &> /dev/null 2>&1; then
    echo ""
    echo "  ERROR: Docker daemon is not running."
    echo "  Start Docker Desktop and try again."
    echo ""
    exit 1
fi

echo "  Docker found: $(docker --version)"

if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    echo "  Compose found: $(docker compose version)"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "  Compose found: $(docker-compose --version)"
else
    echo ""
    echo "  ERROR: Docker Compose is not installed."
    echo "  Install Docker Compose v2+ and try again."
    echo ""
    exit 1
fi
echo ""

# Step 2: Check/configure API key
echo "[2/4] Checking configuration..."
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        echo "  Created config/.env from template."
    else
        echo "  ERROR: No .env or .env.example found in config/."
        exit 1
    fi
fi

# Read current API key
CURRENT_KEY=$(grep "^API_KEY=" "$ENV_FILE" | cut -d'=' -f2-)

if [ -z "$CURRENT_KEY" ] || [ "$CURRENT_KEY" = "YOUR_API_KEY_HERE" ] || [ "$CURRENT_KEY" = "your-api-key-here" ]; then
    echo ""
    echo "  No API key configured."
    echo ""
    echo "  Choose your LLM provider:"
    echo "    1) Anthropic (cloud, requires API key)"
    echo "    2) OpenAI-compatible (cloud, requires API key)"
    echo "    3) Local LLM (Ollama, LM Studio, vLLM, etc.)"
    echo ""
    read -p "  Selection [1/2/3]: " PROVIDER_CHOICE

    case "$PROVIDER_CHOICE" in
        2)
            sed -i "s/^LLM_PROVIDER=.*/LLM_PROVIDER=openai/" "$ENV_FILE"
            echo ""
            read -p "  Enter your OpenAI API key: " NEW_KEY
            sed -i "s/^API_KEY=.*/API_KEY=$NEW_KEY/" "$ENV_FILE"
            read -p "  Enter model name [gpt-4]: " MODEL_NAME
            MODEL_NAME=${MODEL_NAME:-gpt-4}
            sed -i "s/^MODEL_NAME=.*/MODEL_NAME=$MODEL_NAME/" "$ENV_FILE"
            ;;
        3)
            sed -i "s/^LLM_PROVIDER=.*/LLM_PROVIDER=openai/" "$ENV_FILE"
            sed -i "s/^API_KEY=.*/API_KEY=not-needed/" "$ENV_FILE"
            echo ""
            echo "  Common local LLM endpoints:"
            echo "    LM Studio:           http://host.docker.internal:1234/v1"
            echo "    Ollama:              http://host.docker.internal:11434/v1"
            echo "    vLLM:                http://host.docker.internal:8000/v1"
            echo "    text-generation-webui: http://host.docker.internal:5000/v1"
            echo ""
            read -p "  Enter your local LLM URL: " BASE_URL
            sed -i "s|^#*BASE_URL=.*|BASE_URL=$BASE_URL|" "$ENV_FILE"
            read -p "  Enter model name: " MODEL_NAME
            sed -i "s/^MODEL_NAME=.*/MODEL_NAME=$MODEL_NAME/" "$ENV_FILE"
            echo ""
            echo "  NOTE: Your local LLM must support function/tool calling"
            echo "  and have a 32K+ token context window."
            ;;
        *)
            sed -i "s/^LLM_PROVIDER=.*/LLM_PROVIDER=anthropic/" "$ENV_FILE"
            echo ""
            read -p "  Enter your Anthropic API key: " NEW_KEY
            sed -i "s/^API_KEY=.*/API_KEY=$NEW_KEY/" "$ENV_FILE"
            read -p "  Enter Anthropic model identifier: " MODEL_NAME
            sed -i "s/^MODEL_NAME=.*/MODEL_NAME=$MODEL_NAME/" "$ENV_FILE"
            ;;
    esac
    echo ""
    echo "  Configuration saved to config/.env"
else
    PROVIDER=$(grep "^LLM_PROVIDER=" "$ENV_FILE" | cut -d'=' -f2-)
    echo "  API key is configured (provider: $PROVIDER)"
fi
echo ""

# Step 3: Build and start
echo "[3/4] Building and starting GARE containers..."
echo "  (First build downloads Ghidra 12.1 and may take 5-10 minutes)"
echo ""

cd "$DOCKER_DIR"
$COMPOSE_CMD up --build -d

echo ""

# Step 4: Wait for health and open browser
echo "[4/4] Waiting for services to start..."

ATTEMPTS=0
MAX_ATTEMPTS=60
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo ""
        echo "============================================"
        echo "  GARE is running!"
        echo ""
        echo "  Web UI:   http://localhost:3000"
        echo "  API:      http://localhost:8000"
        echo "  API Docs: http://localhost:8000/docs"
        echo ""
        echo "  To stop:  cd docker && $COMPOSE_CMD down"
        echo "  Logs:     docker logs gare-backend -f"
        echo "============================================"
        echo ""

        # Try to open browser
        if command -v xdg-open &> /dev/null; then
            xdg-open http://localhost:3000 2>/dev/null &
        elif command -v open &> /dev/null; then
            open http://localhost:3000 2>/dev/null &
        elif command -v explorer.exe &> /dev/null; then
            explorer.exe "http://localhost:3000" 2>/dev/null &
        fi

        exit 0
    fi
    ATTEMPTS=$((ATTEMPTS + 1))
    printf "  Waiting... (%d/%d)\r" "$ATTEMPTS" "$MAX_ATTEMPTS"
    sleep 5
done

echo ""
echo "  WARNING: Health check timed out after 5 minutes."
echo "  Containers may still be building. Check logs with:"
echo "    docker logs gare-backend -f"
echo ""
