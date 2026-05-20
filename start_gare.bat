@echo off
REM GARE Launcher - Ghidra Agentic Reverse Engineering Pipeline
REM Run this script to configure and start GARE on Windows.

setlocal enabledelayedexpansion

echo.
echo ============================================
echo   GARE - Ghidra Agentic RE Pipeline
echo   Launcher (Windows)
echo ============================================
echo.

REM Step 1: Check Docker
echo [1/4] Checking Docker...
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   ERROR: Docker is not installed or not in PATH.
    echo.
    echo   Install Docker Desktop from: https://www.docker.com/products/docker-desktop
    echo   After installing, ensure Docker is running and try again.
    echo.
    pause
    exit /b 1
)

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   ERROR: Docker daemon is not running.
    echo   Start Docker Desktop and try again.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('docker --version') do echo   Docker found: %%i

docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   ERROR: Docker Compose is not available.
    echo   Update Docker Desktop to get Docker Compose v2.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('docker compose version') do echo   Compose found: %%i
echo.

REM Step 2: Check/configure API key
echo [2/4] Checking configuration...

set "SCRIPT_DIR=%~dp0"
set "ENV_FILE=%SCRIPT_DIR%config\.env"
set "ENV_EXAMPLE=%SCRIPT_DIR%config\.env.example"

if not exist "%ENV_FILE%" (
    if exist "%ENV_EXAMPLE%" (
        copy "%ENV_EXAMPLE%" "%ENV_FILE%" >nul
        echo   Created config\.env from template.
    ) else (
        echo   ERROR: No .env or .env.example found in config\.
        pause
        exit /b 1
    )
)

REM Check if API key needs to be set
findstr /c:"YOUR_API_KEY_HERE" "%ENV_FILE%" >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo   No API key configured.
    echo.
    echo   Choose your LLM provider:
    echo     1^) Anthropic (cloud, requires API key)
    echo     2^) OpenAI-compatible (cloud, requires API key)
    echo     3^) Local LLM (Ollama, LM Studio, vLLM, etc.)
    echo.
    set /p PROVIDER_CHOICE="  Selection [1/2/3]: "

    if "!PROVIDER_CHOICE!"=="3" (
        echo.
        echo   Common local LLM endpoints:
        echo     LM Studio:             http://host.docker.internal:1234/v1
        echo     Ollama:                http://host.docker.internal:11434/v1
        echo     vLLM:                  http://host.docker.internal:8000/v1
        echo     text-generation-webui: http://host.docker.internal:5000/v1
        echo.
        set /p BASE_URL="  Enter your local LLM URL: "
        set /p MODEL_NAME="  Enter model name: "
        set "NEW_KEY=not-needed"
        set "PROVIDER=openai"
        echo.
        echo   NOTE: Your local LLM must support function/tool calling
        echo   and have a 32K+ token context window.
    ) else if "!PROVIDER_CHOICE!"=="2" (
        set /p NEW_KEY="  Enter your OpenAI API key: "
        set /p MODEL_NAME="  Enter model name [gpt-4]: "
        if "!MODEL_NAME!"=="" set "MODEL_NAME=gpt-4"
        set "PROVIDER=openai"
    ) else (
        set /p NEW_KEY="  Enter your Anthropic API key: "
        set /p MODEL_NAME="  Enter Anthropic model identifier: "
        set "PROVIDER=anthropic"
    )

    REM Write the config using PowerShell for reliable file editing
    powershell -Command "(Get-Content '%ENV_FILE%') -replace '^API_KEY=.*', 'API_KEY=!NEW_KEY!' -replace '^LLM_PROVIDER=.*', 'LLM_PROVIDER=!PROVIDER!' -replace '^MODEL_NAME=.*', 'MODEL_NAME=!MODEL_NAME!' | Set-Content '%ENV_FILE%'"

    if defined BASE_URL (
        powershell -Command "(Get-Content '%ENV_FILE%') -replace '^#?BASE_URL=.*', 'BASE_URL=!BASE_URL!' | Set-Content '%ENV_FILE%'"
    )

    echo.
    echo   Configuration saved to config\.env
) else (
    echo   API key is configured.
)
echo.

REM Step 3: Build and start
echo [3/4] Building and starting GARE containers...
echo   (First build downloads Ghidra 12.1 and may take 5-10 minutes)
echo.

cd /d "%SCRIPT_DIR%docker"
docker compose up --build -d

echo.

REM Step 4: Wait for health and open browser
echo [4/4] Waiting for services to start...

set ATTEMPTS=0
:healthloop
if %ATTEMPTS% geq 60 goto timeout

curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel% equ 0 goto running

set /a ATTEMPTS+=1
echo   Waiting... (%ATTEMPTS%/60)
timeout /t 5 /nobreak >nul
goto healthloop

:running
echo.
echo ============================================
echo   GARE is running!
echo.
echo   Web UI:   http://localhost:3000
echo   API:      http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
echo   To stop:  cd docker ^&^& docker compose down
echo   Logs:     docker logs gare-backend -f
echo ============================================
echo.
start http://localhost:3000
goto done

:timeout
echo.
echo   WARNING: Health check timed out after 5 minutes.
echo   Containers may still be building. Check logs with:
echo     docker logs gare-backend -f
echo.

:done
pause
