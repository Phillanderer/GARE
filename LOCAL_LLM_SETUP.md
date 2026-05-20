# Local LLM Configuration

## Quick Setup: gpt-oss 120b

### 1. Update `.env` file:

```bash
# LLM Configuration
LLM_PROVIDER=openai
API_KEY=local-key
BASE_URL=http://localhost:8080/v1
MODEL_NAME=gpt-oss-120b
```

### 2. Restart containers:

```bash
cd docker
docker compose down
docker compose up --build
```

---

## Configuration Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `LLM_PROVIDER` | LLM client type | `anthropic` or `openai` |
| `API_KEY` | API key (can be dummy for local) | `local-key` or actual key |
| `BASE_URL` | Local server endpoint | `http://localhost:8080/v1` |
| `MODEL_NAME` | Model identifier | `gpt-oss-120b` |

---

## Local LLM Server Requirements

Your local LLM server must:
- Support OpenAI-compatible API format
- Provide `/v1/chat/completions` endpoint
- Support function/tool calling
- Have sufficient context window (32K+ tokens recommended)

---

## Switching Back to Anthropic

```bash
# In .env file:
LLM_PROVIDER=anthropic
API_KEY=YOUR_API_KEY_HERE
BASE_URL=  # Leave blank or remove
MODEL_NAME=YOUR_MODEL_IDENTIFIER  # e.g. anthropic model ID from console.anthropic.com
```

Then restart: `docker compose down && docker compose up`

---

## Common Local LLM Servers

- **LM Studio**: `http://localhost:1234/v1`
- **Ollama** (with OpenAI compatibility): `http://localhost:11434/v1`
- **text-generation-webui**: `http://localhost:5000/v1`
- **vLLM**: `http://localhost:8000/v1`
- **LiteLLM** (proxy): `http://localhost:8080`

Set `BASE_URL` to your server's endpoint.
