Published by: Justin Phillips

# GARE - Ghidra Agentic RE Pipeline

Automated binary reverse engineering system combining Ghidra's static analysis with LLM-driven autonomous reasoning via Model Context Protocol (MCP) tool calling.

Upload a binary, and an LLM agent autonomously analyzes it through Ghidra -- listing functions, decompiling code, renaming symbols, and producing a structured report in 2-10 minutes.

---

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose
- 8GB+ RAM
- LLM API key (Anthropic or OpenAI-compatible)

### Setup

```bash
# 1. Configure your API key
cd config
cp .env.example .env
# Edit .env and set API_KEY to your key

# 2. Build and start (first build downloads Ghidra 12.1, takes ~5-10 min)
cd ../docker
docker compose up --build

# 3. Access the application
#    Web UI:   http://localhost:3000
#    API:      http://localhost:8000
#    API Docs: http://localhost:8000/docs
```

### Usage

1. Open http://localhost:3000 in your browser
2. Upload a binary file (ELF, PE, Mach-O, etc.)
3. Watch the live analysis logs as the agent works
4. Download results when complete:
   - **Analysis Report (DOCX)** -- Professionally formatted Word document with styled headings, tables, and code blocks
   - **Annotated Code (TXT)** -- Human-readable decompiled code with renamed functions (primary export)
   - **Ghidra Database (ZIP)** -- Full Ghidra project for continued analysis in Ghidra GUI

### Multi-Agent Analysis

Upload with `multi_agent=true` to use three specialized agent personas (triage, security auditor, code analyst) that analyze the binary sequentially with shared findings.

```bash
curl -X POST http://localhost:8000/api/upload \
  -F "file=@binary" -F "multi_agent=true"
```

### Batch Upload

Upload multiple binaries for sequential analysis in a single job:

```bash
curl -X POST http://localhost:8000/api/upload/batch \
  -F "files=@binary1" -F "files=@binary2" -F "intensity=quick"
```

---

## Architecture

Simple 2-container Docker setup:

```
Container 1: gare-backend (port 8000, 8001)
  - FastAPI REST API (accepts uploads, manages jobs, streams logs via SSE)
  - Worker Control Plane (PyGhidra wrapper, executes Ghidra scripts)
  - MCP Server (protocol bridge between agent and worker)
  - LLM Agent (autonomous analysis loop via subprocess)
  - Ghidra 12.1

Container 2: gare-webui (port 3000)
  - React SPA with live log streaming
  - Nginx serving static files
```

### Data Flow

```
Upload -> API -> Ghidra Worker (import + analyze) -> LLM Agent (via MCP tools) -> Report
```

All job state is file-based (no database):

```
/app/data/jobs/{job_id}/
  input/          Uploaded binary
  ghidra_project/ PyGhidra project files
  logs/job.log    Real-time analysis logs
  report/         Generated report (report.md + report.docx)
  job.json        Job metadata and status
```

---

## Configuration

All settings via `config/.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | (required) | LLM provider API key |
| `LLM_PROVIDER` | `anthropic` | Provider: `anthropic` or `openai` |
| `BASE_URL` | (blank) | Custom endpoint for local LLMs |
| `MODEL_NAME` | (required) | Model identifier (provider-specific) |
| `MAX_TOOL_CALLS` | `100` | Max Ghidra tool calls per analysis |
| `AGENT_TIMEOUT` | `300` | Agent timeout in seconds |
| `DISABLE_HOOKS` | `false` | Disable pre/post script hooks (GB-23) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### Local LLM Support

To use a local model (e.g., via Ollama, vLLM, or similar):

```bash
LLM_PROVIDER=openai
API_KEY=local-key
BASE_URL=http://host.docker.internal:8080/v1
MODEL_NAME=your-model-name
```

The local server must provide an OpenAI-compatible `/v1/chat/completions` endpoint with function/tool calling support.

---

## Project Structure

```
GARE/
  backend/            Python backend
    src/
      config/         Configuration modules
      models/         Data models (Job, JobStatus)
      routes/         API endpoints + orchestrator
      services/
        agent/        LLM agent + report generator
        worker/       PyGhidra wrapper + control plane
        mcp_server/   MCP tool bridge
      middleware/     Security (path traversal, sanitization)
      scripts/        Ghidra analysis scripts (36 scripts)
      utils/          Timezone utilities
    Dockerfile
    requirements.txt
  frontend/           React web interface
    src/
      components/     JobDetail, JobsList, UploadView, ReportViewer
      services/       API client
      types/          TypeScript definitions
    Dockerfile
  docker/             Docker Compose files
  config/             Environment configuration
  docs/               Architecture, development guide, changelog
```

---

## Stopping / Restarting

```bash
# Stop
cd docker && docker compose down

# Restart after code changes
cd docker && docker compose up --build

# View logs
docker logs gare-backend -f
docker logs gare-webui -f
```

---

## Documentation

- `docs/DEVELOPMENT.md` -- Developer guidance and code modification patterns
- `docs/ARCHITECTURE.md` -- Technical architecture details
- `docs/CHANGELOG.md` -- Version history

---

## Security Notice

This release ships input-side security controls: path-traversal protection, filename sanitization, Ghidra-script allowlisting (36 named scripts), and argument sanitization for all script parameters. The API itself, however, has **no built-in authentication and no rate limiting** — these are operator responsibilities that must be addressed (reverse-proxy auth, mTLS, network policies, or a higher-layer gateway) before exposing the service to untrusted networks. See `docs/ARCHITECTURE.md` for the full security model.

---

## License

Copyright 2026 Justin Phillips. Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for attribution details.

You may use, modify, and redistribute this project (including for commercial purposes) as long as you preserve the copyright notice, license text, and `NOTICE` file in derivative works, and clearly state any changes you make. The license also grants you a patent license from contributors covering their contributions.

Ghidra itself is a separate work by the U.S. National Security Agency, also under Apache 2.0; it is downloaded at container build time from the [official NSA release](https://github.com/NationalSecurityAgency/ghidra/releases) and is not redistributed by this project.

---

## Status

**Version:** 1.0.0 — Initial Release
**Ghidra:** 12.1 | **Python:** 3.11 | **Node:** 18+ | **Docker:** 2 containers
**Tools:** 40 MCP tools | **Scripts:** 36 Ghidra scripts | **Enhancements:** 23 GB capabilities
