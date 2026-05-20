# GARE Architecture

**Last Updated:** 2026-02-10

## Overview

This document describes the architecture of the Ghidra Agentic RE Pipeline (GARE), a 2-container Docker application for automated binary reverse engineering using Ghidra and LLM-driven autonomous analysis.

## Directory Structure

```
GARE/
|-- frontend/                    # React SPA (renamed from webui/ on 2026-02-02)
|   |-- src/
|   |   |-- assets/              # Static assets (images, fonts)
|   |   |-- components/          # React UI components
|   |   |   |-- JobDetail.tsx    # Job status, logs, downloads
|   |   |   |-- JobsList.tsx     # Job listing
|   |   |   |-- UploadView.tsx   # Binary upload form
|   |   |   `-- ReportViewer.tsx # Report display
|   |   |-- services/            # API communication (api.ts)
|   |   |-- types/               # TypeScript type definitions
|   |   |-- utils/               # Helper functions
|   |   `-- tests/               # Frontend tests
|   |-- Dockerfile
|   |-- package.json
|   `-- vite.config.ts
|
|-- backend/                     # Python backend (all services in one container)
|   |-- src/
|   |   |-- config/              # Configuration modules
|   |   |   |-- api_config.py    # API service config (DATA_DIR, WORKER_URL)
|   |   |   |-- mcp_config.py   # MCP server configuration
|   |   |   `-- worker_config.py # Worker service configuration
|   |   |-- models/              # Data models and schemas
|   |   |   `-- models.py       # Job, JobStatus (Pydantic models)
|   |   |-- routes/              # API endpoints and orchestration
|   |   |   |-- main.py         # FastAPI app, worker subprocess startup
|   |   |   `-- orchestrator.py # Job lifecycle, agent subprocess launch
|   |   |-- services/            # Business logic modules
|   |   |   |-- agent/          # LLM agent for autonomous analysis
|   |   |   |   |-- llm_agent.py       # Agentic loop, tool definitions, LLM client
|   |   |   |   |-- runner.py          # Agent entry point (subprocess)
|   |   |   |   |-- multi_agent.py     # Multi-agent orchestrator (GB-21: triage/security/code personas)
|   |   |   |   |-- metrics_collector.py # Analysis metrics (GB tool utilization, error rates)
|   |   |   |   |-- planner.py         # Analysis step planner (legacy path)
|   |   |   |   |-- prompts.py         # System prompt, analysis strategy, compiler variation ref
|   |   |   |   |-- report_generator.py # Structured report generator (legacy path)
|   |   |   |   |-- docx_exporter.py   # Markdown-to-DOCX converter (styled Word docs)
|   |   |   |   |-- ioc_extractor.py   # IOC extraction utilities
|   |   |   |   `-- mitre_mapping.py   # MITRE ATT&CK mapping
|   |   |   |-- worker/         # PyGhidra worker
|   |   |   |   |-- main.py            # Worker entry point (subprocess, port 8001)
|   |   |   |   |-- control_plane.py   # FastAPI worker endpoints
|   |   |   |   |-- ghidra_runner.py   # PyGhidra script executor, ALLOWED_SCRIPTS
|   |   |   |   |-- analysis_config.py # Intensity-based analysis configuration (GB-11)
|   |   |   |   |-- batch_processor.py # Multi-binary batch processing (GB-22)
|   |   |   |   |-- script_hooks.py    # Pre/post script hook manager (GB-23)
|   |   |   |   |-- pyghidra_wrapper.py # PyGhidra initialization wrapper
|   |   |   |   `-- security.py        # Worker-specific input validation
|   |   |   `-- mcp_server/     # MCP protocol bridge
|   |   |       |-- tools.py           # GhidraTools HTTP wrapper (agent -> worker)
|   |   |       |-- server.py          # MCP FastMCP server definition
|   |   |       `-- config.py          # MCP configuration
|   |   |-- middleware/          # Cross-cutting concerns
|   |   |   |-- security.py     # Path validation, filename sanitization
|   |   |   `-- worker_security.py # Worker-specific security utilities
|   |   |-- scripts/             # Ghidra analysis scripts
|   |   |   `-- ghidra_scripts/  # 36 whitelisted .py scripts
|   |   |-- utils/               # Utility modules
|   |   |   `-- timezone.py      # UTC-aware datetime utilities
|   |   `-- tests/               # Backend tests
|   |-- scripts/                 # Utility shell scripts
|   |   |-- cleanup_old_jobs.sh
|   |   |-- fix_docker_permissions.sh
|   |   |-- install_prerequisites.sh
|   |   `-- smoke_test.sh
|   |-- Dockerfile
|   `-- requirements.txt
|
|-- docker/                      # Docker orchestration
|   `-- docker-compose.yml       # 2-container stack (project name: gare)
|
|-- config/                      # Environment configuration
|   |-- .env                     # Environment variables (gitignored)
|   `-- .env.example             # Template for configuration
|
|-- data/                        # Runtime job data (gitignored)
|   `-- jobs/
|       `-- {job_id}/
|           |-- input/           # Uploaded binary
|           |-- ghidra_project/  # PyGhidra database files
|           |-- artifacts/       # metadata.json, notebook.json
|           |-- logs/            # job.log (agent writes, API streams via SSE)
|           `-- report/          # report.md + report.docx (generated on download)
|
|-- docs/                        # Essential documentation
|   |-- ARCHITECTURE.md          # This file
|   |-- DEVELOPMENT.md           # Development guidance
|   `-- CHANGELOG.md             # Version history
|
|-- LOCAL_LLM_SETUP.md           # Local LLM configuration guide
|-- LOCAL_LLM_CHANGES.md         # Local LLM implementation changes
`-- README.md                    # Getting started guide
```

---

## Key Architecture Decisions

### 1. Monolithic Backend Container

Despite the modular `src/` structure, everything runs in a single Docker container:
- **API Server** (FastAPI on port 8000) — `src/routes/main.py`
- **Worker** (PyGhidra wrapper on port 8001) — `src/services/worker/main.py` (subprocess)
- **MCP Server** (Protocol bridge, internal) — `src/services/mcp_server/tools.py`
- **Agent** (Subprocess spawned per-job by orchestrator) — `src/services/agent/runner.py`
- **Ghidra 12.1** (Full installation at `/opt/ghidra`)

**Why?** Single-host deployment simplicity. PyGhidra requires Ghidra installation in the same filesystem. Worker and Agent run as subprocesses of the main API server process.

### 2. Modular Source Organization

The `src/` structure follows industry best practices:

- **`config/`** — Centralized configuration with environment variable parsing
- **`models/`** — Data structures and API schemas (Pydantic models)
- **`routes/`** — HTTP endpoints and request handling
- **`services/`** — Business logic separated by domain (agent, worker, MCP)
- **`middleware/`** — Cross-cutting concerns (security, logging)
- **`scripts/`** — Ghidra analysis scripts (whitelisted execution only)

### 3. File-Based State Management

No database or Redis. All state is file-based:

```
/app/data/jobs/{job_id}/
|-- job.json              # Job metadata (status, progress, intensity, created_at, completed_at)
|-- job_meta.json         # Intensity and analysis config (legacy; intensity now in job.json)
|-- input/{filename}      # Uploaded binary
|-- ghidra_project/       # PyGhidra database files (.gpr, .rep)
|-- artifacts/            # Analysis outputs
|   |-- metadata.json     # Binary metadata from Ghidra analysis
|   |-- notebook.json     # Agent findings notebook
|   |-- metrics.json      # Tool usage and analysis metrics
|   `-- hook_report.json  # GB-23 hook execution report
|-- batch/                # Per-binary subdirs (batch jobs only, GB-22)
|-- logs/job.log          # Agent execution logs (append-only)
`-- report/
    |-- report.md         # Generated markdown report
    `-- report.docx       # Styled Word document (generated on download)
```

**Why?** Avoids database operational overhead — no schema migrations, connection pools, or extra services to run. Trade-off: no cross-host job sharing and no transactional guarantees on concurrent writes; acceptable for single-host deployments.

### 4. Import Strategy

Python imports use two patterns depending on context:

**Standard modules** (loaded by the API server process) use `src.*` absolute imports:
```python
# In routes/, config/, models/, middleware/
from src.models.models import Job, JobStatus
from src.routes.orchestrator import JobOrchestrator
from src.config.api_config import DATA_DIR
```

**Subprocess entry points** (`worker/main.py`, `agent/runner.py`) use bare sibling imports for their immediate neighbors, then `src.*` for everything else:
```python
# In worker/main.py — bare import (Python adds script dir to sys.path)
from control_plane import app

# In agent/runner.py — src.* imports (PYTHONPATH=/app)
from src.services.agent.planner import AnalysisPlanner
```

The Dockerfile sets `PYTHONPATH=/app` to enable `src.*` imports across all contexts.

### 5. Frontend Best Practices

React SPA following Vite conventions:
- **`components/`** — UI elements (JobDetail, JobsList, UploadView, ReportViewer)
- **`services/`** — API client with type-safe methods
- **`types/`** — TypeScript interfaces
- **`utils/`** — Helper functions

---

## Component Interaction Flow

```
User -> WebUI (port 3000, Nginx)
  |
API Server (port 8000) [FastAPI, src/routes/main.py]
  |
  |-- on startup: spawns Worker subprocess (port 8001)
  |
Orchestrator [src/routes/orchestrator.py]
  |
  |-- 1. Calls Worker API to import binary into Ghidra
  |-- 2. Calls Worker API to run initial analysis
  |-- 3. Spawns Agent subprocess:
  |
  Agent [src/services/agent/runner.py -> llm_agent.py]
    |
    |-- LLM API call (tool_use response)
    |-- execute_tool()
    |     |
    |   MCP Tools [src/services/mcp_server/tools.py]
    |     |
    |   Worker API (port 8001) [src/services/worker/control_plane.py]
    |     |
    |   ghidra_runner.py -> PyGhidra -> Ghidra Script
    |
    |-- (loop: up to 50 iterations, 100 tool calls, 600s timeout)
    |-- Agent writes logs to /app/data/jobs/{id}/logs/job.log
    |-- API polls log file, streams to frontend via SSE
    |
  Report generated -> /app/data/jobs/{id}/report/report.md
    |
  DOCX export (on download) -> /app/data/jobs/{id}/report/report.docx

--- Multi-Agent Path (GB-21, --multi-agent flag) ---

  Orchestrator spawns runner.py with --multi-agent:
    |
    MultiAgentOrchestrator [src/services/agent/multi_agent.py]
      |
      |-- 1. Triage Agent (15% budget): entropy, imports, MITRE, IOCs
      |-- 2. Security Auditor (35% budget): crypto, network, anti-analysis, C2
      |-- 3. Code Analyst (50% budget): decompilation, renaming, structures
      |
      All agents share same Ghidra project (sequential access)
      Findings written to shared notebook with [TRIAGE]/[SECURITY]/[CODE] prefix
      Conversations merged for unified report

--- Batch Processing Path (GB-22, POST /api/upload/batch) ---

  Orchestrator calls process_batch_job():
    |
    BatchProcessor [src/services/worker/batch_processor.py]
      |
      |-- Discovers binaries in input/ dir
      |-- Processes each sequentially with isolated Ghidra projects
      |-- Per-binary subdirs under batch/ for artifacts
      |-- Batch summary saved to batch/batch_summary.json
```

---

## Subprocess Architecture

The main API server spawns two subprocesses:

**Worker** (started at API boot, runs for container lifetime):
```python
# src/routes/main.py:71
subprocess.Popen(["python3", "/app/src/services/worker/main.py"], ...)
```

**Agent** (started per-job, runs until analysis complete or timeout):
```python
# src/routes/orchestrator.py:161-188
subprocess.run(
    ["python3", "/app/src/services/agent/runner.py",
     "--job-id", job_id, "--data-dir", str(DATA_DIR),
     "--metadata-file", metadata_path, "--auto-mode"],
    timeout=600, ...
)
```

**Critical:** These paths are hardcoded absolute paths inside the container. If the source tree is restructured, these must be updated. See DEVELOPMENT.md Gotcha #9.

---

## Ghidra Scripts

36 whitelisted scripts in `backend/src/scripts/ghidra_scripts/`:

| Script | Purpose | Source |
|--------|---------|--------|
| `analyze.py` | Run Ghidra auto-analysis on imported binary | Original |
| `list_functions.py` | List all functions with addresses | Original |
| `decompile.py` | Decompile a specific function to C (with GB-1 decompiler config) | Original + GB-1 |
| `rename.py` | Rename a function in the Ghidra project | Original |
| `get_strings.py` | Extract string references | Original |
| `get_imports_exports.py` | List imported/exported symbols | Original |
| `get_xrefs.py` | Get cross-references with R/W/* classification (GB-8) | Original + GB-8 |
| `get_call_graph.py` | Get function call graph with depth, thunk resolution (GB-5) | Original + GB-5 |
| `get_entropy.py` | Calculate section entropy (packing detection) | Original |
| `get_function_signature.py` | Get function signature and parameters | Original |
| `list_segments.py` | List memory segments | Original |
| `list_namespaces.py` | List namespaces | Original |
| `list_data_types.py` | List data types in the program | Original |
| `search_functions.py` | Search functions by pattern | Original |
| `set_comment.py` | Set decompiler comment at address | Original |
| `apply_data_type.py` | Apply data type to variable/parameter | Original |
| `identify_libraries.py` | Identify linked libraries | Original |
| `disassemble.py` | Get assembly for a function | Original |
| `export_xml.py` | Export Ghidra XML | Original |
| `export_annotations.py` | Export human-readable annotated code | Original |
| `export_binary_package.py` | Export full Ghidra project as ZIP | Original |
| `auto_create_structure.py` | Auto-create struct from pointer offset patterns | GB-2 |
| `get_variable_slice.py` | Forward/backward data flow slicing | GB-3 |
| `analyze_basic_blocks.py` | Basic block and CFG analysis | GB-4 |
| `detect_switch.py` | Switch statement detection (jump table vs binary search) | GB-6 |
| `detect_arrays.py` | Array detection from scaling operations | GB-9 |
| `analyze_cpp_classes.py` | C++ vftable/RTTI class hierarchy analysis | GB-10 |
| `set_function_attributes.py` | Set function attributes (noreturn, varargs, etc.) | GB-12 |
| `set_repeatable_comment.py` | Set repeatable comments (propagate to xref sites) | GB-13 |
| `set_equate.py` | Apply named constants (equates) to operands | GB-14 |
| `convert_code_data.py` | Code/data boundary repair | GB-15 |
| `detect_loops.py` | Loop detection via CFG back-edge analysis | GB-16 |
| `find_desync_errors.py` | Disassembly desynchronization detection | GB-17 |
| `resolve_computed_jump.py` | Emulation-based computed jump resolution | GB-18 |
| `emulate_deobfuscation.py` | Emulation-based static deobfuscation | GB-19 |
| `reconstruct_imports.py` | Import table reconstruction for packed binaries | GB-20 |

Scripts are copied at build time (Dockerfile line 42) to `/app/src/services/worker/scripts/` where `ghidra_runner.py` resolves them via `Path(__file__).parent / "scripts"`.

40 MCP tools are exposed to the LLM agent (tool definitions in `llm_agent.py`).

---

## Running the Application

### Production

```bash
cd GARE/docker
docker compose up --build
```

### Development

There is no separate hot-reload compose file — rebuild after backend code changes (`docker compose up -d --build backend`). Frontend changes require a rebuild of the webui image as well, or run `npm run dev` against the running backend.

**Access Points:**
- Web UI: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Worker: http://localhost:8001 (internal)

---

## Configuration

All configuration via `GARE/config/.env`:

```bash
# LLM Configuration
LLM_PROVIDER=anthropic           # Options: anthropic, openai
API_KEY=your-api-key-here        # Required
BASE_URL=                        # Optional: for local LLM servers
MODEL_NAME=YOUR_MODEL_IDENTIFIER  # Required — provider-specific model ID

# Agent Configuration
MAX_TOOL_CALLS=100               # Max Ghidra tool calls per analysis
AGENT_TIMEOUT=300                # Agent timeout in seconds

# Service URLs
WORKER_URL=http://localhost:8001 # Worker is inside same container

# Storage
DATA_DIR=/app/data
MAX_UPLOAD_SIZE_MB=100

# Script Hooks (GB-23)
DISABLE_HOOKS=false               # Disable pre/post script hooks

# Logging
LOG_LEVEL=INFO
```

For local LLM configuration, see `LOCAL_LLM_SETUP.md` in GARE/ root.

---

## Security Model

- **Path Validation**: `middleware/security.py` prevents path traversal via `safe_job_path()`
- **Filename Sanitization**: `middleware/security.py` removes `..`, hidden files, special characters
- **Worker Security**: `middleware/worker_security.py` provides worker-specific validation
- **Script Whitelist**: Only 36 approved Ghidra scripts can execute (`ghidra_runner.py:ALLOWED_SCRIPTS`)
- **Argument Sanitization**: Script arguments cleaned before execution (512 char max, character whitelist)
- **NO Authentication**: Educational/demonstration use only

See `MISC/research_docs/SECURITY_ANALYSIS.md` for 15 documented security findings.

---

## Migration Notes

### From Old Structure (pre 2026-02-02)

Files were reorganized from:
```
backend/
|-- api/         -> src/routes/ + src/config/
|-- agent/       -> src/services/agent/
|-- worker/      -> src/services/worker/
|-- mcp_server/  -> src/services/mcp_server/
`-- ghidra_scripts/ -> src/scripts/ghidra_scripts/

webui/           -> frontend/
```

### Breaking Changes from Reorg

1. All Python imports updated to `src.*` pattern
2. Docker Compose context paths changed (`../backend` instead of `./backend`)
3. Environment variables now in `config/.env` (referenced by docker-compose)
4. Dockerfile sets `PYTHONPATH=/app` for imports to work
5. Subprocess paths changed to `/app/src/services/...` (fixed 2026-02-05)

---

## Testing

Currently **manual testing only**. No automated test suite exists.

**Smoke Test:**
```bash
# Upload a binary
curl -X POST http://localhost:8000/api/upload -F "file=@test_binary"

# Check job status
curl http://localhost:8000/api/jobs/{job_id}

# Stream logs
curl http://localhost:8000/api/jobs/{job_id}/logs/stream
```

---

## Documentation

| File | Location | Description |
|------|----------|-------------|
| README.md | `GARE/` | Quick start guide |
| DEVELOPMENT.md | `GARE/docs/` | AI assistant and developer guidance |
| ARCHITECTURE.md | `GARE/docs/` | This file |
| CHANGELOG.md | `GARE/docs/` | Version history |
| GHIDRA_BOOK_REFERENCE.md | `GARE/docs/` | Book-informed capabilities (GB-1 to GB-23) |
| LOCAL_LLM_SETUP.md | `GARE/` | Local LLM configuration guide |
| LOCAL_LLM_CHANGES.md | `GARE/` | Local LLM implementation details |
| SECURITY_ANALYSIS.md | `MISC/research_docs/` | 15 security findings |
| Capstone docs | `MISC/capstone_proposal/` | Academic capstone materials |

---

## Version

**Current:** 1.0.0 — Initial Release (2026-05-20)
**LLM Support:** Anthropic API + OpenAI-compatible local LLMs (model identifier provided by operator via `MODEL_NAME`)
**Ghidra:** 12.1
**Python:** 3.11
**Node:** 18+
