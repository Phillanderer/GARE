# DEVELOPMENT.md

This file provides guidance to AI development assistants when working with code in this repository.

**Last Updated:** 2026-02-10

---

## Project Structure (Reorganized 2026-02-02, Patched 2026-02-05, 2026-02-09, 2026-02-10)

```
GARE/
  backend/
    src/
      config/           Configuration modules
      models/           Data models (Job, JobStatus)
      routes/           API endpoints (main.py, orchestrator.py)
      services/
        agent/          LLM agent, runner, multi-agent, metrics, report gen, DOCX exporter, prompts
        worker/         PyGhidra wrapper, control plane, ghidra_runner
        mcp_server/     MCP tool bridge (GhidraTools HTTP wrapper)
      middleware/       Security (path traversal, sanitization)
      scripts/
        ghidra_scripts/ 36 Ghidra analysis scripts (whitelisted)
      utils/            Timezone utilities (timezone.py)
    scripts/            Operational scripts (smoke_test, benchmark)
    Dockerfile
    requirements.txt
  frontend/             React web interface
    src/
      components/       JobDetail, JobsList, UploadView, ReportViewer
      services/         API client
      types/            TypeScript definitions
    Dockerfile
  docker/               Docker Compose files
  config/               Environment configuration (.env)
  data/                 Job data, benchmark results
  docs/                 DEVELOPMENT.md, ARCHITECTURE.md, CHANGELOG.md
```

**Import pattern:** All Python imports use `from src.*` (e.g., `from src.services.mcp_server.tools import GhidraTools`). `PYTHONPATH=/app` in Dockerfile enables this. Subprocess scripts (`runner.py`, `worker/main.py`) use bare sibling imports since Python adds the script directory to `sys.path`.

**See ARCHITECTURE.md for complete details.**

---

## Project Overview

**Ghidra Agentic RE Pipeline** - Automated binary reverse engineering system combining Ghidra's static analysis with LLM-driven autonomous reasoning via Model Context Protocol (MCP) tool calling.

**Key Innovation:** Accelerates reverse engineering workflows through fully autonomous analysis (2-10 minutes) via an agentic loop where the LLM makes analytical decisions, calls Ghidra tools, and documents findings automatically.

**Change History:** All successfully applied changes to this project are documented in **CHANGELOG.md**. See that file for version history, feature additions, and modifications.

---

## Architecture

### High-Level Data Flow

```
Upload -> Orchestrator -> Ghidra Worker -> LLM Agent (via MCP) -> Report
                |
           Job State (file-based JSON)
```

### Component Interaction Model

**This is a simple 2-container deployment.** All backend components run in a single monolithic container:

**Container 1: Backend (`gare-backend`)**
- Built from `backend/Dockerfile`
- Contains everything: API, Worker, MCP Server, Agent, Ghidra 12.1
- Single process (`backend/src/routes/main.py`) that orchestrates all components:
  - **API Server** (port 8000) - Accepts uploads via REST, manages job state via file I/O
  - **Worker Control Plane** (port 8001, subprocess) - PyGhidra wrapper, executes Ghidra scripts
  - **MCP Server** (internal) - Protocol bridge between Agent and Worker
  - **Agent** (subprocess) - Spawned via `subprocess.run()` when job starts
  - **Ghidra** - Full installation at `/opt/ghidra`

**Container 2: Frontend (`gare-webui`)**
- React SPA with SSE for log streaming
- Built from `frontend/Dockerfile`
- Nginx serving static files on port 3000
- **Smart auto-scroll** - Logs auto-scroll during analysis, respects manual scrolling
- **Professional UI** - ASCII-only log output, clear download options

**Key Point:** Despite having modular subdirectories (`backend/src/routes/`, `backend/src/services/agent/`, `backend/src/services/worker/`, `backend/src/services/mcp_server/`), these are **NOT separate services**. They're all modules within the single backend container.

### State Management Architecture

**CRITICAL:** No persistent database. All state is file-based:

```
/app/data/jobs/{job_id}/
|-- input/{filename}          # Uploaded binary
|-- ghidra_project/           # PyGhidra project files
|-- logs/job.log              # Agent writes here directly (file append)
|-- report/report.md          # Generated markdown
`-- job.json                  # Job metadata (status, progress)
```

**Job State Machine:**
```
QUEUED -> RUNNING -> ANALYZING_GHIDRA -> AGENT_RUNNING -> REPORT_WRITING -> COMPLETED
                                    |
                                 FAILED
```

**Why file-based?** Avoids database operational overhead — no schema, migrations, or connection pooling. Job state read/written via `orchestrator._save_job_state()`. Single-host model; not suitable for horizontal scale-out without a coordination layer.

---

## Critical System Constraints

### 1. Agent Execution Model

**NOT containerized parallelism.** Agent runs as subprocess within orchestrator:

```python
# backend/src/routes/orchestrator.py
cmd = [
    "python3",
    "/app/src/services/agent/runner.py",
    "--job-id", job_id,
    "--data-dir", str(DATA_DIR),
    "--metadata-file", metadata_path,
    "--auto-mode",
    "--intensity", intensity,
    # Optional: "--multi-agent"  # GB-21: enables triage/security/code personas
]
result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=timeout,  # quick=480, standard=1500, deep=3000
    env=agent_env,
    cwd="/app/src/services/agent"  # CRITICAL: bare imports in runner.py need this
)
```

**Implications:**
- One agent per job (no parallel job processing)
- Timeout kills subprocess (no graceful shutdown)
- Agent logs via file writes (orchestrator polls file for SSE)

### 2. PyGhidra Integration

**PyGhidra runs in Worker process, NOT agent process.** Agent calls Worker HTTP API:

```
Agent -> HTTP -> Worker (port 8001) -> PyGhidra -> Ghidra Scripts
```

**Why?** PyGhidra requires Ghidra installation path and Java classpath setup. The Worker process has this initialized; the agent subprocess communicates over HTTP.

**Script Execution Model:**
```python
# backend/src/services/worker/ghidra_runner.py:17-23
# WHITELISTED scripts only (ALLOWED_SCRIPTS set, 36 total)
# Includes original 21 scripts plus 15 GB-enhancement scripts:
#   auto_create_structure.py, get_variable_slice.py, analyze_basic_blocks.py,
#   detect_switch.py, detect_arrays.py, analyze_cpp_classes.py,
#   set_function_attributes.py, set_repeatable_comment.py, set_equate.py,
#   convert_code_data.py, detect_loops.py, find_desync_errors.py,
#   resolve_computed_jump.py, emulate_deobfuscation.py, reconstruct_imports.py
runner.run_script("decompile.py", function_name)
# -> Executes via PyGhidra API in Ghidra context
```

### 3. Tool Calling Flow

**LLM doesn't call Worker directly.** Flow is:

```
LLM -> LLM API (tool_use block)
    -> Agent (execute_tool)
        -> MCP Server (GhidraTools HTTP wrapper)
            -> Worker API
                -> PyGhidra
```

**Tool definitions in:** `backend/src/services/agent/llm_agent.py` (40 tools as LLM provider tool schemas)

**Tool execution in:** `backend/src/services/mcp_server/tools.py` (HTTP client to Worker)

---

## Development Commands

### Build & Run

```bash
# Full stack (first time takes 5-10 min - downloads Ghidra 12.1)
cd docker && docker compose up --build

# Run detached
cd docker && docker compose up -d

# Stop
cd docker && docker compose down

# View logs
docker logs gare-backend -f
docker logs gare-webui -f

# Restart after code changes
cd docker && docker compose restart backend
```

**Simple 2-container setup:**
- `gare-backend` - Contains API, Worker, Agent, MCP Server, Ghidra
- `gare-webui` - React frontend

### Local Development (Without Docker)

**Backend API:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment
export LLM_PROVIDER=anthropic  # or openai for local LLMs
export API_KEY=your-api-key-here
export BASE_URL=  # Leave blank for cloud APIs
export DATA_DIR=/tmp/ghidra-data
export WORKER_URL=http://localhost:8001

# Run API (from backend/ directory)
python3 -m src.routes.main
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev  # Vite dev server on port 3000
```

**Critical:** Worker requires Ghidra installation. Easiest to run Worker in Docker even during local dev:
```bash
cd docker && docker compose up backend
```

### Testing

**No unit/integration test suite ships with v1.0.** Testing is via scripts:

```bash
# Smoke test (verifies pipeline end-to-end)
cd backend && bash scripts/smoke_test.sh /path/to/binary

# Benchmark single binary (extracts metrics from job.log)
cd backend && bash scripts/benchmark.sh /path/to/binary [quick|standard|deep] [output.csv]

# Benchmark suite (multiple binaries, reproducibility, intensity comparison)
cd backend && bash scripts/benchmark_suite.sh binary1 binary2
cd backend && bash scripts/benchmark_suite.sh --reproducibility binary 5
cd backend && bash scripts/benchmark_suite.sh --intensity-compare binary

# Manual API test
curl -X POST http://localhost:8000/api/upload \
  -F "file=@test_binary" -F "intensity=standard" | jq .

# Monitor job
JOB_ID="job_..."
curl http://localhost:8000/api/jobs/$JOB_ID | jq .

# Stream logs
curl http://localhost:8000/api/jobs/$JOB_ID/logs/stream
```

### Configuration

**All config via `config/.env` file** (NOT environment variables in docker-compose.yml):

**CRITICAL: Docker does NOT strip inline comments from .env files.** Writing `BASE_URL=  # comment` will set `BASE_URL` to `# comment` (the literal string), which will break API calls. Always put comments on their own line.

```bash
# LLM Configuration
# Options for LLM_PROVIDER: anthropic, openai
LLM_PROVIDER=anthropic
API_KEY=your-api-key-here
# For local LLMs, uncomment and set BASE_URL (e.g. http://localhost:8080/v1)
# Leave commented out for cloud APIs
#BASE_URL=
MODEL_NAME=YOUR_MODEL_IDENTIFIER  # Required — provider-specific model ID

# Agent Configuration
AUTO_APPROVE_RENAMES=false
MAX_TOOL_CALLS=100
AGENT_TIMEOUT=300

# Script Hooks (GB-23)
DISABLE_HOOKS=false

# System
DATA_DIR=/app/data
LOG_LEVEL=INFO
```

**Frontend build-time config** (must rebuild after changes):
```bash
# Set in docker-compose.yml environment for webui service
VITE_API_URL=http://localhost:8000
```

### Local LLM Configuration

**GARE supports local LLM models** via OpenAI-compatible APIs:

```bash
# In config/.env for local LLM:
LLM_PROVIDER=openai
API_KEY=local-key
BASE_URL=http://host.docker.internal:8080/v1
MODEL_NAME=your-model-name
```

**Supported providers:**
- `anthropic` - Anthropic API (default, cloud or local proxy)
- `openai` - OpenAI-compatible API (cloud or local server)

**Common local LLM servers:**
- LM Studio: `http://localhost:1234/v1`
- Ollama (OpenAI mode): `http://localhost:11434/v1`
- text-generation-webui: `http://localhost:5000/v1`
- vLLM: `http://localhost:8000/v1`

**Requirements for local models:**
- OpenAI-compatible `/v1/chat/completions` endpoint
- Function/tool calling support (critical)
- 32K+ token context window (recommended)

**See `LOCAL_LLM_SETUP.md` (in GARE/ root) for detailed instructions.**

---

## Code Modification Patterns

### Adding a New MCP Tool

1. **Define Ghidra script** in `backend/src/scripts/ghidra_scripts/my_tool.py`:
   ```python
   # Must accept args from command line
   import sys
   arg1 = sys.argv[1]
   # Use currentProgram global (provided by PyGhidra)
   # Return JSON to stdout
   print(json.dumps({"result": ...}))
   ```

2. **Add to whitelist** in `backend/src/services/worker/ghidra_runner.py`:
   ```python
   ALLOWED_SCRIPTS = {..., "my_tool.py"}
   ```

3. **Add Worker endpoint** in `backend/src/services/worker/control_plane.py`:
   ```python
   @app.get("/jobs/{job_id}/my-operation")
   def my_operation(job_id: str, param: str):
       runner = get_runner(job_id)
       output = runner.run_script("my_tool.py", param)
       return {"result": output}
   ```

4. **Add MCP tool wrapper** in `backend/src/services/mcp_server/tools.py`:
   ```python
   def my_tool(self, param: str) -> Dict:
       response = requests.get(
           f"{self.worker_url}/jobs/{self.job_id}/my-operation",
           params={"param": param}
       )
       return response.json()
   ```

5. **Add tool definition** in `backend/src/services/agent/llm_agent.py` (in `get_tool_definitions()`, lines 67-172):
   ```python
   {
       "name": "my_tool",
       "description": "What this tool does (LLM reads this!)",
       "input_schema": {
           "type": "object",
           "properties": {
               "param": {"type": "string", "description": "..."}
           },
           "required": ["param"]
       }
   }
   ```

6. **Map in agent** - Automatic via `getattr(self.ghidra_tools, tool_name)`

7. **Copy to runtime location** - Dockerfile line 42 copies scripts to `/app/src/services/worker/scripts/` where `ghidra_runner.py` resolves them via `Path(__file__).parent / "scripts"`.

### Modifying Agent Behavior

**System prompt** controls agent strategy: `backend/src/services/agent/llm_agent.py:231-249`

**Key constraints (configurable via intensity level):**
- quick: 15 iterations, 30 tool calls, 480s timeout
- standard: 50 iterations, 100 tool calls, 1500s timeout
- deep: 100 iterations, 250 tool calls, 3000s timeout

**Agent termination:** LLM must respond with "ANALYSIS_COMPLETE" in text block. If not present, agent sends "Continue your analysis" prompt to keep iterating.

### Report Generation

**Two report paths exist depending on agent mode:**

**1. LLM-Driven Path (default, `--auto-mode`):**
- Used when `runner.py` is called with `--auto-mode` flag (the default)
- `generate_llm_report()` in `backend/src/services/agent/runner.py:355-419`
- Produces a **factual summary report** with:
  - Binary metadata table
  - Iteration and tool call statistics
  - List of renamed functions (old_name -> new_name)
  - Raw binary metadata dump
- Pure factual statements, no conversational text

**2. Legacy Path (`--no-llm` flag):**
- Uses `ReportGenerator` class in `backend/src/services/agent/report_generator.py`
- Produces a **structured analysis report** with 8 sections:
  1. Binary Information - Table with binary metadata
  2. TL;DR - Minimum 50-word summary
  3. Analysis Approach - Reconnaissance, memory layout, entry points
  4. Solution Walkthrough - Step-by-step breakdown (6 steps)
  5. Key Functions - Top 10 functions with decompiled C code
  6. Artifacts & Indicators - Categorized imports, notable strings, IOCs
  7. Conclusion - Key takeaways, capability assessment, next steps
  8. Reproducibility - Requirements and steps to reproduce findings

**Report output characteristics (both paths):**
- Pure factual statements about binary characteristics
- Statistics on iterations, tool calls, and functions renamed
- NO self-aware commentary from LLM
- Lists of renamed functions with old_name -> new_name mappings

**3. DOCX Export (`docx_exporter.py`):**
- `backend/src/services/agent/docx_exporter.py` converts any markdown report to a styled Word document
- Generates on-demand via `GET /api/jobs/{id}/report/docx`
- Professional styling: blue Calibri headings with bottom borders, Consolas code blocks with gray shading, styled tables (blue header, alternating row colors), bullet/numbered lists, blockquotes
- Handles all markdown elements: `#` headings, `|` tables, ` ``` ` code fences, `**bold**`, `` `code` ``, `- ` lists, `> ` blockquotes, `---` horizontal rules
- Output filename: `GARE_Report_{binary}_{job_id_suffix}.docx`
- Dependency: `python-docx==1.1.2` (in `requirements.txt`)

### WebUI Features & Behavior

**Smart Auto-Scroll** (`frontend/src/components/JobDetail.tsx:28-57`):
- Auto-scrolls ONLY during active analysis (status: `running`, `queued`, `analyzing_ghidra`, `agent_running`, `report_writing`)
- Detects manual scrolling and respects user position (50px threshold)
- Resumes auto-scroll when user scrolls back to bottom
- Permanently stops when analysis completes (status: `completed`, `failed`, `canceled`)
- Implementation uses React refs and scroll position detection

**Log Output Format** (`backend/src/services/agent/llm_agent.py`):
- **ASCII-only** - No emojis in any log output
- Professional formatting with bracketed labels:
  - `[ITERATION N/50]` - Analysis iteration counter
  - `[ANALYSIS]` - LLM reasoning/analysis text
  - `[TOOL #N]` - Tool call with parameters
  - `  -> Returned N items` - Tool result summary
  - `  -> Renamed: old_name -> new_name` - Function rename operation
  - `  -> ERROR: message` - Tool failure
  - `[COMPLETE]` - Analysis finished
  - `[SUMMARY]` - Final statistics

**Download Options** (three distinct formats):
1. **Download Analysis Report (DOCX)** - Professionally formatted Word document
   - Styled with blue headings, code blocks, tables, and clean typography
   - Suitable for presenting to leadership / chain of command
   - Generated on-demand from `report.md` via `docx_exporter.py`
   - **Endpoint:** `GET /api/jobs/{id}/report/docx`
2. **Download Annotated Code (TXT)** - Primary export (green, bold button)
   - Human-readable text file with decompiled C code
   - Shows renamed functions with addresses and signatures
   - Searchable, shareable without Ghidra installation
   - **Generated by:** `backend/src/scripts/ghidra_scripts/export_annotations.py`
3. **Download Ghidra Database (ZIP)** - Full Ghidra project for opening in Ghidra GUI
   - Secondary option (gray button)
   - Contains .gpr, .rep, and internal database files
   - Only useful if you want to continue analysis in Ghidra GUI

### Performance Considerations

**Bottleneck is LLM API latency.** Observed during 2026-02-09 benchmarking with a frontier-class API model:
- Per-iteration time: **30-60 seconds** (varies by response complexity)
- bbbbloat (36 functions, simple binary): reached 26 iterations / 54 tool calls in ~11 min before timeout
- At standard intensity (50 iterations max), worst case is ~25-50 minutes per binary
- `quick` intensity (15 iterations) may be sufficient for small binaries and benchmarking

**To reduce analysis time:**
1. **Use `quick` intensity** for benchmarking and small binaries (15 iter, ~8-15 min max)
2. **Reduce max_tokens** in LLM call (currently 4096 in `llm_agent.py`) - shorter responses = faster
3. **Simplify system prompt** - agent spends iterations self-correcting and re-analyzing
4. **File-based logging is critical:** Previous HTTP progress tracking caused 2.5x slowdown (removed in current version)

**DO NOT add HTTP calls inside agent loop** - write to file instead.

**Logging best practices:**
- All agent logs are ASCII-only (no emojis, no unicode symbols)
- Use bracketed labels: `[ITERATION]`, `[TOOL #N]`, `[ANALYSIS]`, etc.
- Write directly to job log file, API reads and streams via SSE
- Keep log lines concise and grep-friendly

### Benchmark Scripts

**Single binary benchmark:** `backend/scripts/benchmark.sh`
```bash
# Basic usage
./benchmark.sh /path/to/binary [intensity] [output.csv]

# Examples
./benchmark.sh ./bbbbloat standard results.csv
./benchmark.sh /bin/ls quick
```

Uploads binary, polls until completion, parses job.log for metrics (TTFI, iterations, tool calls, functions decompiled/renamed, coverage %). Calculates speed vs Kirk 15-20 min baseline.

**Multi-binary suite:** `backend/scripts/benchmark_suite.sh`
```bash
# Multiple binaries
./benchmark_suite.sh binary1 binary2 binary3

# Reproducibility test (same binary N times)
./benchmark_suite.sh --reproducibility ./bbbbloat 5

# Intensity comparison (quick/standard/deep)
./benchmark_suite.sh --intensity-compare ./bbbbloat
```

Generates markdown report at `data/benchmark_results/benchmark_YYYYMMDD.md`.

### Multi-Agent Analysis Mode (GB-21)

Activate with `--multi-agent` flag or `multi_agent=true` on the upload API:

```bash
curl -X POST http://localhost:8000/api/upload \
  -F "file=@binary" -F "multi_agent=true" -F "intensity=standard"
```

Three specialized agent personas analyze the binary sequentially:

1. **Triage Agent** (15% of tool budget): Quick classification, entropy check, library ID, MITRE mapping, IOC extraction
2. **Security Auditor** (35% of tool budget): Crypto routines, network ops, anti-analysis, C2 patterns, import reconstruction
3. **Code Analyst** (50% of tool budget): Deep decompilation, function renaming, structure recovery, loop/switch detection

All agents share the same Ghidra project via PyGhidra (sequential access). Findings are written to the shared notebook with `[TRIAGE]`, `[SECURITY]`, `[CODE]` prefixes. Conversations are merged for unified report generation.

**Files:** `backend/src/services/agent/multi_agent.py`, `backend/src/services/agent/runner.py`

### Batch Processing (GB-22)

Upload multiple binaries for sequential analysis in a single job:

```bash
curl -X POST http://localhost:8000/api/upload/batch \
  -F "files=@binary1" -F "files=@binary2" -F "intensity=quick"
```

- `BatchProcessor` class discovers and processes binaries sequentially
- Per-binary subdirectories under `batch/` for isolated Ghidra projects
- Batch summary saved to `batch/batch_summary.json`
- Per-file timeout prevents any single binary from blocking the batch

**Files:** `backend/src/services/worker/batch_processor.py`, `backend/src/routes/main.py`

### Script Hooks (GB-23)

Pre/post script hook architecture with 6 lifecycle points:

| Hook Point | Purpose |
|------------|---------|
| `PRE_IMPORT` | Validate binary (magic bytes, size) |
| `POST_IMPORT` | Configure decompiler options by intensity |
| `PRE_ANALYSIS` | Pre-analysis metadata extraction |
| `POST_ANALYSIS` | Post-analysis artifact tracking |
| `PRE_SCRIPT` | Per-script logging (name, args) |
| `POST_SCRIPT` | Per-script output logging |

Built-in hooks: `hook_validate_binary` (ELF/PE/Mach-O detection), `hook_configure_decompiler` (intensity-aware), `hook_log_script` (execution logging).

Hook report saved to `artifacts/hook_report.json`. Disable globally with `DISABLE_HOOKS=true`.

**Files:** `backend/src/services/worker/script_hooks.py`, `backend/src/services/worker/ghidra_runner.py`

### Analysis Metrics

`MetricsCollector` records per-job tool usage and findings:

- Per-tool call counts (success/failure)
- GB-enhanced tool utilization percentage
- Findings per tool call ratio
- Error rate

Metrics saved to `artifacts/metrics.json` and included in the analysis report under "## Analysis Metrics".

Access via API: `GET /api/jobs/{job_id}/metrics`

**Files:** `backend/src/services/agent/metrics_collector.py`, `backend/src/services/agent/llm_agent.py`

---

## Security Model

**Current state (v1.0):** NO built-in authentication or rate limiting at the API layer. Input validation is in place for filenames, job IDs, file paths, and Ghidra script arguments; further controls (auth, rate limit, request quotas) are operator responsibilities.

**Implemented mitigations:**
1. **Path traversal protection:** `middleware/security.py:safe_job_path()` validates job_id and resolves symlinks
2. **Filename sanitization:** `middleware/security.py:sanitize_filename()` removes `..`, hidden files, special chars
3. **Script whitelist:** `services/worker/ghidra_runner.py:ALLOWED_SCRIPTS` prevents arbitrary script execution (36 whitelisted scripts)
4. **Argument sanitization:** `services/worker/ghidra_runner.py:sanitize_script_arg()` removes shell metacharacters
   - Allows forward slashes for file paths
   - Max argument length: 512 characters
   - Whitelist: alphanumeric, underscore, hyphen, dot, colon, @, forward slash

**For production:** Must add API authentication before network deployment.

---

## Known Quirks & Gotchas

### 1. Single Container, Multiple Processes

Despite the `backend/src/` directory having subdirectories (`routes/`, `services/agent/`, `services/worker/`, `services/mcp_server/`), **everything runs in a single container**. There is no Redis, no separate worker container, no microservices. Just one monolithic backend container running the API server, which spawns the worker and agent as subprocesses.

### 2. Agent Can't Resume

If agent subprocess times out or crashes, there's no resume mechanism. Job is marked failed. Must re-upload binary for new analysis.

### 3. Function Rename Persistence

Renames via `rename_function` tool modify Ghidra project **in place**. There's no undo. Project is saved after each rename.

### 4. Frontend API URL is Build-Time

`VITE_API_URL` is baked into frontend build. Changing the API URL requires rebuilding the webui container:
```bash
cd docker && docker compose build webui && docker compose up webui
```

### 5. Log Streaming Implementation

SSE endpoint (`/api/jobs/{job_id}/logs/stream`) **polls file** every 1 second. Not true streaming. Agent writes to file, API reads file, pushes to SSE.

### 6. Ghidra Download on First Build

Backend Dockerfile downloads Ghidra 12.1 (~500MB) on first build. Cached after that. Build takes 5-10 minutes first time.

### 7. Smart Auto-Scroll Behavior

WebUI logs tab has intelligent auto-scroll (`frontend/src/components/JobDetail.tsx`):
- Only active when job is running (not when completed/failed)
- Detects manual scrolling and pauses auto-scroll
- Resumes when user scrolls back to bottom (50px threshold)
- This is intentional UX - users can review previous logs during analysis without interference

### 8. Three Download Formats

**NOT all downloads are the same:**
- **Report (DOCX)** - Styled Word document with analysis findings, suitable for chain-of-command delivery
- **Annotated Code (TXT)** - Primary export, human-readable decompiled code with renames
- **Ghidra Database (ZIP)** - Full project for Ghidra GUI (not human-readable)

Most users want the **Annotated Code (TXT)** export - it's highlighted as the primary download button (green, bold). The **Report (DOCX)** is the presentable output for leadership.

### 9. Subprocess Path Sensitivity (cwd is CRITICAL)

Subprocess scripts use **bare imports** for sibling modules (e.g., `from llm_agent import LLMAgent` in `runner.py`, `from control_plane import app` in `worker/main.py`). These require `cwd` to be set to the script's directory, otherwise the imports fail silently.

**Both subprocess launches MUST include `cwd`:**
- `backend/src/routes/main.py:70-74` - Worker startup: `cwd="/app/src/services/worker"`
- `backend/src/routes/orchestrator.py:202-209` - Agent runner: `cwd="/app/src/services/agent"`
- `backend/Dockerfile:42` - Ghidra scripts copy destination

If code is restructured, grep for `/app/` patterns AND `subprocess.Popen`/`subprocess.run` to find all hardcoded paths and ensure `cwd` is correct.

### 10. .env Inline Comments Break Everything

Docker does NOT strip inline comments from `.env` files. This:
```
BASE_URL=  # For local LLMs: http://localhost:8080/v1
```
Sets `BASE_URL` to the literal string `# For local LLMs: http://localhost:8080/v1`, which gets passed to the Anthropic client as a `base_url`, causing silent API failures. The agent runs 1 iteration with 0 tool calls and reports success.

**Always put comments on their own line in `.env` files.**

### 11. rename_function Fixed (2026-02-09)

Previously returned `{"error": "name 'ghidra' is not defined"}` due to missing explicit import of `ghidra.program.model.symbol.SourceType` in PyGhidra context (bare `ghidra` package isn't auto-exposed like in Jython). **Fixed** — renames now persist correctly in the Ghidra project.

### 12. Naive vs Aware Datetime Comparison (Fixed 2026-02-10)

After introducing `timezone.py` (`utc_now()` returns aware datetimes), older jobs on disk had naive `created_at` timestamps. The `list_jobs()` sort crashed with `can't compare offset-naive and offset-aware datetimes`. **Fixed** in `orchestrator.py` — naive datetimes are normalized to UTC-aware when loading from disk.

---

## Documentation Structure

### In `docs/`
- **DEVELOPMENT.md** - This file. Development guidance for AI assistants and developers
- **ARCHITECTURE.md** - Technical architecture details
- **CHANGELOG.md** - Version history and successfully applied changes

### In GARE/ root
- **README.md** - Getting started, deployment, quick reference
- **LOCAL_LLM_SETUP.md** - Detailed local LLM configuration guide

**For understanding system behavior, read in order:**
1. This file (DEVELOPMENT.md)
2. `docs/CHANGELOG.md` (recent changes and version history)
3. `backend/src/routes/orchestrator.py` (job lifecycle)
4. `backend/src/services/agent/llm_agent.py` (agentic loop)
5. `backend/src/services/mcp_server/tools.py` (tool bridge)

---

## Version Info

**Current Version:** 1.0.0 — Initial Release (2026-05-20)
**Status:** Released. Production deployments must add auth and rate limiting at the gateway layer (see Security Model section).
**LLM Support:** Anthropic API + OpenAI-compatible local LLMs (model identifier provided by operator via `MODEL_NAME`)
**Python:** 3.11
**Ghidra:** 12.1
**Node:** 18+ (frontend)
**Docker:** Simple 2-container setup (backend + webui)

**Changes (2026-02-10):**
- **GB-1 through GB-23**: All 23 Ghidra Book enhancements implemented (see `docs/GHIDRA_BOOK_REFERENCE.md`)
  - P1 (GB-1 to GB-7): Decompiler config, auto structures, variable slicing, CFG, enhanced call graph, switch detection, compiler variation prompt
  - P2 (GB-8 to GB-16): Xref classification, array detection, C++ vftable/RTTI, headless optimization, function attributes, repeatable comments, named constants, code/data repair, loop detection
  - P3 (GB-17 to GB-23): Desync detection, computed jump resolution, emulation deobfuscation, import reconstruction, multi-agent analysis, batch processing, pre/post script hooks
- **15 new Ghidra scripts** added (36 total, all whitelisted)
- **18 new MCP tools** added (40 total)
- **Multi-agent mode** (GB-21): `--multi-agent` flag activates triage/security/code personas
- **Batch processing** (GB-22): `POST /api/upload/batch` for multi-binary jobs
- **Script hooks** (GB-23): 6 lifecycle points, `DISABLE_HOOKS` env var
- **Analysis metrics**: `MetricsCollector` with GB tool utilization tracking, `GET /api/jobs/{id}/metrics`
- Added DOCX report export: `backend/src/services/agent/docx_exporter.py` converts markdown to professionally styled Word document
- New endpoint: `GET /api/jobs/{id}/report/docx` generates and serves .docx on-demand
- Updated frontend download button: "Download Analysis Report (DOCX)" pointing to `/report/docx`
- Added `python-docx==1.1.2` to `requirements.txt`
- Fixed datetime comparison crash in `orchestrator.py:list_jobs()` — naive timestamps from older jobs normalized to UTC-aware when loading from disk
- Cleaned up 3 orphaned jobs stuck in `agent_running` status
- **Job runtime & intensity tracking**: `completed_at` and `intensity` fields added to Job model, populated by orchestrator, backfilled from `job_meta.json` for older jobs
- **WebUI layout improvements**: Centered app header/nav, centered upload page headings, job detail two-column layout (status left, download buttons stacked right), bold parameter labels in job list, plain-text method display

**Changes (2026-02-09):**
- Fixed worker subprocess crash: added `cwd="/app/src/services/worker"` to Popen call in `main.py`
- Fixed agent subprocess import failure: added `cwd="/app/src/services/agent"` to subprocess.run in `orchestrator.py`
- Fixed .env inline comments poisoning BASE_URL (moved all comments to own lines)
- Increased agent timeouts for Sonnet 4.5 latency: quick=480s, standard=1500s, deep=3000s
- Added `benchmark.sh` script (single binary benchmark with metric extraction from job.log)
- Added `benchmark_suite.sh` script (multi-binary, reproducibility, intensity comparison modes)
- Added intensity parameter support to upload API and agent runner
- Capstone doc: removed all fabricated data, replaced with [BENCHMARK DATA] placeholders
- Identified rename_function PyGhidra issue (returns error but logs success)

**Changes (2026-02-05):**
- Fixed 3 broken subprocess paths from 2026-02-02 reorganization
- Scrubbed exposed API key from config/.env
- Cleaned stale service URLs from .env and .env.example
- Fixed Ghidra version mismatch in .env.example (11.0.1 -> 12.0)
- Removed deprecated version key from docker-compose.yml
- Wrote README.md (was empty)
- Updated DEVELOPMENT.md to match actual codebase

**Changes (2026-02-02):**
- Full project reorganization (backend/src/ structure, frontend/, docker/, config/, docs/)
- All imports converted to `from src.*` pattern
- Added local LLM support (LLM_PROVIDER, BASE_URL, openai-compatible)

**Changes (2026-01-23):**
- Smart auto-scroll in logs (respects user scrolling)
- ASCII-only log output (all emojis removed)
- Factual report format (no conversational text)
- Annotation export (human-readable code with renames)
- Improved download button labels and prioritization
- See `docs/CHANGELOG.md` for details
