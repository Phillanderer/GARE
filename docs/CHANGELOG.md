# Changelog

All notable changes to the Ghidra Agentic RE Pipeline project are documented here.

**Format:** This changelog follows the structure and style of DEVELOPMENT.md, documenting only successful, production-ready changes. Failed experiments and reverted changes are not logged.

**Versioning:** Semantic versioning. v1.0.0 is the initial public release.

---

## [1.0.0] - 2026-05-20 - Initial Release

### Changed — Ghidra Upgrade 12.0 → 12.1 (2026-05-20)

- **Reason:** NSA released Ghidra 12.1 on 2026-05-13 with security fixes, improved bitfield decompilation, AARCH64/ARM/X86 processor-specification fixes, and reworked Objective-C analyzers.
- **What's better for GARE:**
  - Decompiler now recovers and displays bitfield names in structured types — cleaner C output for the LLM to consume on protocol parsers, packed structs, kernel/driver code.
  - Many missing/extension instructions added to X86/AARCH64/ARM since 12.0, plus numerous processor-spec bugs fixed — direct accuracy improvement on the most common architectures.
  - Mach-O `_objc_msgSend$` stubs now resolve to actual target methods (Apple-binary analysis).
  - RMI serialization filters tightened (not in GARE's threat surface — no Ghidra Server — but future-proofing).
- **Backward compatibility:** 12.1 reads 12.0 project data. Programs analyzed in 12.1 are not readable by older Ghidra. GARE re-imports per job, so this is a non-issue.
- **Compatibility verified:**
  - JDK 21 already in base image (`eclipse-temurin:21-jdk-jammy`) — 12.1 minimum is JDK 21 ✓
  - Python 3.11 in image — 12.1 requires 3.9–3.14 ✓
  - PyGhidra 3.1.0 (installed via `requirements.txt: pyghidra>=3.0.0`) works with Ghidra 12.x — confirmed by successful import + analysis of `/usr/bin/whoami` (function_count=161, valid metadata).
  - GARE uses PyGhidra (CPython + JPype), not Jython, so 12.1's "Jython moved to optional extension" change does not affect us.
- **Files:** `backend/Dockerfile` (version + build-date ARGs parameterized for future bumps), `config/.env`, `config/.env.example`, `README.md`, `start_gare.sh`, `start_gare.bat`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`.

### Fixed — Silent LLM Failure Marks Jobs Completed (2026-05-20)

- **Cause:** `llm_agent.py:run_autonomous_analysis()` caught every `Exception` raised by `client.messages.create()`, logged it via Python's logger (visible only at DEBUG), then `break`'d out of the iteration loop. `runner.py` continued past the broken loop, wrote a near-empty `report.md`, and exited 0. The orchestrator saw `returncode == 0` and marked the job `COMPLETED` with 0 tool calls — concealing auth failures, network errors, rate limits, and any other transient or fatal LLM API error.
- **Fix:**
  - `llm_agent.py` — Track caught exception in `self.error`, append to job log via `_log_to_job(f"[ERROR] ...")` and `[FAILED]` summary, return the error in the findings dict.
  - `multi_agent.py` — Same change in the per-persona inner loop. New top-level aggregation: if every persona failed, set `combined_results["error"]` so runner sees it.
  - `runner.py:main()` — After report.md is written, check `findings.get("error")` and `sys.exit(1)` with the error printed to stderr. Report is still saved so users can inspect partial output.
  - `orchestrator.py:_run_agent()` — Return signature changed from `bool` to `(bool, Optional[str])`. On non-zero exit, parse the agent's stderr for the `ERROR:` line and propagate the real reason. `process_job()` raises with that reason, which becomes the job's `error_message`.
- **Result:** Jobs that hit an LLM error now end in `failed` status with a specific `error_message` (e.g., `"Analysis failed: APIConnectionError: Connection error."`) instead of `completed` with empty findings. Verified end-to-end by uploading with the `.env.example` placeholder key.
- **Files:** `backend/src/services/agent/llm_agent.py`, `backend/src/services/agent/multi_agent.py`, `backend/src/services/agent/runner.py`, `backend/src/routes/orchestrator.py`

### Added — Ghidra Book Enhancements (GB-1 through GB-23)

All 23 enhancements from *The Ghidra Book* (Eagle & Nance, 2020) implemented on 2026-02-10. See `docs/GHIDRA_BOOK_REFERENCE.md` for detailed book-to-code mappings.

**Priority 1 — High Impact (GB-1 to GB-7):**
- **GB-1: Decompiler Configuration** — Eliminate unreachable code and simplify predication in `decompile.py`
- **GB-2: Auto Structure Creation** — New `auto_create_structure.py` script and MCP tool for detecting pointer offset patterns
- **GB-3: Variable Slicing** — New `get_variable_slice.py` for forward/backward data flow analysis
- **GB-4: Basic Block / CFG Analysis** — New `analyze_basic_blocks.py` with loop detection, edge classification
- **GB-5: Enhanced Call Graph** — Configurable depth, thunk resolution, cycle detection in `get_call_graph.py`
- **GB-6: Switch Detection** — New `detect_switch.py` identifying jump table vs. binary search implementations
- **GB-7: Compiler Variation Prompt** — Added `COMPILER_VARIATION_REFERENCE` to agent system prompt in `prompts.py`

**Priority 2 — Significant Enhancement (GB-8 to GB-16):**
- **GB-8: Xref Type Classification** — R/W/* classification added to `get_xrefs.py`
- **GB-9: Array Detection** — New `detect_arrays.py` identifying scaling operation patterns
- **GB-10: C++ vftable/RTTI Analysis** — New `analyze_cpp_classes.py` for class hierarchy recovery
- **GB-11: Headless Optimization** — New `analysis_config.py` with intensity-based timeout/CPU controls
- **GB-12: Function Attributes** — New `set_function_attributes.py` for noreturn, varargs, calling convention
- **GB-13: Repeatable Comments** — New `set_repeatable_comment.py` propagating to all xref sources
- **GB-14: Named Constants (Equates)** — New `set_equate.py` applying named constants to operands
- **GB-15: Code/Data Boundary Repair** — New `convert_code_data.py` for misclassified region fixes
- **GB-16: Loop Detection** — New `detect_loops.py` via CFG back-edge analysis with nesting depth

**Priority 3 — Specialized Capabilities (GB-17 to GB-23):**
- **GB-17: Desync Detection** — New `find_desync_errors.py` detecting disassembly desynchronization
- **GB-18: Computed Jump Resolution** — New `resolve_computed_jump.py` using p-code emulation
- **GB-19: Emulation Deobfuscation** — New `emulate_deobfuscation.py` for static unpacking via EmulatorHelper
- **GB-20: Import Reconstruction** — New `reconstruct_imports.py` for packed binaries with hash-based API resolution
- **GB-21: Multi-Agent Analysis** — New `multi_agent.py` with triage/security/code personas, shared notebook
  - Files: `agent/multi_agent.py`, `agent/runner.py`, `routes/orchestrator.py`, `routes/main.py`
- **GB-22: Batch Processing** — New `batch_processor.py` for multi-binary jobs via `POST /api/upload/batch`
  - Files: `worker/batch_processor.py`, `routes/orchestrator.py`, `routes/main.py`
- **GB-23: Pre/Post Script Hooks** — New `script_hooks.py` with 6 lifecycle points, `DISABLE_HOOKS` env var
  - Files: `worker/script_hooks.py`, `worker/ghidra_runner.py`

**New Ghidra Scripts (15):** `auto_create_structure.py`, `get_variable_slice.py`, `analyze_basic_blocks.py`, `detect_switch.py`, `detect_arrays.py`, `analyze_cpp_classes.py`, `set_function_attributes.py`, `set_repeatable_comment.py`, `set_equate.py`, `convert_code_data.py`, `detect_loops.py`, `find_desync_errors.py`, `resolve_computed_jump.py`, `emulate_deobfuscation.py`, `reconstruct_imports.py`

**New Modules (4):** `agent/multi_agent.py`, `agent/metrics_collector.py`, `worker/batch_processor.py`, `worker/script_hooks.py`, `worker/analysis_config.py`

**Modified Files:** `ghidra_runner.py` (ALLOWED_SCRIPTS 21->36, hook integration), `llm_agent.py` (18 new tool definitions, metrics), `runner.py` (--multi-agent flag, metrics save), `control_plane.py` (new endpoints), `tools.py` (new tool methods), `prompts.py` (compiler variation ref), `main.py` (batch upload, metrics endpoint), `orchestrator.py` (batch processing)

### Added — Analysis Metrics (2026-02-10)
- **MetricsCollector** — Records tool usage, GB tool utilization %, error rate, findings per tool call
  - New file: `backend/src/services/agent/metrics_collector.py`
  - Integrated in `llm_agent.py:execute_tool()` for automatic tracking
  - Saves to `artifacts/metrics.json` after analysis
  - Report includes "## Analysis Metrics" table
- **Metrics API** — `GET /api/jobs/{job_id}/metrics` returns metrics JSON

### Added — Job Runtime & Intensity Tracking (2026-02-10)
- **Backend: `completed_at` field** — Job model tracks completion timestamp
  - `orchestrator.py:update_job_status()` sets `completed_at = utc_now()` on terminal states (COMPLETED, FAILED, CANCELED)
  - `orchestrator.py:get_job()` normalizes naive `completed_at` timestamps to UTC-aware when loading from disk
- **Backend: `intensity` field** — Job model tracks analysis method (quick/standard/deep)
  - `orchestrator.py:create_job()` sets `intensity` on the Job object at creation
  - `orchestrator.py:get_job()` backfills `intensity` from `job_meta.json` for older jobs
- Files modified: `backend/src/models/models.py`, `backend/src/routes/orchestrator.py`, `frontend/src/types/index.ts`

### Changed — WebUI Layout Improvements (2026-02-10)
- **App header centered** — "Ghidra Agentic RE Pipeline" title and "Upload"/"Jobs" nav links centered
  - File: `frontend/src/App.tsx`
- **Upload page centered** — "Upload Binary for Analysis" heading and "Analysis Intensity" label centered
  - File: `frontend/src/components/UploadView.tsx`
- **Job detail two-column layout** — Status card on left, download buttons stacked vertically on right
  - New `statusAndActions` flex wrapper around status card and actions
  - Status card uses `flex: 1` for left column, actions stack with `flexDirection: column`
  - Status row labels and values use `gap: 0.5rem` instead of `space-between` for tighter spacing
  - File: `frontend/src/components/JobDetail.tsx`
- **Jobs list bold labels** — Parameter names (Job ID, SHA256, Created, Method, Runtime) bolded with `<strong>` tags
  - Method displayed as plain text (removed color-coded badge)
  - Runtime displayed on its own line, conditional on `completed_at`
  - File: `frontend/src/components/JobsList.tsx`

### Documentation
- **Thesis Reference Document** - Created `docs/THESIS_REFERENCE.md` tracking workflow changes influenced by Shrivastava (2023) thesis (2026-02-10)
  - Maps 4 workflow changes (WF-1 through WF-4) to specific thesis chapters and GARE file locations
  - Covers: `get_function_signature.py` tool, calling convention reference in agent prompt, pointer tracing instructions, MCP tool registration
  - Includes concept mapping table, unmeasured efficiency metrics, and future work informed by thesis
  - Reference: Rashmi Shrivastava, *Static Analysis of Stripped Binary Executables to Find Function Parameters, Local Variables and Parameters Used as Pointers in Intel 32-bit and 64-bit Architectures*, M.S. Thesis, University of Idaho, May 2023
- **Ghidra Book Reference Document** - Created `docs/GHIDRA_BOOK_REFERENCE.md` tracking capabilities influenced by Eagle & Nance (2020) (2026-02-10)
  - Maps 14 existing GARE capabilities (EC-1 through EC-14) to specific book chapters
  - Defines 23 planned enhancements (GB-1 through GB-23) across 3 priority tiers
  - Priority 1 (7 items): Decompiler config, auto structures, variable slicing, CFG analysis, enhanced call graph, switch detection, compiler variation prompt
  - Priority 2 (8 items): Xref classification, array detection, C++ vftable/RTTI, headless optimization, function attributes, repeatable comments, named constants, code/data repair, loop detection
  - Priority 3 (7 items): Desync detection, computed jump resolution, emulation deobfuscation, import reconstruction, multi-agent Ghidra Server, batch processing, pre/post script hooks
  - Includes implementation tracking table with status, dates, and priority for incremental adoption
  - Reference: Chris Eagle and Kara Nance, *The Ghidra Book: The Definitive Guide*, No Starch Press, 2020

### Added
- **DOCX Report Export** - Professional Word document download for analysis reports (2026-02-10)
  - New file: `backend/src/services/agent/docx_exporter.py` — Full markdown-to-DOCX converter
  - Styled with blue Calibri headings, Consolas code blocks with gray shading, formatted tables (blue headers, alternating row colors), bullet/numbered lists, blockquotes
  - New endpoint: `GET /api/jobs/{id}/report/docx` — Generates and serves .docx on-demand from `report.md`
  - Frontend button updated: "Download Analysis Report (DOCX)" replaces old "(MD)" button
  - Output filename: `GARE_Report_{binary}_{job_suffix}.docx`
  - Dependency added: `python-docx==1.1.2` in `requirements.txt`
  - Files modified: `backend/src/routes/main.py`, `frontend/src/services/api.ts`, `frontend/src/components/JobDetail.tsx`

### Fixed
- **Datetime Comparison Crash in Job Listing** - Fixed `list_jobs()` crash from mixed naive/aware timestamps (2026-02-10)
  - Error: `can't compare offset-naive and offset-aware datetimes` on `GET /api/jobs`
  - Cause: After introducing `timezone.py` (`utc_now()` returns UTC-aware), older jobs on disk had naive `created_at` timestamps. The `sorted()` call in `list_jobs()` couldn't compare them.
  - Fix: `orchestrator.py:get_job()` now normalizes naive datetimes to UTC-aware when loading from disk
  - File: `backend/src/routes/orchestrator.py:307`

- **Broken Subprocess Paths** - Fixed 3 hardcoded paths broken by 2026-02-02 reorg (2026-02-05)
  - Worker startup: `/app/worker/main.py` -> `/app/src/services/worker/main.py` (`backend/src/routes/main.py:71`)
  - Agent runner: `/app/agent/runner.py` -> `/app/src/services/agent/runner.py` (`backend/src/routes/orchestrator.py:163`)
  - Ghidra scripts copy: `/app/worker/scripts/` -> `/app/src/services/worker/scripts/` (`backend/Dockerfile:42`)

- **Exposed API Key** - Scrubbed real Anthropic key from `config/.env` (2026-02-05)

- **Stale Configuration** - Cleaned up .env files (2026-02-05)
  - Removed stale multi-service URLs (Redis, separate MCP/worker) from `config/.env`
  - Fixed Ghidra version mismatch in `.env.example` (11.0.1 -> 12.0)
  - Removed deprecated `version: '3.8'` from `docker-compose.yml`

### Changed
- **DEVELOPMENT.md Rewrite** - Full audit and correction of development guide (2026-02-05)
  - Fixed 20+ file path references to match post-reorg `backend/src/` structure
  - Fixed agent subprocess code example (path, args, line numbers)
  - Fixed tool definition line range (47-152 -> 67-172)
  - Fixed system prompt line range (211-229 -> 231-249)
  - Updated ALLOWED_SCRIPTS to 14 (was missing `export_binary_package.py`)
  - Documented dual report paths (LLM-driven factual vs legacy structured format)
  - Removed 12 references to documentation files that don't exist in MAIN/
  - Added subprocess path sensitivity gotcha (#9)
  - Added project structure tree with accurate directory layout
  - Updated version info with full change history
  - Root-level `DEVELOPMENT.md` now redirects to `MAIN/docs/DEVELOPMENT.md`

- **README.md** - Written from scratch (was empty) (2026-02-05)

- **ARCHITECTURE.md Rewrite** - Full audit and correction of architecture doc (2026-02-05)
  - Expanded directory tree with every file in backend/src/ (was missing worker_config.py, worker_security.py, planner.py, prompts.py, pyghidra_wrapper.py, worker/security.py, mcp_server/config.py, mcp_server/server.py)
  - Added backend/scripts/ utility shell scripts to tree
  - Documented subprocess architecture (worker Popen + agent run) with exact code paths
  - Added Ghidra scripts table (14 scripts with purposes)
  - Documented dual import strategy (src.* for modules, bare for subprocess entry points)
  - Fixed configuration section (removed exposed key pattern, added LLM_PROVIDER/BASE_URL)
  - Added WARNING about broken docker-compose.dev.yml volume mounts
  - Added component interaction flow with numbered steps
  - Updated documentation table with actual file locations
  - Noted docker-compose.dev.yml as known issue from reorg

### Added
- **Local LLM Support** - OpenAI-compatible local model support (2026-02-02)
  - Added `LLM_PROVIDER` configuration (anthropic or openai)
  - Added `BASE_URL` configuration for local LLM servers
  - Modified `backend/src/services/agent/runner.py` - Provider selection and custom base_url
  - Modified `backend/src/services/agent/llm_agent.py` - Dynamic client initialization
  - Supports gpt-oss 120b and other local models via OpenAI-compatible endpoints
  - Backward compatible: Existing Anthropic configurations work unchanged
  - Documentation: `LOCAL_LLM_SETUP.md` and `LOCAL_LLM_CHANGES.md`

- **Smart Log Auto-Scroll** - Intelligent auto-scroll with user control (2026-01-23)
  - Auto-scrolls ONLY during active analysis (not when completed)
  - Detects when user manually scrolls up and respects their position
  - Resumes auto-scroll when user scrolls back to bottom
  - 50px threshold prevents false positives
  - Files: `webui/src/components/JobDetail.tsx`
  - Documentation: `AUTOSCROLL_FIX.md`

- **Annotation Export Feature** - Human-readable export of Ghidra annotations (2026-01-23)
  - Added `backend/ghidra_scripts/export_annotations.py` - Exports renamed functions with decompiled code
  - Added `/api/jobs/{job_id}/download/annotations` endpoint - Downloads text file with all annotations
  - Added `/jobs/{job_id}/export_annotations` worker endpoint
  - Exports include: renamed function names, addresses, decompiled C code, comments, and summary statistics
  - Example: 4,623 lines covering 232 renamed functions from 386 total (ls binary)
  - File format: Plain text, searchable, shareable without Ghidra
  - Alternative to Ghidra project ZIP for viewing agent's findings

### Fixed
- **Ghidra Project Persistence After Worker Restart** - Runner detects existing projects (2026-01-23)
  - Fixed `backend/worker/ghidra_runner.py:__init__` to detect existing `.gpr` files
  - Automatically sets `program_imported = True` when project exists
  - Finds binary filename from `input/` directory for existing projects
  - Allows export tools to run after worker restarts

### Changed
- **Removed All Emojis from Logs** - Professional ASCII-only log output (2026-01-23)
  - Replaced [*] with [ITERATION N/50]
  - Replaced [*] with [ANALYSIS]
  - Replaced [*] with [TOOL #N]
  - Replaced [*][*], [*], [*], [OK], [*][*], [*] with ASCII equivalents
  - File: `backend/agent/llm_agent.py` (9 locations)

- **Factual Report Format** - Reports now show only factual findings (2026-01-23)
  - Removed conversational "I'll help you..." text
  - Report shows statistics and renamed functions only
  - No more self-aware commentary from LLM
  - File: `backend/agent/runner.py`

- **Improved Download Button Labels** - Clearer labeling of download options (2026-01-23)
  - "Download Analysis Report (MD)" - Markdown report
  - "Download Annotated Code (TXT)" - Primary button (green, bold)
  - "Download Ghidra Database (ZIP)" - Secondary button (gray)
  - Users now understand what each download contains
  - Files: `webui/src/components/JobDetail.tsx`, `webui/src/services/api.ts`

- **Path Argument Sanitization** - Allow forward slashes for file paths (2026-01-23)
  - Updated `backend/worker/ghidra_runner.py:sanitize_script_arg()` to allow `/` character
  - Increased max argument length from 256 to 512 characters for full paths
  - Fixes issue where export paths had slashes stripped

### Documentation
- **Fixes Documentation** - Comprehensive guide for January 23 fixes (2026-01-23)
  - Created `FIXES_APPLIED_20260123.md` - Complete documentation of all four fixes
  - Includes before/after examples, testing results, deployment status
  - Documents log auto-scroll, emoji removal, factual reports, better downloads

- **Annotation Export Documentation** - Created guides for new export feature (2026-01-23)
  - Created `ANNOTATION_EXPORT_GUIDE.md` - Usage guide for annotation export feature
  - Created `GHIDRA_PROJECT_LOCKING_ISSUE.md` - Explains HIGH-03 thread safety issue (identified but not fixed)

- **Capstone Documentation Package** - Created comprehensive proposed edits for capstone integration (2026-01-21)
  - Created `capstone_proposal/DRAFT/CAPSTONE_PROPOSED_EDITS.md` (90KB) - Complete integration guide for CHAPTERS_8_9_10_DRAFT into working capstone
  - Created `capstone_proposal/DRAFT/CHANGELOG_v3.0.md` - Changelog entry for Draft v3.0 capstone version
  - Created `capstone_proposal/DRAFT/THREE_STAGE_EVOLUTION_UPDATE.md` - Documentation of three-stage RE evolution framework
  - Documented three-stage evolution: Manual (4-8 hrs) -> Semi-Autonomous MCP (15-20 min) -> Fully Autonomous GARE (<3 min)
  - Integrated Laurie Kirk's GhidraMCP project as Stage 2 semi-autonomous baseline
  - Added measured performance comparisons: 5-7x improvement over semi-autonomous, comparable performance
  - Clarified GARE's modular LLM architecture supporting any locally hosted LLM via MCP abstraction
  - Removed all emojis and non-ASCII characters for professional academic formatting
  - Converted appropriate content to professional paragraph form while maintaining technical clarity
  - All three new chapters (8, 9, 10) provide validation methodology, operational proof, and honest assessment

### Changed
- **Project Structure Cleanup** - Reorganized repository for cleaner development (2026-01-12)
  - Removed duplicate standalone directories (api/, agent/, worker/, mcp_server/)
  - All source code now consolidated under `backend/` directory
  - Moved historical artifacts to `GARBAGE/` folder for user review
  - Cleaned old test outputs, smoke test reports, and build logs
  - Moved test artifacts (TEST_BINARY, GHIDRA_BOOK) to GARBAGE
  - Moved historical documentation to GARBAGE (10 obsolete .md files)
  - Removed IDE/agent metadata directories
  - Created `scripts/cleanup_old_jobs.sh` for removing Docker-owned job data
  - Added `GARBAGE/README.md` with cleanup instructions

### Documentation
- Created CHANGELOG.md to track project changes (2026-01-12)
- Updated DEVELOPMENT.md to reference changelog for historical tracking (2026-01-12)

### Structure (After Cleanup)
```
ghidra-agentic-re-pipeline/
|-- backend/           # All Python backend code
|   |-- agent/        # LLM agent and prompts
|   |-- api/          # FastAPI application
|   |-- ghidra_scripts/  # Ghidra analysis scripts
|   |-- mcp_server/   # MCP protocol server
|   `-- worker/       # PyGhidra worker
|-- webui/            # React frontend
|-- data/             # Runtime job data
|-- docs/             # Architecture documentation
|-- reports/          # Report templates
|-- scripts/          # Utility scripts
|-- GARBAGE/          # Archived files (safe to delete after review)
`-- *.md              # Core documentation files
```

---

## [0.1.0] - Pre-Release Baseline

### Core Features
- **Automated Binary Analysis** - Ghidra + LLM Agent agentic pipeline
- **MCP Tool Integration** - 9 tools for binary analysis (list_functions, decompile_function, rename_function, etc.)
- **Structured Analysis Reports** - Markdown reports with binary metadata, findings, and recommendations
- **Web Interface** - React SPA with SSE log streaming
- **File-based State** - Simple job state management without database
- **Docker Deployment** - 2-container setup (backend + webui)

### Architecture
- Single monolithic backend container containing API, Worker, Agent, MCP Server, and Ghidra 12.0
- PyGhidra integration for Ghidra script execution
- Subprocess-based agent execution model
- File-based logging and job state management

### Security
- Path traversal protection via `security.py:safe_job_path()`
- Filename sanitization via `security.py:sanitize_filename()`
- Whitelisted Ghidra scripts via `ALLOWED_SCRIPTS`
- Argument sanitization for script parameters
- **Note:** No authentication - educational/demonstration use only

### Documentation
- README.md - Getting started and deployment
- DEVELOPMENT.md - Development guidance for AI assistants
- DEV_SETUP.md - Live development workflow with hot reload
- WORKFLOW_OVERVIEW.md - Technical architecture deep-dive
- EXECUTIVE_SUMMARY.md - Project narrative and transformation story
- SECURITY_ANALYSIS.md - 15 documented security findings
- REPORT_FORMAT_FIX.md - Report format specification
- NETWORK_DEPLOYMENT_GUIDE.md - Home lab deployment instructions
- external_agent_sdk.py - SDK for cross-agent integration

---

## Format Guide

### Change Categories
- **Added** - New features, tools, or capabilities
- **Changed** - Modifications to existing functionality
- **Fixed** - Bug fixes and corrections
- **Removed** - Deprecated or deleted features
- **Security** - Security-related changes
- **Documentation** - Documentation updates
- **Performance** - Performance improvements

### Entry Format
```markdown
### Category
- **Feature Name** - Brief description (YYYY-MM-DD)
  - Additional context if needed
  - File references: `path/to/file.py:line`
```

### What to Log
[OK] Successfully applied code changes
[OK] New features that work as intended
[OK] Bug fixes that resolve issues
[OK] Documentation improvements
[OK] Configuration changes
[OK] Architecture modifications

[*] Broken implementations
[*] Reverted changes
[*] Failed experiments
[*] Work-in-progress code
[*] Debug/testing modifications

---

## Reference

**Project Start:** January 2026
**Current Version:** 1.0.0 — Initial Release
**Model:** Operator-configured via `MODEL_NAME` (Anthropic API or OpenAI-compatible)
**Scripts:** 36 whitelisted | **Tools:** 40 MCP | **Enhancements:** 23 GB
**Last Updated:** 2026-02-10
