#!/bin/bash
# benchmark.sh - Single binary benchmark for GARE pipeline
# Uploads a binary, waits for completion, extracts metrics from job.log
#
# Usage: benchmark.sh <binary_path> [intensity] [output_csv]
#   binary_path  - Path to binary file to analyze
#   intensity    - quick|standard|deep (default: standard)
#   output_csv   - Path to append CSV results (optional)

set -euo pipefail

# Configuration
API_URL="${API_URL:-http://localhost:8000}"
MAX_WAIT="${MAX_WAIT:-5400}"  # 90 minutes max (standard: ~50 iterations * 60s + overhead)
POLL_INTERVAL=5
KIRK_BASELINE_MIN=15  # Kirk semi-autonomous baseline: 15-20 minutes
KIRK_BASELINE_MAX=20

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Arguments
BINARY_PATH="${1:-}"
INTENSITY="${2:-standard}"
OUTPUT_CSV="${3:-}"

usage() {
    echo "Usage: $0 <binary_path> [intensity] [output_csv]"
    echo ""
    echo "Arguments:"
    echo "  binary_path   Path to binary file to analyze"
    echo "  intensity     Analysis intensity: quick, standard, deep (default: standard)"
    echo "  output_csv    Optional CSV file to append results"
    echo ""
    echo "Environment:"
    echo "  API_URL       API base URL (default: http://localhost:8000)"
    echo "  MAX_WAIT      Max wait time in seconds (default: 900)"
    echo "  DATA_DIR      Override data directory for log access"
    echo ""
    echo "Examples:"
    echo "  $0 ./bbbbloat"
    echo "  $0 ./bbbbloat standard results.csv"
    echo "  $0 ./bbbbloat deep"
    exit 1
}

log_info()  { echo -e "${GREEN}[BENCH]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[BENCH]${NC} $1"; }
log_error() { echo -e "${RED}[BENCH]${NC} $1"; }
log_metric(){ echo -e "${CYAN}[METRIC]${NC} ${BOLD}$1${NC}: $2"; }

# Validate arguments
if [ -z "$BINARY_PATH" ]; then
    usage
fi

if [ ! -f "$BINARY_PATH" ]; then
    log_error "Binary not found: $BINARY_PATH"
    exit 1
fi

case "$INTENSITY" in
    quick|standard|deep) ;;
    *) log_error "Invalid intensity: $INTENSITY (must be quick, standard, or deep)"; exit 1 ;;
esac

BINARY_NAME=$(basename "$BINARY_PATH")

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} GARE Benchmark: $BINARY_NAME${NC}"
echo -e "${BOLD} Intensity: $INTENSITY${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# Step 1: Check API health
log_info "Checking API health..."
if ! curl -s -f "$API_URL/health" > /dev/null 2>&1; then
    log_error "API not responding at $API_URL/health"
    exit 1
fi
log_info "API is healthy"

# Step 2: Upload binary with intensity
log_info "Uploading $BINARY_NAME (intensity=$INTENSITY)..."
UPLOAD_START=$(date +%s)

UPLOAD_RESPONSE=$(curl -s -X POST \
    -F "file=@$BINARY_PATH" \
    -F "intensity=$INTENSITY" \
    "$API_URL/api/upload")

if echo "$UPLOAD_RESPONSE" | grep -q '"detail"'; then
    log_error "Upload failed:"
    echo "$UPLOAD_RESPONSE" | jq . 2>/dev/null || echo "$UPLOAD_RESPONSE"
    exit 1
fi

JOB_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.job_id')
if [ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ]; then
    log_error "Failed to get job ID"
    echo "$UPLOAD_RESPONSE"
    exit 1
fi

log_info "Job created: $JOB_ID"

# Step 3: Poll until completion
log_info "Waiting for analysis to complete..."
LAST_STATUS=""

while true; do
    ELAPSED=$(($(date +%s) - UPLOAD_START))
    if [ "$ELAPSED" -gt "$MAX_WAIT" ]; then
        log_error "Timeout after ${MAX_WAIT}s"
        exit 1
    fi

    JOB_JSON=$(curl -s "$API_URL/api/jobs/$JOB_ID")
    STATUS=$(echo "$JOB_JSON" | jq -r '.job.status')
    PROGRESS=$(echo "$JOB_JSON" | jq -r '.job.progress // 0')

    if [ "$STATUS" != "$LAST_STATUS" ]; then
        log_info "Status: $STATUS ($PROGRESS%) [${ELAPSED}s elapsed]"
        LAST_STATUS="$STATUS"
    fi

    case "$STATUS" in
        completed)
            log_info "Analysis complete!"
            break
            ;;
        failed)
            ERROR_MSG=$(echo "$JOB_JSON" | jq -r '.job.error_message // "unknown"')
            log_error "Job failed: $ERROR_MSG"
            exit 1
            ;;
        canceled)
            log_error "Job was canceled"
            exit 1
            ;;
    esac

    sleep "$POLL_INTERVAL"
done

WALL_CLOCK=$(($(date +%s) - UPLOAD_START))

# Step 4: Locate and parse job log
# Try common data directory locations
DATA_DIR="${DATA_DIR:-}"
LOG_FILE=""

if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/jobs/$JOB_ID/logs/job.log" ]; then
    LOG_FILE="$DATA_DIR/jobs/$JOB_ID/logs/job.log"
else
    # Try relative paths from script location and common Docker volume mounts
    for candidate in \
        "data/jobs/$JOB_ID/logs/job.log" \
        "../data/jobs/$JOB_ID/logs/job.log" \
        "../../data/jobs/$JOB_ID/logs/job.log" \
        "/mnt/c/Users/Justi/Desktop/GARE/MAIN/data/jobs/$JOB_ID/logs/job.log"; do
        if [ -f "$candidate" ]; then
            LOG_FILE="$candidate"
            break
        fi
    done
fi

# Metric extraction (defaults if log not found)
TOTAL_ELAPSED_SEC="$WALL_CLOCK"
GHIDRA_TIME_SEC="N/A"
AGENT_TIME_SEC="N/A"
ITERATIONS_USED=0
MAX_ITERATIONS=0
TOOL_CALLS=0
FUNCTIONS_DECOMPILED=0
FUNCTIONS_RENAMED=0
TOTAL_FUNCTIONS=0

if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    log_info "Parsing job log: $LOG_FILE"

    # Extract timestamps for elapsed time calculation
    FIRST_TIMESTAMP=$(head -1 "$LOG_FILE" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1 || echo "")
    LAST_TIMESTAMP=$(tail -1 "$LOG_FILE" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1 || echo "")

    if [ -n "$FIRST_TIMESTAMP" ] && [ -n "$LAST_TIMESTAMP" ]; then
        FIRST_EPOCH=$(date -d "$FIRST_TIMESTAMP" +%s 2>/dev/null || echo "")
        LAST_EPOCH=$(date -d "$LAST_TIMESTAMP" +%s 2>/dev/null || echo "")
        if [ -n "$FIRST_EPOCH" ] && [ -n "$LAST_EPOCH" ]; then
            TOTAL_ELAPSED_SEC=$((LAST_EPOCH - FIRST_EPOCH))
        fi
    fi

    # Ghidra analysis time: from "Starting Ghidra" or "Importing binary" to "Ghidra analysis complete" or "auto-analysis"
    GHIDRA_START_TS=$(grep -iP '(starting ghidra|importing binary|ghidra import)' "$LOG_FILE" | head -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")
    GHIDRA_END_TS=$(grep -iP '(ghidra analysis complete|auto.analysis complete|analysis complete.*ghidra)' "$LOG_FILE" | head -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")

    if [ -n "$GHIDRA_START_TS" ] && [ -n "$GHIDRA_END_TS" ]; then
        GS_EPOCH=$(date -d "$GHIDRA_START_TS" +%s 2>/dev/null || echo "")
        GE_EPOCH=$(date -d "$GHIDRA_END_TS" +%s 2>/dev/null || echo "")
        if [ -n "$GS_EPOCH" ] && [ -n "$GE_EPOCH" ]; then
            GHIDRA_TIME_SEC=$((GE_EPOCH - GS_EPOCH))
        fi
    fi

    # Agent analysis time: from "Starting agent" to "Analysis marked as complete" or "ANALYSIS_COMPLETE"
    AGENT_START_TS=$(grep -iP '(starting agent|agent analysis|begin.*agent)' "$LOG_FILE" | head -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")
    AGENT_END_TS=$(grep -iP '(analysis.*complete|ANALYSIS_COMPLETE|agent.*complete|COMPLETE.*analysis)' "$LOG_FILE" | tail -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")

    if [ -n "$AGENT_START_TS" ] && [ -n "$AGENT_END_TS" ]; then
        AS_EPOCH=$(date -d "$AGENT_START_TS" +%s 2>/dev/null || echo "")
        AE_EPOCH=$(date -d "$AGENT_END_TS" +%s 2>/dev/null || echo "")
        if [ -n "$AS_EPOCH" ] && [ -n "$AE_EPOCH" ]; then
            AGENT_TIME_SEC=$((AE_EPOCH - AS_EPOCH))
        fi
    fi

    # Iterations used: count [ITERATION X/Y] entries, get max X and Y
    ITERATION_LINES=$(grep -oP '\[ITERATION \d+/\d+\]' "$LOG_FILE" || echo "")
    if [ -n "$ITERATION_LINES" ]; then
        ITERATIONS_USED=$(echo "$ITERATION_LINES" | grep -oP '\d+(?=/)' | sort -n | tail -1 || echo "0")
        MAX_ITERATIONS=$(echo "$ITERATION_LINES" | grep -oP '(?<=/)\d+' | sort -n | tail -1 || echo "0")
    fi

    # Tool calls: count [TOOL #N] entries
    TOOL_CALLS=$(grep -cP '\[TOOL #\d+\]' "$LOG_FILE" || echo "0")

    # Functions decompiled: count decompile_function tool calls
    FUNCTIONS_DECOMPILED=$(grep -cP '\[TOOL #\d+\] decompile_function' "$LOG_FILE" || echo "0")

    # Functions renamed: count rename_function tool calls
    FUNCTIONS_RENAMED=$(grep -cP '\[TOOL #\d+\] rename_function' "$LOG_FILE" || echo "0")

    # Total functions: from first list_methods result "Returned N items"
    TOTAL_FUNCTIONS=$(grep -A1 'list_methods' "$LOG_FILE" | grep -oP 'Returned \K\d+' | head -1 || echo "0")

    # Fallback: try to get total functions from any "N functions" mention
    if [ "$TOTAL_FUNCTIONS" = "0" ] || [ -z "$TOTAL_FUNCTIONS" ]; then
        TOTAL_FUNCTIONS=$(grep -oP '(\d+) (functions|methods)' "$LOG_FILE" | head -1 | grep -oP '^\d+' || echo "0")
    fi
else
    log_warn "Job log not found. Using wall-clock time only."
    log_warn "Set DATA_DIR to the data directory path for full metrics."
fi

# Step 5: Calculate derived metrics
# Format elapsed time as Xm Ys
TOTAL_MIN=$((TOTAL_ELAPSED_SEC / 60))
TOTAL_SEC_REM=$((TOTAL_ELAPSED_SEC % 60))
TTFI_FORMATTED="${TOTAL_MIN}m ${TOTAL_SEC_REM}s"

# Function coverage
if [ "$TOTAL_FUNCTIONS" -gt 0 ] 2>/dev/null; then
    DECOMPILE_COVERAGE=$((FUNCTIONS_DECOMPILED * 100 / TOTAL_FUNCTIONS))
    RENAME_COVERAGE=$((FUNCTIONS_RENAMED * 100 / TOTAL_FUNCTIONS))
else
    DECOMPILE_COVERAGE="N/A"
    RENAME_COVERAGE="N/A"
fi

# Speed multiplier vs Kirk baseline (use midpoint of 15-20 min = 17.5 min = 1050 sec)
KIRK_BASELINE_MID_SEC=$(( (KIRK_BASELINE_MIN + KIRK_BASELINE_MAX) * 60 / 2 ))
if [ "$TOTAL_ELAPSED_SEC" -gt 0 ] 2>/dev/null; then
    # Calculate with one decimal using awk
    SPEED_VS_KIRK_MIN=$(awk "BEGIN {printf \"%.1f\", $KIRK_BASELINE_MIN * 60 / $TOTAL_ELAPSED_SEC}")
    SPEED_VS_KIRK_MAX=$(awk "BEGIN {printf \"%.1f\", $KIRK_BASELINE_MAX * 60 / $TOTAL_ELAPSED_SEC}")
    SPEED_VS_KIRK_MID=$(awk "BEGIN {printf \"%.1f\", $KIRK_BASELINE_MID_SEC / $TOTAL_ELAPSED_SEC}")
else
    SPEED_VS_KIRK_MIN="N/A"
    SPEED_VS_KIRK_MAX="N/A"
    SPEED_VS_KIRK_MID="N/A"
fi

# Step 6: Output results
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} BENCHMARK RESULTS${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

log_metric "Binary" "$BINARY_NAME"
log_metric "Intensity" "$INTENSITY"
log_metric "Job ID" "$JOB_ID"
echo ""

log_metric "Total Functions" "$TOTAL_FUNCTIONS"
log_metric "TTFI (wall clock)" "${WALL_CLOCK}s"
log_metric "TTFI (from log)" "$TTFI_FORMATTED ($TOTAL_ELAPSED_SEC s)"
echo ""

if [ "$GHIDRA_TIME_SEC" != "N/A" ]; then
    log_metric "Ghidra Analysis Time" "${GHIDRA_TIME_SEC}s"
fi
if [ "$AGENT_TIME_SEC" != "N/A" ]; then
    log_metric "Agent Analysis Time" "${AGENT_TIME_SEC}s"
fi
echo ""

log_metric "Iterations" "$ITERATIONS_USED / $MAX_ITERATIONS"
log_metric "Tool Calls" "$TOOL_CALLS"
log_metric "Functions Decompiled" "$FUNCTIONS_DECOMPILED ($DECOMPILE_COVERAGE%)"
log_metric "Functions Renamed" "$FUNCTIONS_RENAMED ($RENAME_COVERAGE%)"
echo ""

log_metric "Speed vs Kirk baseline (15-20 min)" "~${SPEED_VS_KIRK_MIN}-${SPEED_VS_KIRK_MAX}x (mid: ${SPEED_VS_KIRK_MID}x)"
echo ""
echo -e "${BOLD}========================================${NC}"

# Step 7: Append to CSV if requested
if [ -n "$OUTPUT_CSV" ]; then
    # Create header if file doesn't exist
    if [ ! -f "$OUTPUT_CSV" ]; then
        echo "timestamp,binary,intensity,job_id,total_functions,ttfi_sec,ghidra_sec,agent_sec,iterations_used,max_iterations,tool_calls,decompiled,renamed,decompile_pct,rename_pct,speed_vs_kirk_mid" > "$OUTPUT_CSV"
    fi

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "$TIMESTAMP,$BINARY_NAME,$INTENSITY,$JOB_ID,$TOTAL_FUNCTIONS,$TOTAL_ELAPSED_SEC,$GHIDRA_TIME_SEC,$AGENT_TIME_SEC,$ITERATIONS_USED,$MAX_ITERATIONS,$TOOL_CALLS,$FUNCTIONS_DECOMPILED,$FUNCTIONS_RENAMED,$DECOMPILE_COVERAGE,$RENAME_COVERAGE,$SPEED_VS_KIRK_MID" >> "$OUTPUT_CSV"
    log_info "Results appended to $OUTPUT_CSV"
fi

# Output machine-readable summary to stdout (for piping to benchmark_suite.sh)
# This goes to stderr so it doesn't interfere with piped output
cat <<SUMMARY_EOF >&2

--- MACHINE-READABLE SUMMARY ---
BENCHMARK_BINARY=$BINARY_NAME
BENCHMARK_INTENSITY=$INTENSITY
BENCHMARK_JOB_ID=$JOB_ID
BENCHMARK_TOTAL_FUNCTIONS=$TOTAL_FUNCTIONS
BENCHMARK_TTFI_SEC=$TOTAL_ELAPSED_SEC
BENCHMARK_GHIDRA_SEC=$GHIDRA_TIME_SEC
BENCHMARK_AGENT_SEC=$AGENT_TIME_SEC
BENCHMARK_ITERATIONS=$ITERATIONS_USED/$MAX_ITERATIONS
BENCHMARK_TOOL_CALLS=$TOOL_CALLS
BENCHMARK_DECOMPILED=$FUNCTIONS_DECOMPILED
BENCHMARK_RENAMED=$FUNCTIONS_RENAMED
BENCHMARK_DECOMPILE_PCT=$DECOMPILE_COVERAGE
BENCHMARK_RENAME_PCT=$RENAME_COVERAGE
BENCHMARK_SPEED_VS_KIRK=$SPEED_VS_KIRK_MID
--- END SUMMARY ---
SUMMARY_EOF
