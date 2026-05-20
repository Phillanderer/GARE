#!/bin/bash
# benchmark_suite.sh - Multi-binary benchmark suite for GARE pipeline
# Runs benchmark.sh against multiple binaries and aggregates results
#
# Usage:
#   benchmark_suite.sh <binary1> [binary2] [binary3] ...
#   benchmark_suite.sh --reproducibility <binary> <N>
#   benchmark_suite.sh --intensity-compare <binary>
#
# Options:
#   --reproducibility <binary> <N>   Run same binary N times for consistency testing
#   --intensity-compare <binary>     Run same binary at quick/standard/deep
#   --output-dir <dir>               Override output directory

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_SCRIPT="$SCRIPT_DIR/benchmark.sh"
DEFAULT_OUTPUT_DIR="$(cd "$SCRIPT_DIR" && cd ../../data/benchmark_results 2>/dev/null && pwd || echo "$SCRIPT_DIR/../../data/benchmark_results")"
DATE_STAMP=$(date +%Y%m%d)
TIME_STAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[SUITE]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[SUITE]${NC} $1"; }
log_error() { echo -e "${RED}[SUITE]${NC} $1"; }

# Parse arguments
MODE="multi"  # multi, reproducibility, intensity-compare
BINARIES=()
REPRO_COUNT=5
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"

while [ $# -gt 0 ]; do
    case "$1" in
        --reproducibility)
            MODE="reproducibility"
            shift
            if [ $# -lt 2 ]; then
                echo "Usage: $0 --reproducibility <binary> <N>"
                exit 1
            fi
            BINARIES=("$1")
            REPRO_COUNT="$2"
            shift 2
            ;;
        --intensity-compare)
            MODE="intensity-compare"
            shift
            if [ $# -lt 1 ]; then
                echo "Usage: $0 --intensity-compare <binary>"
                exit 1
            fi
            BINARIES=("$1")
            shift
            ;;
        --output-dir)
            shift
            OUTPUT_DIR="$1"
            shift
            ;;
        -h|--help)
            echo "Usage:"
            echo "  $0 <binary1> [binary2] ...              Run multiple binaries"
            echo "  $0 --reproducibility <binary> <N>       Run same binary N times"
            echo "  $0 --intensity-compare <binary>          Run at quick/standard/deep"
            echo ""
            echo "Options:"
            echo "  --output-dir <dir>   Override output directory"
            echo ""
            echo "Results saved to: $DEFAULT_OUTPUT_DIR/benchmark_YYYYMMDD.md"
            exit 0
            ;;
        *)
            BINARIES+=("$1")
            shift
            ;;
    esac
done

if [ ${#BINARIES[@]} -eq 0 ]; then
    log_error "No binaries specified"
    echo "Usage: $0 <binary1> [binary2] ..."
    exit 1
fi

# Verify benchmark script exists
if [ ! -x "$BENCHMARK_SCRIPT" ]; then
    log_error "benchmark.sh not found or not executable at $BENCHMARK_SCRIPT"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
CSV_FILE="$OUTPUT_DIR/benchmark_${TIME_STAMP}.csv"
MD_FILE="$OUTPUT_DIR/benchmark_${DATE_STAMP}.md"

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD} GARE Benchmark Suite${NC}"
echo -e "${BOLD} Mode: $MODE${NC}"
echo -e "${BOLD} Binaries: ${#BINARIES[@]}${NC}"
echo -e "${BOLD} Output: $MD_FILE${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""

# Track results for markdown generation
declare -a RESULT_LINES=()
TOTAL_RUNS=0
FAILED_RUNS=0

run_benchmark() {
    local binary="$1"
    local intensity="${2:-standard}"
    local run_label="${3:-}"

    TOTAL_RUNS=$((TOTAL_RUNS + 1))
    local binary_name
    binary_name=$(basename "$binary")

    if [ -n "$run_label" ]; then
        log_info "--- Run $run_label: $binary_name (intensity=$intensity) ---"
    else
        log_info "--- Benchmarking: $binary_name (intensity=$intensity) ---"
    fi

    # Run benchmark and capture output
    local bench_output
    local bench_exit=0
    bench_output=$("$BENCHMARK_SCRIPT" "$binary" "$intensity" "$CSV_FILE" 2>&1) || bench_exit=$?

    if [ $bench_exit -ne 0 ]; then
        log_error "Benchmark failed for $binary_name (exit code $bench_exit)"
        FAILED_RUNS=$((FAILED_RUNS + 1))
        RESULT_LINES+=("| $binary_name | $intensity | ${run_label:-1} | FAILED | - | - | - | - | - | - |")
        return 1
    fi

    # Extract metrics from output
    local ttfi_sec ttfi_fmt total_funcs iterations tool_calls decompiled renamed decompile_pct rename_pct speed_kirk

    ttfi_sec=$(echo "$bench_output" | grep 'BENCHMARK_TTFI_SEC=' | cut -d= -f2 || echo "?")
    total_funcs=$(echo "$bench_output" | grep 'BENCHMARK_TOTAL_FUNCTIONS=' | cut -d= -f2 || echo "?")
    iterations=$(echo "$bench_output" | grep 'BENCHMARK_ITERATIONS=' | cut -d= -f2 || echo "?")
    tool_calls=$(echo "$bench_output" | grep 'BENCHMARK_TOOL_CALLS=' | cut -d= -f2 || echo "?")
    decompiled=$(echo "$bench_output" | grep 'BENCHMARK_DECOMPILED=' | cut -d= -f2 || echo "?")
    renamed=$(echo "$bench_output" | grep 'BENCHMARK_RENAMED=' | cut -d= -f2 || echo "?")
    decompile_pct=$(echo "$bench_output" | grep 'BENCHMARK_DECOMPILE_PCT=' | cut -d= -f2 || echo "?")
    rename_pct=$(echo "$bench_output" | grep 'BENCHMARK_RENAME_PCT=' | cut -d= -f2 || echo "?")
    speed_kirk=$(echo "$bench_output" | grep 'BENCHMARK_SPEED_VS_KIRK=' | cut -d= -f2 || echo "?")

    # Format TTFI
    if [ "$ttfi_sec" != "?" ] && [ -n "$ttfi_sec" ]; then
        local mins=$((ttfi_sec / 60))
        local secs=$((ttfi_sec % 60))
        ttfi_fmt="${mins}m ${secs}s"
    else
        ttfi_fmt="?"
    fi

    RESULT_LINES+=("| $binary_name | $intensity | ${run_label:-1} | $ttfi_fmt | $total_funcs | $iterations | $tool_calls | $decompiled ($decompile_pct%) | $renamed ($rename_pct%) | ${speed_kirk}x |")

    echo ""
    return 0
}

# Execute based on mode
case "$MODE" in
    multi)
        for binary in "${BINARIES[@]}"; do
            run_benchmark "$binary" "standard" || true
        done
        ;;

    reproducibility)
        log_info "Running ${BINARIES[0]} $REPRO_COUNT times for reproducibility testing"
        for i in $(seq 1 "$REPRO_COUNT"); do
            run_benchmark "${BINARIES[0]}" "standard" "$i" || true
            # Brief pause between runs to avoid overwhelming the API
            if [ "$i" -lt "$REPRO_COUNT" ]; then
                log_info "Waiting 10s before next run..."
                sleep 10
            fi
        done
        ;;

    intensity-compare)
        log_info "Running ${BINARIES[0]} at all intensity levels"
        for level in quick standard deep; do
            run_benchmark "${BINARIES[0]}" "$level" "$level" || true
            # Pause between runs
            if [ "$level" != "deep" ]; then
                log_info "Waiting 10s before next intensity level..."
                sleep 10
            fi
        done
        ;;
esac

# Generate markdown report
log_info "Generating markdown report: $MD_FILE"

{
    echo "# GARE Benchmark Results"
    echo ""
    echo "**Date:** $(date '+%Y-%m-%d %H:%M:%S')"
    echo "**Mode:** $MODE"
    echo "**Total Runs:** $TOTAL_RUNS (Failed: $FAILED_RUNS)"
    echo ""
    echo "## Kirk Semi-Autonomous Baseline"
    echo ""
    echo "- **Method:** Laurie Kirk's GhidraMCP with a third-party MCP-compatible LLM client"
    echo "- **Observed TTFI:** 15-20 minutes per binary"
    echo "- **Human Involvement:** ~50% (analyst guides LLM throughout)"
    echo "- **Source:** Direct observation during earlier testing"
    echo ""

    case "$MODE" in
        multi)
            echo "## Performance Comparison"
            echo ""
            echo "| Binary | Intensity | Run | TTFI | Functions | Iterations | Tool Calls | Decompiled | Renamed | Speed vs Kirk |"
            echo "|--------|-----------|-----|------|-----------|------------|------------|------------|---------|---------------|"
            ;;
        reproducibility)
            echo "## Reproducibility Test: $(basename "${BINARIES[0]}")"
            echo ""
            echo "| Binary | Intensity | Run | TTFI | Functions | Iterations | Tool Calls | Decompiled | Renamed | Speed vs Kirk |"
            echo "|--------|-----------|-----|------|-----------|------------|------------|------------|---------|---------------|"
            ;;
        intensity-compare)
            echo "## Intensity Level Comparison: $(basename "${BINARIES[0]}")"
            echo ""
            echo "| Binary | Intensity | Level | TTFI | Functions | Iterations | Tool Calls | Decompiled | Renamed | Speed vs Kirk |"
            echo "|--------|-----------|-------|------|-----------|------------|------------|------------|---------|---------------|"
            ;;
    esac

    for line in "${RESULT_LINES[@]}"; do
        echo "$line"
    done

    echo ""

    # Add reproducibility analysis if applicable
    if [ "$MODE" = "reproducibility" ] && [ ${#RESULT_LINES[@]} -gt 1 ]; then
        echo "### Reproducibility Analysis"
        echo ""
        echo "Consistency metrics to be calculated from the CSV data above."
        echo "Key questions:"
        echo "- Do all runs identify the same core findings?"
        echo "- What is the TTFI variance across runs?"
        echo "- How consistent is function rename count?"
        echo ""
    fi

    # Add intensity analysis if applicable
    if [ "$MODE" = "intensity-compare" ]; then
        echo "### Intensity Level Analysis"
        echo ""
        echo "Shows how iteration budget (quick=15, standard=50, deep=100) affects:"
        echo "- Coverage (more iterations = more functions examined)"
        echo "- Time (more iterations = longer analysis)"
        echo "- Diminishing returns threshold"
        echo ""
    fi

    echo "## Notes"
    echo ""
    echo "- Speed vs Kirk calculated as: Kirk baseline midpoint (17.5 min) / measured TTFI"
    echo "- Kirk baseline of 15-20 minutes was observed during earlier testing, not concurrent"
    echo "- Decompiled % = functions decompiled / total functions"
    echo "- Renamed % = functions renamed / total functions"
    echo "- All tests run against GARE v1.0 with the operator-configured LLM backend"
    echo ""
    echo "## Raw Data"
    echo ""
    echo "CSV file: \`$CSV_FILE\`"
    echo ""

} > "$MD_FILE"

# Summary
echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD} SUITE COMPLETE${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
log_info "Total runs: $TOTAL_RUNS (failed: $FAILED_RUNS)"
log_info "Markdown report: $MD_FILE"
log_info "CSV data: $CSV_FILE"
echo ""

# Print the results table to console too
echo -e "${BOLD}Results Summary:${NC}"
echo ""
echo "| Binary | Intensity | Run | TTFI | Functions | Iterations | Tool Calls | Decompiled | Renamed | Speed vs Kirk |"
echo "|--------|-----------|-----|------|-----------|------------|------------|------------|---------|---------------|"
for line in "${RESULT_LINES[@]}"; do
    echo "$line"
done
echo ""
