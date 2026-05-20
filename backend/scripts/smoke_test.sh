#!/bin/bash
# Smoke test script - uploads a test binary and verifies the pipeline works

set -e

echo "========================================"
echo "Smoke Test - Ghidra Agentic RE Pipeline"
echo "========================================"
echo ""

# Configuration
API_URL="${API_URL:-http://localhost:8000}"
TEST_BINARY="${1}"
MAX_WAIT=600  # 10 minutes
POLL_INTERVAL=5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_service() {
    local url=$1
    local name=$2

    if curl -s -f "$url" > /dev/null 2>&1; then
        log_info "$name is healthy"
        return 0
    else
        log_error "$name is not responding at $url"
        return 1
    fi
}

# Check if binary is provided
if [ -z "$TEST_BINARY" ]; then
    log_warn "No test binary provided"
    echo ""
    echo "Usage: $0 <path-to-binary>"
    echo ""
    echo "You can use any binary for testing. For example:"
    echo "  /bin/ls"
    echo "  /usr/bin/whoami"
    echo "  ./my-test-binary"
    echo ""

    # Check if /bin/ls exists
    if [ -f "/bin/ls" ]; then
        log_info "Using /bin/ls as test binary"
        TEST_BINARY="/bin/ls"
    else
        log_error "No binary provided and /bin/ls not found"
        exit 1
    fi
fi

# Verify binary exists
if [ ! -f "$TEST_BINARY" ]; then
    log_error "Binary not found: $TEST_BINARY"
    exit 1
fi

log_info "Test binary: $TEST_BINARY"
echo ""

# Step 1: Check services
log_info "[1/5] Checking service health..."
check_service "$API_URL/health" "API" || exit 1
check_service "http://localhost:8001/health" "Worker" || exit 1
check_service "http://localhost:3000" "WebUI" || exit 1
echo ""

# Step 2: Upload binary
log_info "[2/5] Uploading binary..."
UPLOAD_RESPONSE=$(curl -s -X POST \
    -F "file=@$TEST_BINARY" \
    "$API_URL/api/upload")

# Check for error
if echo "$UPLOAD_RESPONSE" | grep -q "detail"; then
    log_error "Upload failed:"
    echo "$UPLOAD_RESPONSE" | jq .
    exit 1
fi

JOB_ID=$(echo "$UPLOAD_RESPONSE" | jq -r .job_id)

if [ -z "$JOB_ID" ] || [ "$JOB_ID" = "null" ]; then
    log_error "Failed to get job ID from response"
    echo "$UPLOAD_RESPONSE"
    exit 1
fi

log_info "Job created: $JOB_ID"
FILENAME=$(echo "$UPLOAD_RESPONSE" | jq -r .filename)
SHA256=$(echo "$UPLOAD_RESPONSE" | jq -r .sha256)
log_info "Filename: $FILENAME"
log_info "SHA256: ${SHA256:0:16}..."
echo ""

# Step 3: Monitor job progress
log_info "[3/5] Monitoring job progress..."
START_TIME=$(date +%s)
LAST_STATUS=""
LAST_PROGRESS=0

while true; do
    # Check timeout
    ELAPSED=$(($(date +%s) - START_TIME))
    if [ $ELAPSED -gt $MAX_WAIT ]; then
        log_error "Timeout after ${MAX_WAIT}s"
        exit 1
    fi

    # Get job status
    JOB_STATUS=$(curl -s "$API_URL/api/jobs/$JOB_ID")

    STATUS=$(echo "$JOB_STATUS" | jq -r .job.status)
    PROGRESS=$(echo "$JOB_STATUS" | jq -r .job.progress)
    ERROR_MSG=$(echo "$JOB_STATUS" | jq -r .job.error_message)

    # Update if changed
    if [ "$STATUS" != "$LAST_STATUS" ] || [ "$PROGRESS" != "$LAST_PROGRESS" ]; then
        log_info "Status: $STATUS ($PROGRESS%)"
        LAST_STATUS=$STATUS
        LAST_PROGRESS=$PROGRESS
    fi

    # Check terminal states
    case $STATUS in
        completed)
            log_info "Job completed successfully!"
            break
            ;;
        failed)
            log_error "Job failed: $ERROR_MSG"
            exit 1
            ;;
        canceled)
            log_error "Job was canceled"
            exit 1
            ;;
    esac

    sleep $POLL_INTERVAL
done
echo ""

# Step 4: Fetch report
log_info "[4/5] Fetching report..."
REPORT_RESPONSE=$(curl -s "$API_URL/api/jobs/$JOB_ID/report")

if echo "$REPORT_RESPONSE" | grep -q "detail"; then
    log_error "Failed to fetch report:"
    echo "$REPORT_RESPONSE" | jq .
    exit 1
fi

REPORT_CONTENT=$(echo "$REPORT_RESPONSE" | jq -r .content)

if [ -z "$REPORT_CONTENT" ] || [ "$REPORT_CONTENT" = "null" ]; then
    log_error "Report content is empty"
    exit 1
fi

# Save report
REPORT_FILE="smoke_test_report_$(date +%Y%m%d_%H%M%S).md"
echo "$REPORT_CONTENT" > "$REPORT_FILE"
log_info "Report saved to: $REPORT_FILE"

# Verify report content
REPORT_LINES=$(echo "$REPORT_CONTENT" | wc -l)
log_info "Report contains $REPORT_LINES lines"

if [ "$REPORT_LINES" -lt 10 ]; then
    log_warn "Report seems too short"
fi

# Check for key sections
check_section() {
    local section=$1
    if echo "$REPORT_CONTENT" | grep -q "$section"; then
        log_info "  ✓ Contains '$section' section"
    else
        log_warn "  ✗ Missing '$section' section"
    fi
}

check_section "Executive Summary"
check_section "Binary Overview"
check_section "Function Analysis"

echo ""

# Step 5: Verify artifacts
log_info "[5/5] Verifying artifacts..."

# Check job directory
JOB_DIR="data/jobs/$JOB_ID"
if [ -d "$JOB_DIR" ]; then
    log_info "Job directory exists: $JOB_DIR"

    # Check subdirectories
    for dir in input ghidra_project artifacts logs report; do
        if [ -d "$JOB_DIR/$dir" ]; then
            log_info "  ✓ $dir/ exists"
        else
            log_warn "  ✗ $dir/ missing"
        fi
    done

    # Check report file
    if [ -f "$JOB_DIR/report/report.md" ]; then
        log_info "  ✓ report.md exists"
        REPORT_SIZE=$(stat -c%s "$JOB_DIR/report/report.md" 2>/dev/null || stat -f%z "$JOB_DIR/report/report.md" 2>/dev/null)
        log_info "  ✓ Report size: $REPORT_SIZE bytes"
    else
        log_warn "  ✗ report.md missing"
    fi

else
    log_error "Job directory not found: $JOB_DIR"
    log_warn "Check Docker volume mounts"
fi

echo ""

# Summary
echo "========================================"
echo -e "${GREEN}✓ SMOKE TEST PASSED${NC}"
echo "========================================"
echo ""
echo "Job ID:        $JOB_ID"
echo "Binary:        $FILENAME"
echo "Status:        $STATUS"
echo "Report:        $REPORT_FILE"
echo "Job Directory: $JOB_DIR"
echo ""
echo "View report in WebUI:"
echo "  http://localhost:3000/jobs/$JOB_ID"
echo ""
echo "View report locally:"
echo "  cat $REPORT_FILE"
echo ""
echo "========================================"
