#!/bin/bash
# Cleanup old job data (requires sudo due to Docker container ownership)

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
JOBS_DIR="$PROJECT_ROOT/data/jobs"
GARBAGE_DIR="$PROJECT_ROOT/GARBAGE/old_jobs"

echo "=== Old Job Data Cleanup ==="
echo "Project root: $PROJECT_ROOT"
echo "Jobs directory: $JOBS_DIR"
echo "Moving to: $GARBAGE_DIR"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run with sudo"
    echo "Usage: sudo $0"
    exit 1
fi

# Count jobs to move
JOB_COUNT=$(find "$JOBS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

if [ "$JOB_COUNT" -eq 0 ]; then
    echo "No job directories found. Nothing to clean."
    exit 0
fi

echo "Found $JOB_COUNT job directories to move"
echo ""

# Move each job directory
for job_dir in "$JOBS_DIR"/*; do
    if [ -d "$job_dir" ]; then
        job_name=$(basename "$job_dir")
        echo "Moving: $job_name"
        mv "$job_dir" "$GARBAGE_DIR/"
    fi
done

echo ""
echo "✓ Cleanup complete. Moved $JOB_COUNT directories to GARBAGE/old_jobs/"
echo "✓ Jobs directory is now clean and ready for new analysis runs"
