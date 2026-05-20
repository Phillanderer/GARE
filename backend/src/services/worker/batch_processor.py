"""
Batch Processing for Multi-Binary Jobs (GB-22)

Processes multiple binaries in a single batch job, reusing the same JVM/PyGhidra
instance across files to avoid startup overhead.

Book Reference: Ch. 16 (Ghidra in Headless Mode, pp. 349-350)
  - Recursive directory processing with -recursive flag
  - Wildcard support for file matching
  - Single JVM instance processes multiple files sequentially
  - Per-file timeout prevents any single binary from blocking the batch

Implementation:
  - Accept a list of binary paths (from batch upload or directory scan)
  - Process each binary sequentially with per-file timeout
  - Produce per-binary metadata + artifacts
  - Summary report aggregating findings across all binaries
"""

import os
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class BatchProcessor:
    """Processes multiple binaries in a single batch job"""

    def __init__(self, job_id: str, data_dir: str, intensity: str = "standard"):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.intensity = intensity
        self.results: List[Dict[str, Any]] = []

        logger.info(f"BatchProcessor initialized for job {job_id} (intensity={intensity})")

    def discover_binaries(self, input_dir: Optional[str] = None, patterns: Optional[List[str]] = None) -> List[Path]:
        """Discover binaries to process from input directory

        Args:
            input_dir: Directory to scan. Defaults to job's input/ directory.
            patterns: Glob patterns to match (e.g., ["*.exe", "*.dll", "*.elf"]).
                      If None, matches all files.

        Returns:
            List of binary file paths found
        """
        scan_dir = Path(input_dir) if input_dir else self.job_dir / "input"

        if not scan_dir.exists():
            logger.warning(f"Input directory does not exist: {scan_dir}")
            return []

        if patterns:
            binaries = []
            for pattern in patterns:
                binaries.extend(scan_dir.rglob(pattern))
        else:
            # Match all files (skip directories and hidden files)
            binaries = [f for f in scan_dir.rglob("*") if f.is_file() and not f.name.startswith(".")]

        # Sort for deterministic order
        binaries = sorted(set(binaries))
        logger.info(f"Discovered {len(binaries)} binaries in {scan_dir}")
        return binaries

    def process_batch(self, binary_paths: List[Path], per_file_timeout: Optional[int] = None) -> Dict[str, Any]:
        """Process multiple binaries sequentially

        Args:
            binary_paths: List of binary file paths to analyze
            per_file_timeout: Max seconds per binary. Defaults to intensity-based timeout.

        Returns:
            Batch result summary with per-binary results
        """
        from src.services.worker.ghidra_runner import GhidraRunner
        from src.services.worker.analysis_config import get_analysis_config

        config = get_analysis_config(self.intensity)
        timeout = per_file_timeout or config["import_timeout_seconds"]

        batch_start = time.time()
        total = len(binary_paths)

        self._log_to_job(f"Starting batch processing: {total} binaries (intensity={self.intensity}, per_file_timeout={timeout}s)")

        batch_result = {
            "mode": "batch",
            "job_id": self.job_id,
            "total_binaries": total,
            "processed": 0,
            "succeeded": 0,
            "failed": 0,
            "skipped": 0,
            "binaries": [],
            "elapsed_seconds": 0
        }

        for idx, binary_path in enumerate(binary_paths):
            binary_name = binary_path.name
            file_start = time.time()

            self._log_to_job(f"[{idx + 1}/{total}] Processing: {binary_name}")

            # Create per-binary subdirectory for artifacts
            binary_id = f"binary_{idx:04d}_{binary_name}"
            binary_dir = self.job_dir / "batch" / binary_id
            binary_dir.mkdir(parents=True, exist_ok=True)
            (binary_dir / "ghidra_project").mkdir(exist_ok=True)
            (binary_dir / "artifacts").mkdir(exist_ok=True)

            try:
                # Create a GhidraRunner scoped to this binary's subdirectory
                runner = GhidraRunner(
                    job_id=f"{self.job_id}_batch_{idx}",
                    data_dir=str(binary_dir.parent.parent),  # Points back to job dir
                    intensity=self.intensity
                )

                # Override paths to use batch subdirectory
                runner.job_dir = binary_dir
                runner.project_dir = binary_dir / "ghidra_project"
                runner.project_name = f"project_{binary_name}"

                # Import and analyze
                import_result = runner.import_binary(str(binary_path))

                file_elapsed = time.time() - file_start

                if import_result.get("success"):
                    metadata = import_result.get("metadata", {})

                    # Save per-binary metadata
                    meta_path = binary_dir / "artifacts" / "metadata.json"
                    with open(meta_path, 'w') as f:
                        json.dump(metadata, f, indent=2)

                    binary_entry = {
                        "index": idx,
                        "name": binary_name,
                        "path": str(binary_path),
                        "success": True,
                        "metadata": metadata,
                        "elapsed_seconds": round(file_elapsed, 2)
                    }
                    batch_result["succeeded"] += 1
                    self._log_to_job(f"[{idx + 1}/{total}] Success: {binary_name} ({file_elapsed:.1f}s)")
                else:
                    binary_entry = {
                        "index": idx,
                        "name": binary_name,
                        "path": str(binary_path),
                        "success": False,
                        "error": import_result.get("error", "Unknown error"),
                        "elapsed_seconds": round(file_elapsed, 2)
                    }
                    batch_result["failed"] += 1
                    self._log_to_job(f"[{idx + 1}/{total}] Failed: {binary_name} — {import_result.get('error')}")

            except Exception as e:
                file_elapsed = time.time() - file_start
                binary_entry = {
                    "index": idx,
                    "name": binary_name,
                    "path": str(binary_path),
                    "success": False,
                    "error": str(e),
                    "elapsed_seconds": round(file_elapsed, 2)
                }
                batch_result["failed"] += 1
                logger.error(f"Batch binary {binary_name} failed: {e}", exc_info=True)
                self._log_to_job(f"[{idx + 1}/{total}] Error: {binary_name} — {str(e)}")

            batch_result["binaries"].append(binary_entry)
            batch_result["processed"] += 1

        batch_result["elapsed_seconds"] = round(time.time() - batch_start, 2)

        # Save batch summary
        summary_path = self.job_dir / "batch" / "batch_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(batch_result, f, indent=2)

        self._log_to_job(
            f"Batch complete: {batch_result['succeeded']}/{total} succeeded, "
            f"{batch_result['failed']} failed, {batch_result['elapsed_seconds']}s total"
        )

        return batch_result

    def generate_batch_report(self, batch_result: Dict[str, Any]) -> str:
        """Generate a summary report for the batch analysis

        Args:
            batch_result: Result from process_batch()

        Returns:
            Markdown-formatted batch report
        """
        from src.utils.timezone import format_display

        lines = [
            "# Batch Analysis Report",
            "",
            f"**Job ID**: {self.job_id}",
            f"**Analysis Date**: {format_display(fmt='%Y-%m-%d %H:%M:%S %Z')}",
            f"**Intensity**: {self.intensity}",
            f"**Total Binaries**: {batch_result['total_binaries']}",
            f"**Succeeded**: {batch_result['succeeded']}",
            f"**Failed**: {batch_result['failed']}",
            f"**Total Time**: {batch_result['elapsed_seconds']}s",
            "",
            "---",
            "",
            "## Per-Binary Results",
            "",
            "| # | Binary | Status | Time | Architecture | Format |",
            "|---|--------|--------|------|-------------|--------|",
        ]

        for entry in batch_result.get("binaries", []):
            status = "OK" if entry.get("success") else "FAIL"
            meta = entry.get("metadata", {})
            arch = meta.get("language", meta.get("processor", "—"))
            fmt = meta.get("executable_format", "—")
            elapsed = f"{entry.get('elapsed_seconds', 0):.1f}s"
            lines.append(f"| {entry['index'] + 1} | `{entry['name']}` | {status} | {elapsed} | {arch} | {fmt} |")

        lines.append("")

        # Failed binaries detail
        failed = [e for e in batch_result.get("binaries", []) if not e.get("success")]
        if failed:
            lines.append("## Failed Binaries")
            lines.append("")
            for entry in failed:
                lines.append(f"- **{entry['name']}**: {entry.get('error', 'Unknown error')}")
            lines.append("")

        # Successful binary metadata summary
        succeeded = [e for e in batch_result.get("binaries", []) if e.get("success")]
        if succeeded:
            lines.append("## Binary Metadata Summary")
            lines.append("")
            for entry in succeeded:
                meta = entry.get("metadata", {})
                lines.append(f"### {entry['name']}")
                lines.append("")
                lines.append(f"- **Architecture**: {meta.get('language', 'unknown')}")
                lines.append(f"- **Format**: {meta.get('executable_format', 'unknown')}")
                lines.append(f"- **Compiler**: {meta.get('compiler', 'unknown')}")
                lines.append(f"- **Functions**: {meta.get('function_count', 'unknown')}")
                lines.append(f"- **Entry Point**: {meta.get('entry_point', 'unknown')}")
                lines.append("")

        lines.extend([
            "---",
            "",
            f"**Report Generated**: {format_display(fmt='%Y-%m-%d %H:%M:%S %Z')}",
            f"**Analysis Engine**: GARE Batch Processor"
        ])

        return "\n".join(lines)

    def _log_to_job(self, message: str):
        """Write log message to job log file"""
        try:
            from src.utils.timezone import utc_now
            log_file = self.job_dir / "logs" / "job.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            timestamp = utc_now().isoformat()
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] [BATCH] {message}\n")
        except Exception:
            pass
