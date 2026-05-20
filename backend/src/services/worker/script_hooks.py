"""
Pre/Post Script Hook Architecture (GB-23)

Configurable script hooks that run before and after Ghidra auto-analysis.
Hooks enable setup, validation, configuration, and data extraction at
defined lifecycle points.

Book Reference: Ch. 16 (Ghidra in Headless Mode, pp. 353-360)
  - -preScript: runs before auto-analysis (setup, validation, custom config)
  - -postScript: runs after auto-analysis (data extraction, report generation)
  - Scripts can chain: preScript sets options → analysis runs → postScript extracts results
  - HeadlessSimpleROP example: runs as postScript to extract gadgets

Lifecycle points:
  1. PRE_IMPORT  — before binary is imported (validate, log)
  2. POST_IMPORT — after import, before auto-analysis (configure analysis options)
  3. PRE_ANALYSIS — just before auto-analysis begins (set decompiler options)
  4. POST_ANALYSIS — after auto-analysis completes (extract metadata, run scripts)
  5. PRE_SCRIPT  — before each tool script runs (logging, validation)
  6. POST_SCRIPT — after each tool script runs (output transformation, caching)

Hook configuration is stored per-job in job_meta.json or globally in
environment variables.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class HookPoint(str, Enum):
    """Lifecycle points where hooks can be registered"""
    PRE_IMPORT = "pre_import"
    POST_IMPORT = "post_import"
    PRE_ANALYSIS = "pre_analysis"
    POST_ANALYSIS = "post_analysis"
    PRE_SCRIPT = "pre_script"
    POST_SCRIPT = "post_script"


class HookResult:
    """Result from a hook execution"""

    def __init__(self, success: bool, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        self.success = success
        self.data = data or {}
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        result = {"success": self.success}
        if self.data:
            result["data"] = self.data
        if self.error:
            result["error"] = self.error
        return result


# Built-in hook implementations

def hook_log_import(context: Dict[str, Any]) -> HookResult:
    """Log binary import details"""
    binary_path = context.get("binary_path", "unknown")
    job_id = context.get("job_id", "unknown")
    logger.info(f"[HOOK:pre_import] Importing {binary_path} for job {job_id}")
    return HookResult(success=True, data={"logged": True})


def hook_validate_binary(context: Dict[str, Any]) -> HookResult:
    """Validate binary file before import"""
    binary_path = Path(context.get("binary_path", ""))

    if not binary_path.exists():
        return HookResult(success=False, error=f"Binary not found: {binary_path}")

    file_size = binary_path.stat().st_size
    max_size = context.get("max_binary_size", 100 * 1024 * 1024)  # 100MB default

    if file_size == 0:
        return HookResult(success=False, error="Binary file is empty")

    if file_size > max_size:
        return HookResult(success=False, error=f"Binary too large: {file_size} bytes (max: {max_size})")

    # Check magic bytes for common executable formats
    with open(binary_path, 'rb') as f:
        magic = f.read(4)

    known_formats = {
        b'\x7fELF': "ELF",
        b'MZ\x90\x00': "PE/MZ",
        b'MZ\x00\x00': "PE/MZ",
        b'\xfe\xed\xfa\xce': "Mach-O (32-bit)",
        b'\xfe\xed\xfa\xcf': "Mach-O (64-bit)",
        b'\xce\xfa\xed\xfe': "Mach-O (32-bit, reversed)",
        b'\xcf\xfa\xed\xfe': "Mach-O (64-bit, reversed)",
    }

    # Also check 2-byte prefix for PE
    detected = None
    for prefix, fmt in known_formats.items():
        if magic[:len(prefix)] == prefix:
            detected = fmt
            break

    if not detected and magic[:2] == b'MZ':
        detected = "PE/MZ"

    return HookResult(
        success=True,
        data={
            "file_size": file_size,
            "format_detected": detected or "unknown",
            "magic_hex": magic.hex()
        }
    )


def hook_configure_decompiler(context: Dict[str, Any]) -> HookResult:
    """Configure decompiler options based on intensity (runs post-import)"""
    intensity = context.get("intensity", "standard")

    # These options map to GB-1 decompiler configuration
    decompiler_options = {
        "quick": {
            "eliminate_unreachable": True,
            "simplify_predication": True,
            "max_payload_bytes": 100000
        },
        "standard": {
            "eliminate_unreachable": True,
            "simplify_predication": True,
            "max_payload_bytes": 500000
        },
        "deep": {
            "eliminate_unreachable": False,  # Keep all code for thorough analysis
            "simplify_predication": False,
            "max_payload_bytes": 2000000
        }
    }

    options = decompiler_options.get(intensity, decompiler_options["standard"])
    logger.info(f"[HOOK:post_import] Decompiler options for '{intensity}': {options}")
    return HookResult(success=True, data={"decompiler_options": options})


def hook_extract_metadata(context: Dict[str, Any]) -> HookResult:
    """Extract and save metadata after analysis (post-analysis hook)"""
    job_dir = context.get("job_dir")
    if not job_dir:
        return HookResult(success=True, data={"skipped": "no job_dir in context"})

    job_dir = Path(job_dir)
    artifacts_dir = job_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Check what artifacts exist
    artifacts = []
    for f in artifacts_dir.iterdir():
        if f.is_file():
            artifacts.append(f.name)

    return HookResult(success=True, data={"artifacts_found": artifacts})


def hook_log_script(context: Dict[str, Any]) -> HookResult:
    """Log script execution (pre/post script hook)"""
    script_name = context.get("script_name", "unknown")
    hook_point = context.get("hook_point", "unknown")
    job_id = context.get("job_id", "unknown")

    logger.info(f"[HOOK:{hook_point}] Script '{script_name}' for job {job_id}")
    return HookResult(success=True, data={"logged": True})


# Default hook registry — built-in hooks enabled by default
DEFAULT_HOOKS: Dict[str, List[Callable]] = {
    HookPoint.PRE_IMPORT: [hook_log_import, hook_validate_binary],
    HookPoint.POST_IMPORT: [hook_configure_decompiler],
    HookPoint.PRE_ANALYSIS: [],
    HookPoint.POST_ANALYSIS: [hook_extract_metadata],
    HookPoint.PRE_SCRIPT: [hook_log_script],
    HookPoint.POST_SCRIPT: [],
}


class HookManager:
    """Manages and executes script hooks at defined lifecycle points"""

    def __init__(self, job_id: str, data_dir: str, intensity: str = "standard"):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.intensity = intensity
        self.hooks: Dict[str, List[Callable]] = {}
        self.hook_results: Dict[str, List[Dict]] = {}
        self.enabled = True

        # Load default hooks
        for point, hook_list in DEFAULT_HOOKS.items():
            self.hooks[point] = list(hook_list)

        # Check for hook disable flag
        if os.environ.get("DISABLE_HOOKS", "").lower() == "true":
            self.enabled = False
            logger.info(f"Hooks disabled for job {job_id} (DISABLE_HOOKS=true)")

        # Load per-job hook configuration
        self._load_job_hooks()

    def _load_job_hooks(self):
        """Load hook configuration from job_meta.json"""
        meta_path = self.job_dir / "job_meta.json"
        if not meta_path.exists():
            return

        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)

            hook_config = meta.get("hooks", {})

            # Allow disabling specific hook points
            disabled_points = hook_config.get("disabled", [])
            for point in disabled_points:
                if point in self.hooks:
                    self.hooks[point] = []
                    logger.info(f"Hooks disabled at {point} for job {self.job_id}")

        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load hook config: {e}")

    def register_hook(self, point: str, hook_fn: Callable):
        """Register a custom hook at the specified lifecycle point"""
        if point not in self.hooks:
            self.hooks[point] = []
        self.hooks[point].append(hook_fn)

    def run_hooks(self, point: str, context: Optional[Dict[str, Any]] = None) -> List[HookResult]:
        """Execute all hooks registered at the given lifecycle point

        Args:
            point: The HookPoint to execute
            context: Context dict passed to each hook (job_id, binary_path, etc.)

        Returns:
            List of HookResult from each hook execution
        """
        if not self.enabled:
            return []

        hooks = self.hooks.get(point, [])
        if not hooks:
            return []

        # Build context
        ctx = {
            "job_id": self.job_id,
            "data_dir": str(self.data_dir),
            "job_dir": str(self.job_dir),
            "intensity": self.intensity,
            "hook_point": point,
        }
        if context:
            ctx.update(context)

        results = []
        for hook_fn in hooks:
            try:
                result = hook_fn(ctx)
                results.append(result)

                if not result.success:
                    logger.warning(f"Hook {hook_fn.__name__} at {point} failed: {result.error}")
                    # For pre-import validation failure, stop the chain
                    if point == HookPoint.PRE_IMPORT:
                        break

            except Exception as e:
                logger.error(f"Hook {hook_fn.__name__} at {point} raised exception: {e}")
                results.append(HookResult(success=False, error=str(e)))

        # Store results for later inspection
        self.hook_results.setdefault(point, []).extend(
            [r.to_dict() for r in results]
        )

        return results

    def get_hook_report(self) -> Dict[str, Any]:
        """Get a summary of all hook executions"""
        return {
            "job_id": self.job_id,
            "enabled": self.enabled,
            "hook_results": self.hook_results,
            "registered_hooks": {
                point: [fn.__name__ for fn in fns]
                for point, fns in self.hooks.items()
                if fns
            }
        }

    def save_hook_report(self):
        """Save hook execution report to job artifacts"""
        report = self.get_hook_report()
        report_path = self.job_dir / "artifacts" / "hook_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save hook report: {e}")
