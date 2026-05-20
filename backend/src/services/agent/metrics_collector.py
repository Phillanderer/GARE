"""
Analysis metrics collector for before/after comparison.
Tallies tool usage, findings, and GB-enhanced tool utilization.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Tools added by GB enhancements (GB-1 through GB-23)
GB_ENHANCED_TOOLS = {
    "analyze_basic_blocks",      # GB-4
    "get_variable_slice",        # GB-3
    "auto_create_structure",     # GB-2
    "detect_switch",             # GB-6
    "detect_arrays",             # GB-9
    "analyze_cpp_classes",       # GB-10
    "set_function_attributes",   # GB-12
    "set_repeatable_comment",    # GB-13
    "set_equate",                # GB-14
    "suggest_equates",           # GB-14
    "convert_to_code",           # GB-15
    "convert_to_data",           # GB-15
    "detect_loops",              # GB-16
    "find_desync_errors",        # GB-17
    "resolve_computed_jump",     # GB-18
    "emulate_deobfuscation",     # GB-19
    "reconstruct_imports",       # GB-20
}


class MetricsCollector:
    """Collects analysis metrics for before/after comparison."""

    def __init__(self):
        self.tool_calls: Dict[str, int] = {}
        self.tool_successes: Dict[str, int] = {}
        self.tool_failures: Dict[str, int] = {}
        self.findings: Dict[str, int] = {}
        self.total_tool_calls = 0
        self.total_successes = 0
        self.total_failures = 0
        self.total_findings = 0

    def record_tool_call(self, name: str, success: bool):
        """Record a tool call with success/failure status."""
        self.total_tool_calls += 1
        self.tool_calls[name] = self.tool_calls.get(name, 0) + 1

        if success:
            self.total_successes += 1
            self.tool_successes[name] = self.tool_successes.get(name, 0) + 1
        else:
            self.total_failures += 1
            self.tool_failures[name] = self.tool_failures.get(name, 0) + 1

    def record_finding(self, category: str):
        """Record a notebook finding by category."""
        self.total_findings += 1
        self.findings[category] = self.findings.get(category, 0) + 1

    def compute_summary(self) -> Dict[str, Any]:
        """Compute derived metrics."""
        gb_tool_calls = sum(
            count for name, count in self.tool_calls.items()
            if name in GB_ENHANCED_TOOLS
        )

        return {
            "total_tool_calls": self.total_tool_calls,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "total_findings": self.total_findings,
            "error_rate": round(self.total_failures / max(self.total_tool_calls, 1), 4),
            "findings_per_tool_call": round(self.total_findings / max(self.total_tool_calls, 1), 4),
            "gb_tool_calls": gb_tool_calls,
            "gb_tool_utilization_pct": round(gb_tool_calls / max(self.total_tool_calls, 1) * 100, 1),
            "unique_tools_used": len(self.tool_calls),
            "unique_gb_tools_used": len([t for t in self.tool_calls if t in GB_ENHANCED_TOOLS]),
            "tool_call_counts": dict(sorted(self.tool_calls.items(), key=lambda x: -x[1])),
            "finding_counts": dict(sorted(self.findings.items(), key=lambda x: -x[1])),
        }

    def save(self, job_dir: str):
        """Write metrics.json to the job's artifacts directory."""
        artifacts_dir = Path(job_dir) / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        metrics_path = artifacts_dir / "metrics.json"
        data = self.compute_summary()

        try:
            with open(metrics_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Metrics saved to {metrics_path}")
        except IOError as e:
            logger.warning(f"Failed to save metrics: {e}")
