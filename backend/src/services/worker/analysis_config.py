"""
Analysis configuration for intensity-based resource control (GB-11)

Maps GARE intensity presets to Ghidra analysis parameters.
Book Reference: Ch. 16 (Ghidra in Headless Mode, pp. 341-360)
  - analysisTimeoutPerFile: prevents runaway analysis
  - max-cpu: limits thread count for resource control
  - readOnly: reduces disk I/O for stateless analysis

Since GARE uses PyGhidra (not analyzeHeadless CLI), these concepts are
adapted to Python-level timeouts and configuration parameters.
"""

import logging

logger = logging.getLogger(__name__)


# Intensity preset definitions
# Each maps to analysis behavior parameters
ANALYSIS_PRESETS = {
    "quick": {
        "import_timeout_seconds": 120,      # Max time for initial binary import + auto-analysis
        "script_timeout_seconds": 30,       # Max time per script execution
        "max_output_bytes": 500_000,        # Cap script output to prevent memory bloat
        "analyze_on_import": True,          # Run auto-analysis during import
        "verbose_ghidra": False,            # Suppress Ghidra verbose output
        "description": "Fast overview — limited analysis depth, strict timeouts"
    },
    "standard": {
        "import_timeout_seconds": 300,
        "script_timeout_seconds": 60,
        "max_output_bytes": 2_000_000,
        "analyze_on_import": True,
        "verbose_ghidra": False,
        "description": "Balanced — thorough analysis with reasonable timeouts"
    },
    "deep": {
        "import_timeout_seconds": 900,
        "script_timeout_seconds": 180,
        "max_output_bytes": 10_000_000,
        "analyze_on_import": True,
        "verbose_ghidra": True,             # Capture detailed Ghidra logs for deep analysis
        "description": "Exhaustive — maximum analysis depth, relaxed timeouts"
    }
}


def get_analysis_config(intensity: str) -> dict:
    """
    Get analysis configuration for the given intensity level.

    Args:
        intensity: One of 'quick', 'standard', 'deep'

    Returns:
        Configuration dictionary with timeout and resource parameters
    """
    config = ANALYSIS_PRESETS.get(intensity, ANALYSIS_PRESETS["standard"])
    logger.info(f"Analysis config for intensity '{intensity}': {config['description']}")
    return config


def get_import_timeout(intensity: str) -> int:
    """Get the import/analysis timeout in seconds for the given intensity"""
    return get_analysis_config(intensity)["import_timeout_seconds"]


def get_script_timeout(intensity: str) -> int:
    """Get the per-script execution timeout in seconds for the given intensity"""
    return get_analysis_config(intensity)["script_timeout_seconds"]


def get_max_output_bytes(intensity: str) -> int:
    """Get the maximum script output size in bytes for the given intensity"""
    return get_analysis_config(intensity)["max_output_bytes"]
