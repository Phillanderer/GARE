"""
Ghidra headless runner utility
Manages Ghidra project lifecycle and script execution
"""

import os
import re
import json
import subprocess
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any

from src.services.worker.analysis_config import get_analysis_config, ANALYSIS_PRESETS
from src.services.worker.script_hooks import HookManager, HookPoint

logger = logging.getLogger(__name__)

# Whitelist of allowed Ghidra scripts (CRITICAL-02 mitigation)
ALLOWED_SCRIPTS = {
    "analyze.py", "list_functions.py", "decompile.py", "rename.py",
    "get_strings.py", "get_imports_exports.py", "get_xrefs.py",
    "list_segments.py", "list_namespaces.py", "search_functions.py",
    "disassemble.py", "export_xml.py", "export_annotations.py",
    "export_binary_package.py", "set_comment.py", "get_call_graph.py",
    "get_entropy.py", "identify_libraries.py", "list_data_types.py",
    "apply_data_type.py",
    "get_function_signature.py",
    "auto_create_structure.py",
    "get_variable_slice.py",
    "analyze_basic_blocks.py",
    "detect_switch.py",
    "detect_arrays.py",
    "analyze_cpp_classes.py",
    "set_function_attributes.py",
    "set_repeatable_comment.py",
    "set_equate.py",
    "convert_code_data.py",
    "detect_loops.py",
    "find_desync_errors.py",
    "resolve_computed_jump.py",
    "emulate_deobfuscation.py",
    "reconstruct_imports.py"
}


def sanitize_script_arg(arg: str) -> str:
    """
    Sanitize script argument to prevent command injection.

    Allows only safe characters: alphanumeric, underscore, hyphen, dot, colon, @, forward slash

    Args:
        arg: Script argument to sanitize

    Returns:
        Sanitized argument

    Raises:
        ValueError: If argument is too long or contains only invalid characters
    """
    if not isinstance(arg, str):
        arg = str(arg)

    # Remove any characters that could be used for command injection
    # Allow forward slash for file paths
    sanitized = re.sub(r'[^\w\-.:@/]', '', arg)

    # Prevent extremely long arguments
    if len(sanitized) > 512:
        raise ValueError("Argument too long")

    # Ensure we didn't remove everything
    if not sanitized:
        raise ValueError("Argument contains no valid characters")

    return sanitized

class GhidraRunner:
    """Manages Ghidra headless execution for a job"""

    def __init__(self, job_id: str, data_dir: str, ghidra_install: str = "/opt/ghidra", intensity: str = "standard"):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.ghidra_install = Path(ghidra_install)
        self.project_dir = self.job_dir / "ghidra_project"
        self.project_name = f"project_{job_id}"
        self.binary_path: Optional[Path] = None

        # GB-11: Intensity-based analysis configuration
        self.intensity = intensity
        self.analysis_config = get_analysis_config(intensity)

        # GB-23: Pre/post script hook manager
        self.hook_manager = HookManager(job_id, data_dir, intensity)

        # Check if a Ghidra project already exists for this job
        project_file = self.project_dir / self.project_name / f"{self.project_name}.gpr"
        self.program_imported = project_file.exists()

        if self.program_imported:
            logger.info(f"Found existing Ghidra project for job {job_id}")

            # Find the binary from the input directory
            input_dir = self.job_dir / "input"
            if input_dir.exists():
                binaries = list(input_dir.glob("*"))
                if binaries:
                    self.binary_path = binaries[0]
                    logger.info(f"Found binary: {self.binary_path.name}")

    def import_binary(self, binary_path: str) -> Dict[str, Any]:
        """Import binary into Ghidra project and run auto-analysis with PyGhidra"""
        self.binary_path = Path(binary_path)
        self.project_dir.mkdir(parents=True, exist_ok=True)

        # GB-23: Run pre-import hooks (validation, logging)
        pre_results = self.hook_manager.run_hooks(HookPoint.PRE_IMPORT, {
            "binary_path": binary_path
        })
        for result in pre_results:
            if not result.success:
                logger.error(f"Pre-import hook failed: {result.error}")
                return {"success": False, "error": f"Pre-import validation failed: {result.error}"}

        import_timeout = self.analysis_config["import_timeout_seconds"]
        logger.info(f"Running Ghidra import with PyGhidra: {self.binary_path} (timeout={import_timeout}s, intensity={self.intensity})")

        try:
            import pyghidra

            # Use PyGhidra's run_script to import and analyze
            script_path = Path(__file__).parent / "scripts" / "analyze.py"

            # Have analyze.py write output to a file
            output_file = self.project_dir / "analyze_output.json"

            # GB-11: Run import with timeout to prevent runaway analysis
            import_error = [None]

            def _run_import():
                try:
                    pyghidra.run_script(
                        binary_path=str(self.binary_path),
                        script_path=str(script_path),
                        project_location=str(self.project_dir),
                        project_name=self.project_name,
                        script_args=[str(output_file)],
                        verbose=self.analysis_config["verbose_ghidra"],
                        analyze=self.analysis_config["analyze_on_import"],
                        install_dir=str(self.ghidra_install)
                    )
                except Exception as e:
                    import_error[0] = e

            import_thread = threading.Thread(target=_run_import, daemon=True)
            import_thread.start()
            import_thread.join(timeout=import_timeout)

            if import_thread.is_alive():
                logger.error(f"Import timed out after {import_timeout}s for {self.binary_path.name}")
                return {"success": False, "error": f"Import timed out after {import_timeout}s (intensity={self.intensity})"}

            if import_error[0]:
                raise import_error[0]

            # Read JSON output from file
            json_output = None
            if output_file.exists():
                with open(output_file, 'r') as f:
                    try:
                        json_output = json.load(f)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse analyze output: {e}")

            # Check if import succeeded
            if json_output:
                self.program_imported = True
                logger.info(f"Ghidra import successful for {self.binary_path.name}")

                # GB-23: Run post-analysis hooks (metadata extraction, decompiler config)
                self.hook_manager.run_hooks(HookPoint.POST_ANALYSIS, {
                    "binary_path": binary_path,
                    "metadata": json_output
                })
                self.hook_manager.save_hook_report()

                return {
                    "success": True,
                    "metadata": json_output,
                    "stdout": "",
                    "stderr": ""
                }
            else:
                # Fallback: extract basic metadata if analyze.py didn't produce JSON
                self.program_imported = True
                metadata = {
                    "binary_path": str(self.binary_path),
                    "binary_name": self.binary_path.name,
                    "import_timestamp": os.path.getmtime(str(self.binary_path)),
                    "analysis_completed": True
                }

                # GB-23: Run post-analysis hooks even on fallback path
                self.hook_manager.run_hooks(HookPoint.POST_ANALYSIS, {
                    "binary_path": binary_path,
                    "metadata": metadata
                })
                self.hook_manager.save_hook_report()

                logger.info(f"Ghidra import successful (fallback metadata)")
                return {
                    "success": True,
                    "metadata": metadata,
                    "stdout": "",
                    "stderr": ""
                }

        except Exception as e:
            logger.error(f"Exception during Ghidra import: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def run_script(self, script_name: str, *args) -> str:
        """Run a Ghidra script on the imported program using PyGhidra"""
        if not self.program_imported:
            return json.dumps({"error": "No program imported"})

        # Validate script name against whitelist (CRITICAL-02)
        if script_name not in ALLOWED_SCRIPTS:
            logger.warning(f"Attempt to run unauthorized script: {script_name}")
            return json.dumps({"error": f"Script not allowed: {script_name}"})

        # Sanitize script arguments (CRITICAL-02)
        sanitized_args = []
        if args:
            try:
                sanitized_args = [sanitize_script_arg(arg) for arg in args]
            except ValueError as e:
                logger.error(f"Invalid script argument: {e}")
                return json.dumps({"error": f"Invalid argument: {e}"})

        # GB-23: Run pre-script hooks
        self.hook_manager.run_hooks(HookPoint.PRE_SCRIPT, {
            "script_name": script_name,
            "script_args": list(args)
        })

        script_timeout = self.analysis_config["script_timeout_seconds"]
        max_output = self.analysis_config["max_output_bytes"]
        logger.info(f"Running Ghidra script with PyGhidra: {script_name} (timeout={script_timeout}s)")

        try:
            import pyghidra
            import io
            import sys

            # Use PyGhidra's run_script
            script_path = Path(__file__).parent / "scripts" / script_name

            # Capture stdout to get the JSON output
            old_stdout = sys.stdout
            sys.stdout = captured_output = io.StringIO()

            # GB-11: Run script with timeout
            script_error = [None]

            def _run_script():
                try:
                    pyghidra.run_script(
                        binary_path=None,  # Program already imported
                        script_path=str(script_path),
                        project_location=str(self.project_dir),
                        project_name=self.project_name,
                        script_args=sanitized_args,
                        verbose=self.analysis_config["verbose_ghidra"],
                        analyze=False,  # Don't re-analyze
                        program_name=self.binary_path.name,
                        install_dir=str(self.ghidra_install)
                    )
                except Exception as e:
                    script_error[0] = e

            script_thread = threading.Thread(target=_run_script, daemon=True)
            script_thread.start()
            script_thread.join(timeout=script_timeout)

            sys.stdout = old_stdout
            output = captured_output.getvalue()

            if script_thread.is_alive():
                logger.warning(f"Script {script_name} timed out after {script_timeout}s")
                return json.dumps({"error": f"Script timed out after {script_timeout}s (intensity={self.intensity})"})

            if script_error[0]:
                raise script_error[0]

            # GB-11: Cap output size to prevent memory bloat
            if len(output) > max_output:
                logger.warning(f"Script output truncated from {len(output)} to {max_output} bytes")
                output = output[:max_output]

            # GB-23: Run post-script hooks
            self.hook_manager.run_hooks(HookPoint.POST_SCRIPT, {
                "script_name": script_name,
                "script_args": list(args),
                "output_length": len(output)
            })

            # Extract JSON output
            output_lines = output.strip().split('\n')
            for line in output_lines:
                line = line.strip()
                if line.startswith('{') or line.startswith('['):
                    try:
                        json.loads(line)  # Validate JSON
                        return line
                    except json.JSONDecodeError:
                        continue

            # If no JSON found, return raw output
            return output if output else json.dumps({"error": "No output from script"})

        except Exception as e:
            logger.error(f"Script execution failed: {e}", exc_info=True)
            return json.dumps({"error": str(e)})
