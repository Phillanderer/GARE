"""
Agent runner - coordinates LLM-driven reverse engineering analysis
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from src.utils.timezone import utc_now, format_display

from src.services.agent.planner import AnalysisPlanner, AnalysisStep
from src.services.agent.report_generator import ReportGenerator
from src.services.agent.prompts import SYSTEM_PROMPT, ANALYSIS_STRATEGY, sanitize_for_llm

# Import LLM client based on provider
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")

if LLM_PROVIDER == "anthropic":
    from anthropic import Anthropic
elif LLM_PROVIDER == "openai":
    from openai import OpenAI

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


class AgentRunner:
    """Main agent that performs autonomous reverse engineering"""

    def __init__(self, job_id: str, data_dir: str, mcp_server_url: str):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.mcp_server_url = mcp_server_url

        self.planner = AnalysisPlanner()
        self.report_gen = ReportGenerator(job_id)

        self.metadata: Dict[str, Any] = {}
        self.tool_call_count = 0
        self.max_tool_calls = int(os.environ.get("MAX_TOOL_CALLS", 100))
        self.auto_approve_renames = os.environ.get("AUTO_APPROVE_RENAMES", "false").lower() == "true"

        # Initialize LLM client
        api_key = os.environ.get("API_KEY")
        base_url = os.environ.get("BASE_URL")  # Optional: for local LLM servers
        model_name = os.environ.get("MODEL_NAME")
        if not model_name:
            raise ValueError("MODEL_NAME environment variable must be set (model identifier from your LLM provider)")

        if LLM_PROVIDER == "anthropic":
            if base_url:
                self.client = Anthropic(api_key=api_key, base_url=base_url)
            else:
                self.client = Anthropic(api_key=api_key)
            self.model = model_name
        elif LLM_PROVIDER == "openai":
            if base_url:
                self.client = OpenAI(api_key=api_key, base_url=base_url)
            else:
                self.client = OpenAI(api_key=api_key)
            self.model = model_name
        else:
            raise ValueError(f"Unsupported LLM provider: {LLM_PROVIDER}")

        logger.info(f"Agent initialized for job {job_id} using {LLM_PROVIDER} {self.model}")

    def call_mcp_tool(self, tool_name: str, **kwargs) -> Any:
        """Call an MCP tool via the MCP server"""
        self.tool_call_count += 1

        if self.tool_call_count > self.max_tool_calls:
            logger.warning(f"Max tool calls ({self.max_tool_calls}) reached")
            return {"error": "Max tool calls reached"}

        logger.info(f"Tool call #{self.tool_call_count}: {tool_name}({kwargs})")

        try:
            # Call MCP server using Python subprocess to invoke the MCP tool
            mcp_cmd = [
                "python3",
                str(Path(__file__).parent.parent / "mcp_server" / "server.py"),
                "--job-id", self.job_id,
                "--worker-url", os.environ.get("WORKER_URL", "http://worker:8001")
            ]

            # For this simplified implementation, we'll call the worker directly
            # In production, use proper MCP protocol communication
            import sys
            sys.path.append(str(Path(__file__).parent.parent / "mcp_server"))
            from tools import GhidraTools

            tools = GhidraTools(os.environ.get("WORKER_URL", "http://worker:8001"), self.job_id)
            tool_method = getattr(tools, tool_name, None)

            if tool_method:
                result = tool_method(**kwargs)
                logger.info(f"Tool result: {str(result)[:200]}...")
                return result
            else:
                logger.error(f"Tool not found: {tool_name}")
                return {"error": f"Tool not found: {tool_name}"}

        except Exception as e:
            logger.error(f"Tool call failed: {e}")
            return {"error": str(e)}

    def run_analysis(self) -> Dict[str, Any]:
        """Run the complete analysis workflow"""
        logger.info(f"Starting analysis for job {self.job_id}")

        # Create analysis plan
        plan = self.planner.create_plan()
        logger.info(f"Created analysis plan with {len(plan)} steps")

        # Execute plan steps
        try:
            # Step 1: Get functions overview
            logger.info("Step 1: Getting functions overview")
            functions_result = self.call_mcp_tool("list_methods", offset=0, limit=100)
            self.planner.add_finding("functions", functions_result)
            self.planner.mark_completed("list_functions", functions_result)

            # Step 2: Get strings
            logger.info("Step 2: Extracting strings")
            strings_result = self.call_mcp_tool("list_strings", offset=0, limit=100)
            self.planner.add_finding("strings", strings_result)
            self.planner.mark_completed("get_strings", strings_result)

            # Step 3: Get imports
            logger.info("Step 3: Getting imports")
            imports_result = self.call_mcp_tool("list_imports", offset=0, limit=100)
            self.planner.add_finding("imports", imports_result)
            self.planner.mark_completed("get_imports", imports_result)

            # Step 4: Get exports
            logger.info("Step 4: Getting exports")
            exports_result = self.call_mcp_tool("list_exports", offset=0, limit=100)
            self.planner.add_finding("exports", exports_result)
            self.planner.mark_completed("get_exports", exports_result)

            # Step 5: Get segments
            logger.info("Step 5: Getting memory segments")
            segments_result = self.call_mcp_tool("list_segments", offset=0, limit=50)
            self.planner.add_finding("segments", segments_result)

            # Step 6: Analyze key functions
            logger.info("Step 6: Analyzing key functions")
            analyzed_functions = self._analyze_key_functions(functions_result)
            self.planner.add_finding("analyzed_functions", analyzed_functions)
            self.planner.mark_completed("analyze_entry_points")

            # Step 7: Rename functions (if enabled)
            renamed_functions = []
            if self.auto_approve_renames:
                logger.info("Step 7: Renaming functions")
                renamed_functions = self._rename_functions(analyzed_functions)
                self.planner.add_finding("renamed_functions", renamed_functions)
            else:
                logger.info("Step 7: Skipping function renaming (AUTO_APPROVE_RENAMES=false)")

            self.planner.mark_completed("rename_functions", renamed_functions)

            # Finalize findings
            self.planner.findings["tool_call_count"] = self.tool_call_count
            self.planner.findings["analysis_steps"] = [
                {"name": step.name, "completed": step.completed}
                for step in self.planner.steps
            ]

            logger.info("Analysis complete!")
            return self.planner.findings

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            raise

    def _analyze_key_functions(self, functions_list: List) -> List[Dict[str, Any]]:
        """Analyze key functions in detail"""
        analyzed = []

        # Parse function list
        function_names = []
        for func in functions_list[:20]:  # Analyze top 20
            func_str = str(func)
            if ':' in func_str:
                parts = func_str.split(':', 1)
                address = parts[0].strip()
                name = parts[1].strip()
                function_names.append({"name": name, "address": address})

        logger.info(f"Analyzing {len(function_names)} key functions")

        for func_info in function_names:
            try:
                name = func_info["name"]
                address = func_info["address"]

                logger.info(f"Decompiling {name}")
                decompiled = self.call_mcp_tool("decompile_function", name=name)

                # Sanitize decompiled code before analysis (CRITICAL-05)
                decompiled_safe = sanitize_for_llm(str(decompiled))

                # Simple analysis - look for keywords
                description = self._generate_function_description(name, decompiled_safe)

                # Store sanitized version in analysis
                analyzed.append({
                    "name": name,
                    "address": address,
                    "decompilation": decompiled_safe[:500],
                    "description": description
                })

            except Exception as e:
                logger.warning(f"Failed to analyze function {name}: {e}")
                continue

        return analyzed

    def _generate_function_description(self, name: str, decompiled: Any) -> str:
        """Generate a simple description of function purpose"""
        decompiled_str = str(decompiled).lower()

        # Pattern matching for common behaviors
        if any(kw in decompiled_str for kw in ['socket', 'connect', 'send']):
            return "Network communication function"
        elif any(kw in decompiled_str for kw in ['fopen', 'fread', 'fwrite', 'file']):
            return "File I/O operation function"
        elif any(kw in decompiled_str for kw in ['malloc', 'alloc', 'free']):
            return "Memory management function"
        elif any(kw in decompiled_str for kw in ['printf', 'puts', 'print']):
            return "Output/display function"
        elif any(kw in decompiled_str for kw in ['scanf', 'gets', 'read', 'input']):
            return "Input handling function"
        elif any(kw in decompiled_str for kw in ['strcmp', 'strncmp', 'check']):
            return "Comparison or validation function"
        elif 'main' in name.lower():
            return "Main program entry point"
        elif 'init' in name.lower():
            return "Initialization function"
        else:
            return "General utility function"

    def _rename_functions(self, analyzed_functions: List[Dict]) -> List[Dict[str, str]]:
        """Rename functions with descriptive names"""
        renamed = []

        for func in analyzed_functions:
            old_name = func.get("name", "")

            # Only rename functions starting with FUN_
            if not old_name.startswith("FUN_"):
                continue

            # Generate new name based on description
            desc = func.get("description", "").lower()
            if "network" in desc:
                new_name = f"VIBE_network_{old_name[4:]}"
            elif "file" in desc:
                new_name = f"VIBE_file_io_{old_name[4:]}"
            elif "memory" in desc:
                new_name = f"VIBE_memory_{old_name[4:]}"
            elif "input" in desc:
                new_name = f"VIBE_input_{old_name[4:]}"
            elif "output" in desc:
                new_name = f"VIBE_output_{old_name[4:]}"
            else:
                new_name = f"VIBE_func_{old_name[4:]}"

            logger.info(f"Renaming {old_name} -> {new_name}")

            try:
                result = self.call_mcp_tool("rename_function", old_name=old_name, new_name=new_name)
                renamed.append({"old_name": old_name, "new_name": new_name, "result": str(result)})
            except Exception as e:
                logger.warning(f"Failed to rename {old_name}: {e}")

        return renamed

    def generate_report(self, findings: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """Generate the final analysis report"""
        logger.info("Generating report")
        report = self.report_gen.generate(findings, metadata)
        return report


def main():
    """Main entry point for agent runner"""
    import argparse

    parser = argparse.ArgumentParser(description="Run reverse engineering analysis agent")
    parser.add_argument("--job-id", required=True, help="Job ID to analyze")
    parser.add_argument("--data-dir", default="/app/data", help="Data directory")
    parser.add_argument("--metadata-file", help="Path to metadata JSON file")
    parser.add_argument("--auto-mode", action="store_true", help="Run in automated mode (no user prompts)")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM-driven analysis (enabled by default)")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM and use legacy agent")
    parser.add_argument("--multi-agent", action="store_true", help="Use multi-agent analysis with specialized personas (GB-21)")
    parser.add_argument("--intensity", default="standard", choices=["quick", "standard", "deep"],
                        help="Analysis intensity level")
    args = parser.parse_args()

    if args.auto_mode:
        logger.info("Running in automated mode")

    # Load metadata
    metadata = {}
    if args.metadata_file and Path(args.metadata_file).exists():
        with open(args.metadata_file, 'r') as f:
            metadata = json.load(f)

    # Choose agent type
    if args.multi_agent:
        # GB-21: Multi-agent analysis with specialized personas
        logger.info(f"Using multi-agent analysis (intensity={args.intensity})")
        from src.services.agent.multi_agent import MultiAgentOrchestrator

        worker_url = os.environ.get("WORKER_URL", "http://localhost:8001")
        orchestrator = MultiAgentOrchestrator(args.job_id, args.data_dir, worker_url, intensity=args.intensity)

        # Run multi-agent analysis
        findings = orchestrator.run_multi_agent_analysis()

        # Generate report from merged conversation
        report = generate_llm_report(findings, metadata, args.job_id, args.data_dir)

    elif not args.no_llm:
        logger.info(f"Using LLM-driven agent (intensity={args.intensity})")
        from llm_agent import LLMAgent

        worker_url = os.environ.get("WORKER_URL", "http://localhost:8001")
        agent = LLMAgent(args.job_id, args.data_dir, worker_url, intensity=args.intensity)

        # Run LLM-driven analysis
        findings = agent.run_autonomous_analysis()

        # Save metrics
        job_dir = str(Path(args.data_dir) / "jobs" / args.job_id)
        agent.metrics.save(job_dir)
        findings["metrics"] = agent.metrics.compute_summary()

        # Generate report from conversation
        report = generate_llm_report(findings, metadata, args.job_id, args.data_dir)

    else:
        logger.info("Using legacy hardcoded agent")
        # Initialize legacy agent
        mcp_server_url = os.environ.get("MCP_SERVER_URL", "http://mcp_server:8002")
        agent = AgentRunner(args.job_id, args.data_dir, mcp_server_url)
        agent.metadata = metadata

        # Run analysis
        findings = agent.run_analysis()

        # Generate report
        report = agent.generate_report(findings, metadata)

    # Save report (even on partial failure, so the user can inspect what we
    # got before the error). Then propagate a non-zero exit if the agent loop
    # raised an exception — otherwise the orchestrator silently marks the job
    # COMPLETED with empty findings (historical bug).
    report_dir = Path(args.data_dir) / "jobs" / args.job_id / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.md"

    with open(report_path, 'w') as f:
        f.write(report)

    logger.info(f"Report saved to {report_path}")

    agent_error = findings.get("error") if isinstance(findings, dict) else None
    if agent_error:
        logger.error(f"Analysis failed: {agent_error}")
        print(f"ERROR: Analysis failed: {agent_error}", file=sys.stderr)
        sys.exit(1)

    print(f"SUCCESS: Report generated at {report_path}")


def generate_llm_report(findings: Dict[str, Any], metadata: Dict[str, Any], job_id: str, data_dir: str = "/app/data") -> str:
    """Generate factual report from analysis, incorporating all data sources"""
    conversation = findings.get("conversation", [])
    job_dir = Path(data_dir) / "jobs" / job_id / "artifacts"

    # --- Load notebook.json ---
    notebook_entries = []
    notebook_path = job_dir / "notebook.json"
    if notebook_path.exists():
        try:
            with open(notebook_path, 'r') as f:
                notebook_data = json.load(f)
                notebook_entries = notebook_data.get("entries", [])
            logger.info(f"Loaded {len(notebook_entries)} notebook entries")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load notebook.json: {e}")

    # --- Enrich metadata from metadata.json if sparse ---
    metadata_path = job_dir / "metadata.json"
    if metadata_path.exists() and not metadata.get("language"):
        try:
            with open(metadata_path, 'r') as f:
                disk_metadata = json.load(f)
            # Merge: disk values fill in missing keys
            for key, val in disk_metadata.items():
                if key not in metadata or metadata[key] in (None, "", "unknown"):
                    metadata[key] = val
            logger.info("Enriched metadata from metadata.json")
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load metadata.json: {e}")

    # --- Extract findings from conversation ---
    functions_renamed = []
    decompiled_snippets = []

    for msg in conversation:
        role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)
        if role != "assistant":
            continue

        content = msg.get("content", []) if isinstance(msg, dict) else getattr(msg, "content", [])
        if isinstance(content, str):
            continue

        for block in content:
            # Handle both Anthropic SDK objects (ToolUseBlock) and plain dicts
            block_type = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)

            if block_type == "tool_use":
                name = block.get("name") if isinstance(block, dict) else getattr(block, "name", None)
                inputs = block.get("input", {}) if isinstance(block, dict) else getattr(block, "input", {})

                if name == "rename_function":
                    old_name = inputs.get("old_name") if isinstance(inputs, dict) else getattr(inputs, "old_name", None)
                    new_name = inputs.get("new_name") if isinstance(inputs, dict) else getattr(inputs, "new_name", None)
                    if old_name and new_name:
                        functions_renamed.append(f"{old_name} -> {new_name}")

                elif name == "decompile_function":
                    fn = inputs.get("name") if isinstance(inputs, dict) else getattr(inputs, "name", None)
                    if fn:
                        decompiled_snippets.append(fn)

    # --- Build report ---
    report_parts = [
        "# Binary Analysis Report",
        "",
        f"**Job ID**: {job_id}",
        f"**Analysis Date**: {format_display(fmt='%Y-%m-%d %H:%M:%S %Z')}",
        f"**Binary**: {metadata.get('name', metadata.get('binary_name', 'unknown'))}",
        f"**Architecture**: {metadata.get('language', 'unknown')}",
        f"**Format**: {metadata.get('executable_format', 'unknown')}",
        f"**Compiler**: {metadata.get('compiler', 'unknown')}",
        "",
        "---",
        "",
        "## Analysis Summary",
        "",
        f"Automated static analysis completed using Ghidra autonomous tooling.",
        f"Analysis performed in **{findings.get('iterations', 0)} iterations** with **{findings.get('tool_call_count', 0)} tool calls**.",
        "",
    ]

    # --- Notebook findings by category ---
    if notebook_entries:
        report_parts.append("## Agent Findings")
        report_parts.append("")

        # Group entries by category
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for entry in notebook_entries:
            cat = entry.get("category", "note")
            by_category.setdefault(cat, []).append(entry)

        category_labels = {
            "capability": "Capabilities",
            "crypto": "Cryptographic Indicators",
            "c2": "Command & Control",
            "persistence": "Persistence Mechanisms",
            "evasion": "Evasion Techniques",
            "ioc": "Indicators of Compromise",
            "note": "General Notes",
        }

        for cat, entries in by_category.items():
            label = category_labels.get(cat, cat.title())
            report_parts.append(f"### {label}")
            report_parts.append("")
            for entry in entries:
                report_parts.append(f"- {entry.get('content', '')}")
            report_parts.append("")

    # --- Functions renamed ---
    if functions_renamed:
        report_parts.append(f"## Functions Renamed ({len(functions_renamed)})")
        report_parts.append("")
        for rename in functions_renamed[:50]:
            report_parts.append(f"- `{rename}`")
        if len(functions_renamed) > 50:
            report_parts.append(f"- ... and {len(functions_renamed) - 50} more")
        report_parts.append("")

    # --- Functions decompiled ---
    if decompiled_snippets:
        report_parts.append(f"## Functions Decompiled ({len(decompiled_snippets)})")
        report_parts.append("")
        for fn in decompiled_snippets[:50]:
            report_parts.append(f"- `{fn}`")
        if len(decompiled_snippets) > 50:
            report_parts.append(f"- ... and {len(decompiled_snippets) - 50} more")
        report_parts.append("")

    # --- Analysis Metrics ---
    metrics = findings.get("metrics")
    if metrics:
        report_parts.extend([
            "## Analysis Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Tool Calls | {metrics.get('total_tool_calls', 0)} |",
            f"| Successful | {metrics.get('total_successes', 0)} |",
            f"| Failed | {metrics.get('total_failures', 0)} |",
            f"| Error Rate | {metrics.get('error_rate', 0):.1%} |",
            f"| Notebook Findings | {metrics.get('total_findings', 0)} |",
            f"| Findings per Tool Call | {metrics.get('findings_per_tool_call', 0):.3f} |",
            f"| Unique Tools Used | {metrics.get('unique_tools_used', 0)} |",
            f"| GB-Enhanced Tool Calls | {metrics.get('gb_tool_calls', 0)} |",
            f"| GB Tool Utilization | {metrics.get('gb_tool_utilization_pct', 0):.1f}% |",
            "",
        ])

    # --- Metadata block ---
    report_parts.extend([
        "---",
        "",
        "## Binary Metadata",
        "",
        "```json",
        json.dumps(metadata, indent=2),
        "```",
        "",
        "---",
        "",
        f"**Report Generated**: {format_display(fmt='%Y-%m-%d %H:%M:%S %Z')}",
        f"**Analysis Engine**: LLM via MCP tooling"
    ])

    return "\n".join(report_parts)


if __name__ == "__main__":
    main()
