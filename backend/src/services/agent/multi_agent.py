"""
Multi-Agent Analysis Framework (GB-21)

Orchestrates multiple specialized agent personas that analyze the same binary
with different focus areas. Each agent records findings to the shared notebook,
and results are merged into a unified report.

Book Reference: Ch. 11 (Collaborative SRE, pp. 217-240)
  - Multiple analysts with different specializations work on the same binary
  - Shared project with version-controlled annotations
  - Audit trail showing which analyst discovered each finding

Implementation:
  - Agents run sequentially (share same Ghidra project via PyGhidra)
  - Each agent has a focused system prompt and reduced iteration budget
  - All agents write to the same notebook with agent attribution
  - Orchestrator merges findings and produces combined report
"""

import os
import json
import logging
from typing import Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


# Agent persona definitions
AGENT_PERSONAS = {
    "triage": {
        "name": "Triage Agent",
        "description": "Quick overview and classification",
        "iteration_fraction": 0.15,  # 15% of total iterations
        "tool_call_fraction": 0.15,
        "system_prompt_extension": """You are the TRIAGE agent. Your job is to quickly classify this binary and set up context for subsequent specialist agents.

Your specific tasks:
1. Run get_entropy() to check for packing
2. Run identify_libraries() to separate user code from library code
3. Run map_mitre_attack() to get ATT&CK triage
4. Run extract_iocs() to pull indicators
5. List functions, strings, imports for overview
6. Use notebook_append() to record: binary type, packing status, platform, key imports, threat level estimate

Do NOT decompile functions or do deep analysis — leave that for the specialist agents.
Record ALL findings with notebook_append() using category 'note' and prefix your content with [TRIAGE]."""
    },

    "security_auditor": {
        "name": "Security Auditor",
        "description": "Security-focused analysis: vulnerabilities, crypto, evasion",
        "iteration_fraction": 0.35,
        "tool_call_fraction": 0.35,
        "system_prompt_extension": """You are the SECURITY AUDITOR agent. Focus exclusively on security-relevant aspects.

Your specific tasks:
1. Read the notebook first (notebook_read) to see what the triage agent found
2. Identify security-critical functions: crypto routines, network operations, privilege escalation
3. Decompile and analyze suspicious functions for vulnerabilities
4. Trace data flow for user-controlled inputs using get_variable_slice()
5. Check for anti-analysis techniques using find_desync_errors()
6. If the binary appears packed, use reconstruct_imports() to find hidden APIs
7. Look for C2 communication patterns, hardcoded keys, persistence mechanisms

Record ALL findings with notebook_append() using appropriate categories (c2, crypto, evasion, persistence).
Prefix your content with [SECURITY]."""
    },

    "code_analyst": {
        "name": "Code Analyst",
        "description": "Deep code analysis: function naming, structure recovery, control flow",
        "iteration_fraction": 0.50,
        "tool_call_fraction": 0.50,
        "system_prompt_extension": """You are the CODE ANALYST agent. Focus on understanding program structure and behavior.

Your specific tasks:
1. Read the notebook first (notebook_read) to see what previous agents found
2. Decompile all significant user functions (skip library code identified by triage)
3. Rename functions with descriptive VIBE_ prefix names
4. Use analyze_basic_blocks() and detect_loops() to understand control flow
5. Use auto_create_structure() on functions with pointer arithmetic
6. Use detect_switch() on functions with complex conditionals
7. Use detect_arrays() on functions with scaling operations
8. Add comments to document function purposes
9. Use set_repeatable_comment() for important API wrappers and security-critical functions
10. Build the complete call graph with get_call_graph(depth=2) for key functions

Record ALL findings with notebook_append() using category 'capability' or 'note'.
Prefix your content with [CODE]."""
    }
}


class MultiAgentOrchestrator:
    """Orchestrates multiple specialized agents analyzing the same binary"""

    def __init__(self, job_id: str, data_dir: str, worker_url: str, intensity: str = "standard"):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.worker_url = worker_url
        self.intensity = intensity
        self.agent_results: Dict[str, Dict] = {}

        logger.info(f"MultiAgentOrchestrator initialized for job {job_id} (intensity={intensity})")

    def _log_to_job(self, message: str):
        """Write log message to job log file"""
        try:
            from src.utils.timezone import utc_now
            log_file = self.job_dir / "logs" / "job.log"
            timestamp = utc_now().isoformat()
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] [ORCHESTRATOR] {message}\n")
        except Exception:
            pass

    def get_agent_sequence(self) -> List[str]:
        """Return the ordered sequence of agent personas to run"""
        return ["triage", "security_auditor", "code_analyst"]

    def run_multi_agent_analysis(self) -> Dict[str, Any]:
        """Run all agent personas sequentially and merge results"""
        from src.services.agent.llm_agent import LLMAgent

        sequence = self.get_agent_sequence()
        self._log_to_job(f"Starting multi-agent analysis with {len(sequence)} agents: {', '.join(sequence)}")

        # Get base intensity presets
        base_presets = LLMAgent.INTENSITY_PRESETS.get(self.intensity, LLMAgent.INTENSITY_PRESETS["standard"])
        total_iterations = base_presets["max_iterations"]
        total_tool_calls = base_presets["max_tool_calls"]

        combined_results = {
            "mode": "multi_agent",
            "agents_run": [],
            "total_iterations": 0,
            "total_tool_calls": 0,
            "conversation": []  # Merged conversation for report generation
        }

        for persona_key in sequence:
            persona = AGENT_PERSONAS[persona_key]

            # Calculate per-agent budget
            agent_iterations = max(5, int(total_iterations * persona["iteration_fraction"]))
            agent_tool_calls = max(10, int(total_tool_calls * persona["tool_call_fraction"]))

            self._log_to_job(f"--- Starting {persona['name']} (iterations={agent_iterations}, tools={agent_tool_calls}) ---")
            logger.info(f"Running {persona['name']} for job {self.job_id}")

            try:
                # Create agent with modified budget
                agent = LLMAgent(self.job_id, str(self.data_dir), self.worker_url, self.intensity)

                # Override iteration/tool limits for this persona
                agent.max_iterations = agent_iterations
                agent.max_tool_calls = agent_tool_calls

                # Run with persona-specific system prompt
                result = self._run_agent_with_persona(agent, persona)
                persona_error = result.get("error")

                self.agent_results[persona_key] = result
                combined_results["agents_run"].append({
                    "persona": persona_key,
                    "name": persona["name"],
                    "iterations": result.get("iterations", 0),
                    "tool_calls": result.get("tool_call_count", 0),
                    "success": persona_error is None,
                    "error": persona_error,
                })
                combined_results["total_iterations"] += result.get("iterations", 0)
                combined_results["total_tool_calls"] += result.get("tool_call_count", 0)

                # Merge conversation for report generation
                combined_results["conversation"].extend(result.get("conversation", []))

                if persona_error:
                    self._log_to_job(f"--- {persona['name']} FAILED in inner loop: {persona_error} ---")
                else:
                    self._log_to_job(f"--- {persona['name']} complete: {result.get('iterations', 0)} iterations, {result.get('tool_call_count', 0)} tools ---")

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                logger.error(f"Agent {persona_key} failed: {error_msg}", exc_info=True)
                self._log_to_job(f"--- {persona['name']} FAILED (outer): {error_msg} ---")
                combined_results["agents_run"].append({
                    "persona": persona_key,
                    "name": persona["name"],
                    "error": error_msg,
                    "success": False
                })

        # Aggregate metrics across all agent personas
        from src.services.agent.metrics_collector import MetricsCollector
        merged_metrics = MetricsCollector()
        for persona_key, result in self.agent_results.items():
            agent_metrics = result.get("_metrics")
            if agent_metrics:
                for name, count in agent_metrics.tool_calls.items():
                    for _ in range(agent_metrics.tool_successes.get(name, 0)):
                        merged_metrics.record_tool_call(name, success=True)
                    for _ in range(agent_metrics.tool_failures.get(name, 0)):
                        merged_metrics.record_tool_call(name, success=False)
                for cat, count in agent_metrics.findings.items():
                    for _ in range(count):
                        merged_metrics.record_finding(cat)

        merged_metrics.save(str(self.job_dir))
        combined_results["metrics"] = merged_metrics.compute_summary()

        # If every persona errored out, surface a top-level error so runner.py
        # marks the job FAILED. Partial failures (some personas succeeded) still
        # count as a successful multi-agent run.
        succeeded = [a for a in combined_results["agents_run"] if a.get("success")]
        if combined_results["agents_run"] and not succeeded:
            errors = [f"{a['persona']}: {a.get('error', 'unknown')}" for a in combined_results["agents_run"]]
            combined_results["error"] = "All multi-agent personas failed: " + "; ".join(errors)
            self._log_to_job(f"[FAILED] {combined_results['error']}")
        else:
            combined_results["error"] = None

        self._log_to_job(f"Multi-agent analysis complete: {combined_results['total_iterations']} total iterations, {combined_results['total_tool_calls']} total tool calls")

        return combined_results

    def _run_agent_with_persona(self, agent: 'LLMAgent', persona: Dict) -> Dict[str, Any]:
        """Run an LLMAgent with a persona-specific system prompt"""
        # Build the persona-enhanced system prompt
        intensity_instructions = agent._get_intensity_instructions()

        system_prompt = f"""You are an expert malware/binary analyst using Ghidra. {persona['system_prompt_extension']}

{intensity_instructions}

When you've completed your assigned tasks, respond with "ANALYSIS_COMPLETE"."""

        # Initial message tells the agent to begin its role
        initial_message = f"""You are the {persona['name']} for job {self.job_id}.
{persona['description']}

Begin your analysis now. Focus on your specific responsibilities and record all findings to the notebook."""

        agent.messages.append({"role": "user", "content": initial_message})

        # Run agentic loop (adapted from LLMAgent.run_autonomous_analysis)
        analysis_complete = False
        iteration = 0

        while not analysis_complete and iteration < agent.max_iterations:
            iteration += 1

            if agent._check_cancelled():
                break

            agent._log_to_job(f"[{persona['name']}] Iteration {iteration}/{agent.max_iterations}")

            try:
                if os.environ.get("LLM_PROVIDER", "anthropic") == "anthropic":
                    response = agent.client.messages.create(
                        model=agent.model,
                        max_tokens=4096,
                        system=system_prompt,
                        messages=agent.messages,
                        tools=agent.get_tool_definitions()
                    )
                else:
                    # OpenAI path would go here
                    break

                # Log text responses
                for block in response.content:
                    if hasattr(block, 'text') and block.text:
                        text_preview = block.text[:200] + "..." if len(block.text) > 200 else block.text
                        agent._log_to_job(f"[{persona['name']}] {text_preview}")

                agent.messages.append({"role": "assistant", "content": response.content})

                if response.stop_reason == "end_turn":
                    for block in response.content:
                        if hasattr(block, 'text') and "ANALYSIS_COMPLETE" in block.text:
                            analysis_complete = True
                            break

                    if not analysis_complete:
                        agent.messages.append({
                            "role": "user",
                            "content": "Continue your analysis. What else should we investigate within your area of focus?"
                        })

                if response.stop_reason == "tool_use":
                    tool_results = []
                    for block in response.content:
                        if block.type == "tool_use":
                            result = agent.execute_tool(block.name, block.input)
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": json.dumps(result) if not isinstance(result, str) else result
                            })
                    agent.messages.append({"role": "user", "content": tool_results})

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                logger.error(f"Persona iteration {iteration} failed: {error_msg}", exc_info=True)
                agent._log_to_job(f"[ERROR] {persona['name']} iteration {iteration} failed: {error_msg}")
                agent.error = error_msg
                break

        return {
            "tool_call_count": agent.tool_call_count,
            "iterations": iteration,
            "conversation": agent.messages,
            "_metrics": agent.metrics,
            "error": agent.error,
        }
