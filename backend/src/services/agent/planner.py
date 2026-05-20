"""
Agent planner for coordinating reverse engineering analysis
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AnalysisStep:
    """Represents a single analysis step"""
    name: str
    description: str
    tool_name: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    completed: bool = False
    result: Any = None


class AnalysisPlanner:
    """Plans and tracks reverse engineering analysis workflow"""

    def __init__(self):
        self.steps: List[AnalysisStep] = []
        self.findings: Dict[str, Any] = {}

    def create_plan(self) -> List[AnalysisStep]:
        """Create a high-level analysis plan"""
        plan = [
            AnalysisStep(
                name="list_functions",
                description="Get overview of all functions in binary",
                tool_name="list_functions"
            ),
            AnalysisStep(
                name="get_strings",
                description="Extract interesting strings",
                tool_name="list_strings",
                params={"limit": 100}
            ),
            AnalysisStep(
                name="get_imports",
                description="Identify imported libraries and functions",
                tool_name="list_imports",
                params={"limit": 100}
            ),
            AnalysisStep(
                name="get_exports",
                description="Identify exported functions",
                tool_name="list_exports",
                params={"limit": 100}
            ),
            AnalysisStep(
                name="analyze_entry_points",
                description="Analyze main entry points and key functions"
            ),
            AnalysisStep(
                name="analyze_interesting_functions",
                description="Deep dive into suspicious or interesting functions"
            ),
            AnalysisStep(
                name="rename_functions",
                description="Rename functions with descriptive names"
            ),
            AnalysisStep(
                name="generate_report",
                description="Compile findings into comprehensive report"
            )
        ]

        self.steps = plan
        return plan

    def mark_completed(self, step_name: str, result: Any = None):
        """Mark a step as completed with optional result"""
        for step in self.steps:
            if step.name == step_name:
                step.completed = True
                step.result = result
                logger.info(f"Completed step: {step_name}")
                break

    def get_next_step(self) -> Optional[AnalysisStep]:
        """Get the next uncompleted step"""
        for step in self.steps:
            if not step.completed:
                return step
        return None

    def add_finding(self, category: str, finding: Any):
        """Add a finding to the collection"""
        if category not in self.findings:
            self.findings[category] = []
        self.findings[category].append(finding)

    def get_progress(self) -> float:
        """Get analysis progress as percentage"""
        if not self.steps:
            return 0.0
        completed = sum(1 for step in self.steps if step.completed)
        return (completed / len(self.steps)) * 100

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis progress"""
        return {
            "total_steps": len(self.steps),
            "completed_steps": sum(1 for step in self.steps if step.completed),
            "progress": self.get_progress(),
            "findings_categories": list(self.findings.keys()),
            "current_step": self.get_next_step().name if self.get_next_step() else "Complete"
        }
