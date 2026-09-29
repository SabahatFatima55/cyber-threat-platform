"""
Base Agent
------------
Minimal shared contract for every agent in the Multi-Agent AI Workflow.
Each agent: (1) receives the shared pipeline state, (2) does one focused
job, (3) logs a structured entry describing what it did and why - so the
whole run produces an auditable multi-agent collaboration transcript
(outputs/agent_log.json), which is what makes this "explainable
multi-agent AI" rather than a black box.
"""

from __future__ import annotations
from typing import Any, Dict


class BaseAgent:
    name: str = "BaseAgent"
    role: str = "Unspecified"

    def __init__(self):
        self.log_entries = []

    def log(self, message: str, **details):
        entry = {"agent": self.name, "role": self.role, "message": message}
        if details:
            entry["details"] = details
        self.log_entries.append(entry)

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
