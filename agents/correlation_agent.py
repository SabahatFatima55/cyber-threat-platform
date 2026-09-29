"""
Correlation Agent
-------------------
Wraps the AI Threat Correlation Engine (rule-based + Isolation Forest).
Its job in the multi-agent workflow: take raw flows in, hand back
correlated/tagged flows, and report what it found to the other agents.
"""

from agents.base_agent import BaseAgent
from detection.threat_engine import run_detection


class CorrelationAgent(BaseAgent):
    name = "CorrelationAgent"
    role = "Correlates raw security events into tagged suspicious/normal flows"

    def run(self, state):
        df = state["df"]
        df = run_detection(df)
        n_suspicious = int((df["verdict"] == "Suspicious").sum())
        self.log(
            f"Correlated {len(df)} flows -> {n_suspicious} flagged suspicious.",
            suspicious_count=n_suspicious, total=len(df),
        )
        state["df"] = df
        return state
