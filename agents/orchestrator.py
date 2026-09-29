"""
Multi-Agent Orchestrator (Multi-Agent AI Architecture)
------------------------------------------------------------
Coordinates five specialized agents in sequence, passing a shared
`state` dict between them - each agent reads what it needs, does its
job, and writes back. This is a simple but genuine multi-agent
architecture: distinct agents, distinct responsibilities, a shared
blackboard state, and a full collaboration transcript.

Agents, in order:
  1. CorrelationAgent   - raw events -> tagged suspicious/normal flows
  2. ThreatHuntingAgent  - proactive multi-flow pattern hunting
  3. RiskAgent           - risk scoring, MITRE mapping, malware family, threat feed
  4. InvestigationAgent  - knowledge graph + structured incident reports
  5. ResponseAgent       - autonomous response-action decisioning

For a heavier production system this same state-passing pattern maps
directly onto a framework like LangGraph (each agent -> a graph node,
`state` -> the graph's shared state schema) - swapping frameworks later
does not require re-deriving the agent boundaries or logic.
"""

from __future__ import annotations
import json
from typing import Any, Dict

from agents.correlation_agent import CorrelationAgent
from agents.hunting_agent import ThreatHuntingAgent
from agents.risk_agent import RiskAgent
from agents.investigation_agent import InvestigationAgent
from agents.response_agent import ResponseAgent


class Orchestrator:
    def __init__(self):
        self.agents = [
            CorrelationAgent(),
            ThreatHuntingAgent(),
            RiskAgent(),
            InvestigationAgent(),
            ResponseAgent(),
        ]

    def run(self, df) -> Dict[str, Any]:
        state: Dict[str, Any] = {"df": df}
        for agent in self.agents:
            state = agent.run(state)
        return state

    def collect_log(self) -> list:
        transcript = []
        for agent in self.agents:
            transcript.extend(agent.log_entries)
        return transcript

    def save_log(self, path: str):
        with open(path, "w") as f:
            json.dump(self.collect_log(), f, indent=2)
