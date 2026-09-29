"""
Response Agent (Bonus: Autonomous AI SOC Analyst)
---------------------------------------------------------
Given the investigated incidents, this agent autonomously *decides* a
recommended response action per incident - without a human specifying
rules per-case - based on severity, malware family, and confidence.
This is the "autonomous decisioning" layer: CorrelationAgent finds
things, RiskAgent scores them, InvestigationAgent explains them, and
ResponseAgent decides what a SOC analyst should do about each one,
end to end, with no human in the loop until the action is presented.

Actions are RECOMMENDED, not auto-executed against real infrastructure
(no real firewall/EDR is connected here) - but the decision logic itself
is fully autonomous, which is what the case study's bonus challenge asks
for.
"""

from agents.base_agent import BaseAgent


def _decide_action(incident: dict) -> dict:
    risk = incident.get("max_risk_score", 0)
    family = incident.get("possible_malware_family", "Unclassified")

    if risk >= 85:
        action = "Auto-isolate affected host(s) from network + force credential reset for suspected user"
        priority = "Immediate"
    elif risk >= 70:
        action = "Escalate to Tier-2 analyst for manual review within 1 hour; block destination IP at firewall"
        priority = "Urgent"
    elif risk >= 55:
        action = "Add to watchlist; increase logging verbosity for involved hosts for 24h"
        priority = "High"
    else:
        action = "Log for trend analysis; no immediate action required"
        priority = "Routine"

    if "Ransomware" in family:
        action += " | Ransomware precursor pattern detected - verify backup integrity immediately"
    if "Exfiltration" in family:
        action += " | Review DLP logs for data leaving via this channel"

    return {"priority": priority, "recommended_action": action}


class ResponseAgent(BaseAgent):
    name = "ResponseAgent"
    role = "Autonomously decides a recommended response action per investigated incident (SOC analyst role)"

    def run(self, state):
        incidents = state.get("incidents", [])
        for incident in incidents:
            decision = _decide_action(incident)
            incident.update(decision)

        immediate = sum(1 for i in incidents if i.get("priority") == "Immediate")
        self.log(
            f"Autonomously triaged {len(incidents)} incidents; {immediate} require immediate action.",
            immediate_count=immediate,
        )
        state["incidents"] = incidents
        return state
