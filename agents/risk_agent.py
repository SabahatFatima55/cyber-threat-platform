"""
Risk Agent
------------
Wraps the Threat Risk Engine + MITRE mapping + malware family
classification + threat-feed enrichment - everything that turns a
"flagged" flow into a scored, explained, contextualized one.
"""

from agents.base_agent import BaseAgent
from risk.risk_engine import apply_risk_scoring
from mitre.mitre_mapping import apply_mitre_mapping
from detection.malware_classifier import apply_malware_classification
from intel.threat_feed import enrich_with_feed


class RiskAgent(BaseAgent):
    name = "RiskAgent"
    role = "Scores risk, maps MITRE techniques, classifies malware family, checks threat feeds"

    def run(self, state):
        df = state["df"]
        df = apply_risk_scoring(df)
        df = apply_mitre_mapping(df)
        df = apply_malware_classification(df)
        df = enrich_with_feed(df)

        feed_hits = int(df["feed_match"].sum())
        critical = int((df["risk_level"] == "Critical").sum())
        self.log(
            f"Scored risk for all flows - {critical} Critical, {feed_hits} matched known-bad threat-feed indicators.",
            critical_count=critical, feed_hits=feed_hits,
        )
        state["df"] = df
        return state
