"""
Threat Hunting Agent (Bonus: AI Threat Hunting Agent)
-----------------------------------------------------------
Proactively hunts for patterns that no single-flow rule would catch:
a source IP making many long-lived, low-volume connections over time
(classic C2 beaconing behavior) even if each individual flow scored
low risk on its own. This is the "assume breach, go looking" agent -
distinct from the reactive CorrelationAgent, which only reacts to
flows already tagged suspicious.
"""

import pandas as pd
from agents.base_agent import BaseAgent


class ThreatHuntingAgent(BaseAgent):
    name = "ThreatHuntingAgent"
    role = "Proactively hunts for multi-flow beaconing/C2 patterns invisible to single-flow rules"

    def run(self, state):
        df = state["df"]
        beacon_ports = {443, 8080, 4444, 6667}

        candidates = df[
            (df["dst_port"].isin(beacon_ports)) & (df["flow_bytes_s"] < 8000)
        ]
        beacon_counts = candidates.groupby("src_ip").size()
        beaconing_ips = beacon_counts[beacon_counts >= 3].index.tolist()

        df = df.copy()
        df["hunt_flag"] = df["src_ip"].isin(beaconing_ips) & df["dst_port"].isin(beacon_ports)

        # Escalate: anything the hunt flags but correlation missed becomes Suspicious too
        newly_caught = int(((df["hunt_flag"]) & (df["verdict"] == "Normal")).sum())
        df.loc[(df["hunt_flag"]) & (df["verdict"] == "Normal"), "verdict"] = "Suspicious"
        df.loc[(df["hunt_flag"]) & (df["verdict"] == "Suspicious") & (df["rule_matches"] == ""),
               "rule_matches"] = "HUNT-BEACON-PATTERN"

        self.log(
            f"Hunted for beaconing patterns across {len(beaconing_ips)} repeat-connecting source IPs; "
            f"escalated {newly_caught} previously-normal flows to Suspicious.",
            beaconing_ips=beaconing_ips[:10], newly_caught=newly_caught,
        )
        state["df"] = df
        return state
