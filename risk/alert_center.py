"""
Notification / Alert Center
------------------------------
Generates structured alerts for high-priority events. In production
this would push to Slack/email/PagerDuty; here it writes a JSON feed
that the dashboard reads.
"""

import pandas as pd
import json


def generate_alerts(df: pd.DataFrame, min_risk=55) -> list:
    alerts = []
    critical = df[(df["verdict"] == "Suspicious") & (df["risk_score"] >= min_risk)]
    critical = critical.sort_values("risk_score", ascending=False)

    for _, r in critical.iterrows():
        alerts.append({
            "flow_id": int(r["flow_id"]),
            "timestamp": r["timestamp"],
            "type": r["attack_type"],
            "severity": r["risk_level"],
            "risk_score": int(r["risk_score"]),
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "dst_port": int(r["dst_port"]),
            "user": r["user"],
            "explanation": r["explanation"],
            "mitre_techniques": r.get("mitre_techniques", ""),
        })
    return alerts


def save_alerts(alerts: list, path="../outputs/alerts.json"):
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Saved {len(alerts)} alerts -> {path}")
