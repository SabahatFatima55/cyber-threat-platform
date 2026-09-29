"""
Threat Risk Engine + Explainable AI
--------------------------------------
Calculates a 0-100 risk score per suspicious flow, combining rule
severity + anomaly score + asset sensitivity. Also produces a
human-readable explanation (Explainable AI requirement) so an
analyst can see WHY something was flagged, not just THAT it was.
"""

import pandas as pd

SEVERITY_WEIGHT = {"Info": 0, "Low": 20, "Medium": 45, "High": 70, "Critical": 90}

SENSITIVE_PORTS = {22: 10, 3389: 15, 445: 15, 3306: 10, 5432: 10}  # admin/db access = higher stakes


def compute_risk_score(row) -> int:
    base = SEVERITY_WEIGHT.get(row.get("rule_severity", "Info"), 0)

    anomaly_bonus = 0
    if row.get("is_anomaly", False):
        anomaly_bonus = 15

    port_bonus = SENSITIVE_PORTS.get(row.get("dst_port"), 0)

    score = min(100, base + anomaly_bonus + port_bonus)
    return int(score)


def explain_flow(row) -> str:
    """Builds a plain-language explanation of why this flow was flagged."""
    reasons = []

    if row.get("rule_matches"):
        rule_names = row["rule_matches"].split(";")
        reasons.append(f"Matched detection rule(s): {', '.join(rule_names)}")

    if row.get("is_anomaly"):
        reasons.append(
            f"Flagged as a statistical anomaly by the ML model "
            f"(anomaly score: {row.get('anomaly_score', 0):.3f}, lower = more unusual)"
        )

    if row.get("dst_port") in SENSITIVE_PORTS:
        reasons.append(f"Destination port {row['dst_port']} is a sensitive/administrative port")

    if row.get("failed_logins", 0) >= 4:
        reasons.append(f"{row['failed_logins']} failed login attempts observed in this flow")

    if not reasons:
        reasons.append("No specific indicators - flagged by general anomaly threshold")

    return " | ".join(reasons)


def apply_risk_scoring(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["risk_score"] = df.apply(compute_risk_score, axis=1)
    df["explanation"] = df.apply(explain_flow, axis=1)

    def risk_level(score):
        if score >= 80:
            return "Critical"
        elif score >= 55:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Info"

    df["risk_level"] = df["risk_score"].apply(risk_level)
    return df
