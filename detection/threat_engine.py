"""
AI Threat Correlation Engine
------------------------------
Detects suspicious events using a hybrid approach:
 1. Rule-based detection (fast, explainable, catches known patterns)
 2. Anomaly detection via Isolation Forest (catches unknown/novel patterns)

This mirrors real SOC practice: rules catch known attack signatures,
ML catches things nobody wrote a rule for yet.
"""

import pandas as pd
from sklearn.ensemble import IsolationForest


RULES = [
    {
        "id": "RULE-PORT-SCAN",
        "name": "Port Scanning Pattern",
        "condition": lambda r: r["flow_duration"] < 250 and r["fwd_packets"] <= 3 and r["bwd_packets"] == 0,
        "severity": "Medium",
    },
    {
        "id": "RULE-BRUTE-FORCE",
        "name": "Repeated Failed Logins",
        "condition": lambda r: r["failed_logins"] >= 4,
        "severity": "High",
    },
    {
        "id": "RULE-DDOS-VOLUME",
        "name": "Abnormal Traffic Volume (possible DDoS)",
        "condition": lambda r: r["flow_bytes_s"] > 40000 and r["fwd_packets"] > 40,
        "severity": "Critical",
    },
    {
        "id": "RULE-EXFIL-VOLUME",
        "name": "Large Outbound Transfer (possible exfiltration)",
        "condition": lambda r: r["fwd_packets"] > 400 and r["dst_port"] in (443, 22, 8080),
        "severity": "Critical",
    },
    {
        "id": "RULE-C2-BEACON",
        "name": "Long-lived low-volume external connection (possible C2 beacon)",
        "condition": lambda r: r["flow_duration"] > 300000 and r["flow_bytes_s"] < 6000
        and r["dst_port"] in (443, 8080, 4444, 6667),
        "severity": "High",
    },
]


def apply_rules(df: pd.DataFrame) -> pd.DataFrame:
    """Tag each row with any rule matches (explainable detections)."""
    matches_col = []
    severity_col = []
    for _, row in df.iterrows():
        matched = []
        max_sev = "Info"
        sev_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        for rule in RULES:
            try:
                if rule["condition"](row):
                    matched.append(rule["id"])
                    if sev_rank[rule["severity"]] > sev_rank[max_sev]:
                        max_sev = rule["severity"]
            except Exception:
                continue
        matches_col.append(";".join(matched) if matched else "")
        severity_col.append(max_sev)
    df = df.copy()
    df["rule_matches"] = matches_col
    df["rule_severity"] = severity_col
    return df


def apply_anomaly_detection(df: pd.DataFrame, contamination=0.08) -> pd.DataFrame:
    """
    Isolation Forest flags statistically unusual flows even if no rule
    caught them - this is the "unknown unknowns" layer.
    """
    features = ["flow_duration", "fwd_packets", "bwd_packets", "flow_bytes_s", "failed_logins"]
    X = df[features].fillna(0)

    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=150)
    preds = model.fit_predict(X)  # -1 = anomaly, 1 = normal
    scores = model.decision_function(X)  # lower = more anomalous

    df = df.copy()
    df["is_anomaly"] = preds == -1
    df["anomaly_score"] = scores
    return df


def run_detection(df: pd.DataFrame) -> pd.DataFrame:
    df = apply_rules(df)
    df = apply_anomaly_detection(df)

    def final_verdict(row):
        if row["rule_matches"] or row["is_anomaly"]:
            return "Suspicious"
        return "Normal"

    df["verdict"] = df.apply(final_verdict, axis=1)
    return df


if __name__ == "__main__":
    df = pd.read_csv("../data/security_logs.csv")
    result = run_detection(df)
    print(result["verdict"].value_counts())
    print(result[result["verdict"] == "Suspicious"].head(10))
