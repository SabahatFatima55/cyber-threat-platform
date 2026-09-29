"""
MITRE ATT&CK Auto Mapping (Bonus Challenge)
----------------------------------------------
Automatically maps detected attack types / rule matches to standard
MITRE ATT&CK technique IDs, so analysts get industry-standard
terminology instead of a custom label.

Reference: https://attack.mitre.org/
"""

import pandas as pd

# Mapping from our internal detection labels -> MITRE ATT&CK techniques
MITRE_MAP = {
    "Port Scanning": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
    ],
    "Brute Force": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
    ],
    "DDoS": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
    ],
    "Data Exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
    ],
    "Malware C2": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    ],
    "RULE-PORT-SCAN": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
    ],
    "RULE-BRUTE-FORCE": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
    ],
    "RULE-DDOS-VOLUME": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
    ],
    "RULE-EXFIL-VOLUME": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
    ],
    "RULE-C2-BEACON": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
    ],
}


def map_to_mitre(row) -> list:
    techniques = {}

    # Map by known attack_type label (ground truth / simulated label)
    for t in MITRE_MAP.get(row.get("attack_type", ""), []):
        techniques[t["id"]] = t

    # Map by which detection rule(s) fired (this is the "auto" part -
    # mapping happens off what the ENGINE detected, not the ground truth)
    if row.get("rule_matches"):
        for rule_id in row["rule_matches"].split(";"):
            for t in MITRE_MAP.get(rule_id, []):
                techniques[t["id"]] = t

    return list(techniques.values())


def apply_mitre_mapping(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["mitre_techniques"] = df.apply(
        lambda r: ";".join([t["id"] for t in map_to_mitre(r)]) or "",
        axis=1,
    )
    df["mitre_tactics"] = df.apply(
        lambda r: ";".join(sorted(set(t["tactic"] for t in map_to_mitre(r)))) or "",
        axis=1,
    )
    return df
