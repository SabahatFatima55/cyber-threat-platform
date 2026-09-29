"""
AI Incident Investigation Engine
-------------------------------------
For a given suspicious actor (a user or an IP), automatically builds a
structured incident report - the exact fields the case study asks for:
  - Timeline
  - Root Cause
  - Related Events
  - Affected Systems
  - Suspected User
  - Possible Malware Family

It pulls from three places that already exist in the pipeline:
  1. The processed flow dataframe (detections, risk scores, explanations)
  2. The Security Knowledge Graph (relationships between user/src/dst)
  3. The malware family classifier (heuristic family attribution)

This is deliberately rule/graph-driven rather than another LLM call, so
every field is traceable back to concrete evidence (Explainable AI),
matching the case study's "Explainable AI" module as well as
"AI Incident Investigation".
"""

from __future__ import annotations
from typing import Dict, Any, List
import pandas as pd
import networkx as nx

from detection.malware_classifier import classify_malware_family
from graph.knowledge_graph import build_attack_chain


def _pick_root_cause(chain: List[dict]) -> str:
    """Root cause = the earliest, most specific rule/anomaly in the chain."""
    if not chain:
        return "Insufficient evidence to determine root cause."
    first = chain[0]
    if first.get("rule_matches"):
        rule = first["rule_matches"].split(";")[0]
        return f"Initiated by {rule} at {first['timestamp']} ({first['attack_type']})."
    return f"Initiated by an anomalous {first['attack_type']} flow at {first['timestamp']} (no known rule signature - flagged by ML anomaly detection)."


def generate_incident_report(df: pd.DataFrame, G: nx.MultiDiGraph, entity: str,
                              entity_type: str = "ip") -> Dict[str, Any]:
    """
    entity_type: 'ip' or 'user'
    """
    if entity_type == "user":
        sub = df[(df["user"] == entity) & (df["verdict"] == "Suspicious")].sort_values("timestamp")
        related_ips = sorted(set(sub["src_ip"]).union(set(sub["dst_ip"])))
        chain = []
        for ip in related_ips:
            chain.extend(build_attack_chain(df, ip))
        chain = sorted(chain, key=lambda r: r["timestamp"])
        suspected_user = entity
    else:
        sub = df[((df["src_ip"] == entity) | (df["dst_ip"] == entity)) & (df["verdict"] == "Suspicious")].sort_values("timestamp")
        chain = build_attack_chain(df, entity)
        users_involved = sub["user"].value_counts()
        suspected_user = users_involved.idxmax() if not users_involved.empty else "unknown"

    if sub.empty:
        return {
            "entity": entity,
            "entity_type": entity_type,
            "status": "no_suspicious_activity_found",
        }

    affected_systems = sorted(set(sub["dst_ip"]).union(set(sub["src_ip"])))
    malware_votes = sub.apply(classify_malware_family, axis=1)
    malware_counts = malware_votes.value_counts()
    possible_family = malware_counts.index[0] if not malware_counts.empty else "Unclassified"

    timeline = [
        {
            "timestamp": r["timestamp"],
            "event": f"{r.get('attack_type', 'Unknown')} ({r.get('rule_severity', 'Info')}) "
                     f"{r['src_ip']} -> {r['dst_ip']}:{int(r['dst_port'])}",
            "risk_score": int(r.get("risk_score", 0)),
            "mitre": r.get("mitre_techniques", ""),
        }
        for _, r in sub.iterrows()
    ]

    related_events = [
        {
            "flow_id": int(r["flow_id"]),
            "attack_type": r.get("attack_type", ""),
            "explanation": r.get("explanation", ""),
        }
        for _, r in sub.iterrows()
    ]

    report = {
        "entity": entity,
        "entity_type": entity_type,
        "status": "investigated",
        "timeline": timeline,
        "root_cause": _pick_root_cause(chain) if chain else _pick_root_cause(
            [{"timestamp": r["timestamp"], "attack_type": r["attack_type"],
              "rule_matches": r.get("rule_matches", "")} for _, r in sub.iterrows()]
        ),
        "related_events": related_events,
        "affected_systems": affected_systems,
        "suspected_user": suspected_user,
        "possible_malware_family": possible_family,
        "max_risk_score": int(sub["risk_score"].max()),
        "total_related_flows": len(sub),
        "mitre_techniques": sorted(set(
            t for val in sub["mitre_techniques"].dropna() for t in val.split(";") if t
        )),
    }
    return report


def generate_all_incidents(df: pd.DataFrame, G: nx.MultiDiGraph, top_n: int = 10) -> List[Dict[str, Any]]:
    """Auto-investigate the top-N highest-risk IPs (most common analyst workflow)."""
    sus = df[df["verdict"] == "Suspicious"]
    if sus.empty:
        return []
    top_ips = (
        sus.groupby("dst_ip")["risk_score"].max().sort_values(ascending=False).head(top_n).index
    )
    reports = [generate_incident_report(df, G, ip, entity_type="ip") for ip in top_ips]
    return [r for r in reports if r.get("status") == "investigated"]
