"""
Factory... no wait, Security Knowledge Graph + Attack Graph Builder
----------------------------------------------------------------------
Builds relationships between: Users, Source IPs, Destination IPs, Ports,
and detected Events. This lets the Copilot answer relationship questions
("which servers did this user touch?") and lets the Attack Graph Builder
reconstruct a plausible attack chain for a given suspicious actor.
"""

import networkx as nx
import pandas as pd


def build_knowledge_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    """
    Node types: user, src_ip, dst_ip
    Edge: represents a flow, carries dst_port, verdict, severity, timestamp
    """
    G = nx.MultiDiGraph()

    for _, row in df.iterrows():
        user = f"user:{row['user']}"
        src = f"ip:{row['src_ip']}"
        dst = f"ip:{row['dst_ip']}"

        G.add_node(user, type="user")
        G.add_node(src, type="ip")
        G.add_node(dst, type="ip")

        G.add_edge(user, src, relation="logged_in_from")
        G.add_edge(
            src, dst,
            relation="connected_to",
            port=row["dst_port"],
            verdict=row.get("verdict", "Unknown"),
            severity=row.get("rule_severity", "Info"),
            attack_type=row.get("attack_type", "Unknown"),
            timestamp=row["timestamp"],
            flow_id=row["flow_id"],
        )

    return G


def build_attack_chain(df: pd.DataFrame, entity_ip: str) -> list:
    """
    Reconstructs a simplified attack chain for a given IP, ordered by time:
    Initial Access -> ... -> Data Exfiltration / Impact
    Only includes flows tagged Suspicious.
    """
    sub = df[
        ((df["src_ip"] == entity_ip) | (df["dst_ip"] == entity_ip))
        & (df["verdict"] == "Suspicious")
    ].sort_values("timestamp")

    chain = []
    for _, row in sub.iterrows():
        chain.append({
            "timestamp": row["timestamp"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "port": int(row["dst_port"]),
            "attack_type": row["attack_type"],
            "rule_matches": row["rule_matches"],
            "severity": row["rule_severity"],
        })
    return chain


def graph_stats(G: nx.MultiDiGraph) -> dict:
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "users": len([n for n, d in G.nodes(data=True) if d.get("type") == "user"]),
        "ips": len([n for n, d in G.nodes(data=True) if d.get("type") == "ip"]),
    }
