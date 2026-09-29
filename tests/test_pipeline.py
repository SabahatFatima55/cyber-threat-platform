"""
Basic tests for the core AI modules. Run: pytest tests/ -v
(Run from the project root so relative imports resolve.)
"""

import os
import sys
import pandas as pd
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from detection.threat_engine import run_detection
from risk.risk_engine import apply_risk_scoring
from mitre.mitre_mapping import apply_mitre_mapping
from detection.malware_classifier import classify_malware_family, apply_malware_classification
from intel.threat_feed import enrich_with_feed
from graph.knowledge_graph import build_knowledge_graph, graph_stats
from investigation.incident_investigator import generate_incident_report


@pytest.fixture(scope="module")
def sample_df():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "security_logs.csv")
    df = pd.read_csv(path).head(500)  # small slice - fast tests
    df = run_detection(df)
    df = apply_risk_scoring(df)
    df = apply_mitre_mapping(df)
    df = apply_malware_classification(df)
    df = enrich_with_feed(df)
    return df


def test_detection_produces_verdicts(sample_df):
    assert "verdict" in sample_df.columns
    assert set(sample_df["verdict"].unique()) <= {"Suspicious", "Normal"}
    assert (sample_df["verdict"] == "Suspicious").sum() > 0


def test_risk_scores_in_range(sample_df):
    assert sample_df["risk_score"].between(0, 100).all()
    assert set(sample_df["risk_level"].unique()) <= {"Info", "Low", "Medium", "High", "Critical"}


def test_explanations_are_non_empty_for_suspicious(sample_df):
    sus = sample_df[sample_df["verdict"] == "Suspicious"]
    assert (sus["explanation"].str.len() > 0).all()


def test_mitre_mapping_present_for_known_attack_types(sample_df):
    brute = sample_df[sample_df["attack_type"] == "Brute Force"]
    if len(brute):
        assert brute["mitre_techniques"].str.contains("T1110").any()


def test_malware_classifier_returns_string():
    row = {"dst_port": 6667, "attack_type": "Malware C2", "flow_duration": 400000, "flow_bytes_s": 3000, "failed_logins": 0, "fwd_packets": 10}
    label = classify_malware_family(row)
    assert isinstance(label, str) and len(label) > 0
    assert label == "IRC-based Botnet C2"


def test_threat_feed_enrichment_adds_columns(sample_df):
    assert "feed_match" in sample_df.columns
    assert "feed_source" in sample_df.columns
    assert sample_df["feed_match"].dtype == bool


def test_knowledge_graph_builds(sample_df):
    G = build_knowledge_graph(sample_df)
    stats = graph_stats(G)
    assert stats["total_nodes"] > 0
    assert stats["total_edges"] == len(sample_df) * 2  # user->src edge + src->dst edge per flow


def test_incident_report_structure(sample_df):
    G = build_knowledge_graph(sample_df)
    sus = sample_df[sample_df["verdict"] == "Suspicious"]
    if sus.empty:
        pytest.skip("No suspicious flows in this sample slice")
    target_ip = sus.iloc[0]["dst_ip"]
    report = generate_incident_report(sample_df, G, target_ip, entity_type="ip")
    for field in ("timeline", "root_cause", "related_events", "affected_systems",
                  "suspected_user", "possible_malware_family"):
        assert field in report
