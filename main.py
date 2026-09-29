"""
Enterprise Cyber Threat Intelligence Platform - Main Pipeline
================================================================
Runs the full pipeline end-to-end through a Multi-Agent AI Architecture:

  CorrelationAgent -> ThreatHuntingAgent -> RiskAgent
      -> InvestigationAgent -> ResponseAgent

Each agent's reasoning is logged to outputs/agent_log.json, producing a
full multi-agent collaboration transcript.

What gets produced:
  outputs/processed_logs.csv   - every flow, tagged/scored/explained
  outputs/alerts.json          - high-priority alert feed (Notification Center)
  outputs/investigations.json  - structured AI incident investigation reports
  outputs/agent_log.json       - multi-agent collaboration transcript

Run: python main.py
"""

import os
import sys
import json
import pandas as pd

sys.path.append(os.path.join(os.path.dirname(__file__)))

from data.generate_data import generate as generate_data
from agents.orchestrator import Orchestrator
from risk.alert_center import generate_alerts, save_alerts

DATA_PATH = os.path.join("data", "security_logs.csv")
OUTPUT_PATH = os.path.join("outputs", "processed_logs.csv")
ALERTS_PATH = os.path.join("outputs", "alerts.json")
INVESTIGATIONS_PATH = os.path.join("outputs", "investigations.json")
AGENT_LOG_PATH = os.path.join("outputs", "agent_log.json")


def run_pipeline():
    print("=" * 60)
    print("Enterprise Cyber Threat Intelligence Platform")
    print("Multi-Agent AI Architecture: Correlation -> Hunting -> Risk -> Investigation -> Response")
    print("=" * 60)

    # Step 1: Data (Security Data Pipeline)
    if not os.path.exists(DATA_PATH):
        print("\n[1/3] No dataset found - generating synthetic logs...")
        generate_data(n_rows=8000, out_path=DATA_PATH)
    else:
        print(f"\n[1/3] Loading existing dataset: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    print(f"      Loaded {len(df)} flow records")

    # Step 2: Run the multi-agent workflow
    print("\n[2/3] Running multi-agent workflow...")
    orchestrator = Orchestrator()
    state = orchestrator.run(df)
    for entry in orchestrator.collect_log():
        print(f"      [{entry['agent']}] {entry['message']}")

    df = state["df"]
    incidents = state["incidents"]

    # Step 3: Alerts + persistence
    print("\n[3/3] Generating alerts and saving outputs...")
    os.makedirs("outputs", exist_ok=True)
    alerts = generate_alerts(df, min_risk=55)
    save_alerts(alerts, ALERTS_PATH)

    df.to_csv(OUTPUT_PATH, index=False)
    with open(INVESTIGATIONS_PATH, "w") as f:
        json.dump(incidents, f, indent=2)
    orchestrator.save_log(AGENT_LOG_PATH)

    # Summary
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE - Summary")
    print("=" * 60)
    print(df["verdict"].value_counts().to_string())
    print("\nAttack type breakdown (suspicious only):")
    print(df[df["verdict"] == "Suspicious"]["attack_type"].value_counts().to_string())
    print(f"\nTotal alerts generated: {len(alerts)}")
    print(f"Structured incident investigations: {len(incidents)} -> {INVESTIGATIONS_PATH}")
    print(f"Multi-agent collaboration log -> {AGENT_LOG_PATH}")
    immediate = sum(1 for i in incidents if i.get("priority") == "Immediate")
    if immediate:
        print(f"\n*** {immediate} incident(s) flagged for IMMEDIATE autonomous response ***")
    print("\nNow run: python dashboard/app.py   (to view the web dashboard)")
    print("     or: python copilot/run_copilot.py  (to chat with the Security Copilot)")


if __name__ == "__main__":
    run_pipeline()
