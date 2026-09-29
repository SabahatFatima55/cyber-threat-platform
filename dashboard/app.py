"""
Threat Intelligence Dashboard + Security Copilot Web UI
-----------------------------------------------------------
Flask app serving:
  - Executive dashboard (charts, stats, alerts)
  - REST API endpoints
  - Security Copilot chat interface
"""

import os
import sys
import json
import pandas as pd
from flask import Flask, jsonify, render_template, request

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from copilot.security_copilot import SecurityCopilot

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
PROCESSED_PATH = os.path.join(BASE_DIR, "outputs", "processed_logs.csv")
ALERTS_PATH = os.path.join(BASE_DIR, "outputs", "alerts.json")
INVESTIGATIONS_PATH = os.path.join(BASE_DIR, "outputs", "investigations.json")
AGENT_LOG_PATH = os.path.join(BASE_DIR, "outputs", "agent_log.json")

app = Flask(__name__)

_df_cache = None
_copilot_cache = None


def get_df():
    global _df_cache
    if _df_cache is None:
        if not os.path.exists(PROCESSED_PATH):
            raise FileNotFoundError("Run `python main.py` first to generate processed data.")
        _df_cache = pd.read_csv(PROCESSED_PATH)
    return _df_cache


def get_copilot():
    global _copilot_cache
    if _copilot_cache is None:
        _copilot_cache = SecurityCopilot(get_df())
    return _copilot_cache


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    df = get_df()
    total = len(df)
    suspicious = int((df["verdict"] == "Suspicious").sum())
    normal = total - suspicious
    critical = int((df["risk_level"] == "Critical").sum())
    high = int((df["risk_level"] == "High").sum())

    attack_counts = (
        df[df["verdict"] == "Suspicious"]["attack_type"].value_counts().to_dict()
    )

    return jsonify({
        "total_flows": total,
        "suspicious": suspicious,
        "normal": normal,
        "critical_risk": critical,
        "high_risk": high,
        "detection_rate": round(suspicious / total * 100, 1),
        "attack_breakdown": attack_counts,
    })


@app.route("/api/alerts")
def api_alerts():
    if not os.path.exists(ALERTS_PATH):
        return jsonify([])
    with open(ALERTS_PATH) as f:
        alerts = json.load(f)
    return jsonify(alerts[:50])


@app.route("/api/mitre")
def api_mitre():
    df = get_df()
    sus = df[df["verdict"] == "Suspicious"]
    all_tech = []
    for val in sus["mitre_techniques"].dropna():
        if val:
            all_tech.extend(val.split(";"))
    counts = pd.Series(all_tech).value_counts().to_dict() if all_tech else {}
    return jsonify(counts)


@app.route("/api/top_targets")
def api_top_targets():
    df = get_df()
    sus = df[df["verdict"] == "Suspicious"]
    top_ips = sus["dst_ip"].value_counts().head(8).to_dict()
    top_users = sus["user"].value_counts().head(8).to_dict()
    return jsonify({"top_targeted_ips": top_ips, "top_affected_users": top_users})


@app.route("/api/copilot", methods=["POST"])
def api_copilot():
    question = request.json.get("question", "")
    if not question:
        return jsonify({"answer": "Please ask a question."})
    copilot = get_copilot()
    answer = copilot.answer(question)
    return jsonify({"answer": answer})


@app.route("/api/investigations")
def api_investigations():
    if not os.path.exists(INVESTIGATIONS_PATH):
        return jsonify([])
    with open(INVESTIGATIONS_PATH) as f:
        return jsonify(json.load(f))


@app.route("/api/agent_log")
def api_agent_log():
    if not os.path.exists(AGENT_LOG_PATH):
        return jsonify([])
    with open(AGENT_LOG_PATH) as f:
        return jsonify(json.load(f))


@app.route("/api/malware_families")
def api_malware_families():
    df = get_df()
    if "possible_malware_family" not in df.columns:
        return jsonify({})
    sus = df[(df["verdict"] == "Suspicious") & (~df["possible_malware_family"].isin(["", "Unclassified"]))]
    return jsonify(sus["possible_malware_family"].value_counts().to_dict())


@app.route("/api/threat_feed_hits")
def api_threat_feed_hits():
    df = get_df()
    if "feed_match" not in df.columns:
        return jsonify({"total_hits": 0, "by_source": {}})
    hits = df[df["feed_match"] == True]
    return jsonify({
        "total_hits": int(len(hits)),
        "by_source": hits["feed_source"].value_counts().to_dict(),
    })


if __name__ == "__main__":
    print("Starting dashboard at http://localhost:5000")
    app.run(debug=True, port=5000)
