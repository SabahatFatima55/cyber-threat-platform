# Enterprise Cyber Threat Intelligence & Autonomous Security Investigation Platform

An AI-powered security operations platform built for Ezitech Engineering
Framework case study **AI-001**. It ingests security flow logs, correlates
and scores threats, builds a security knowledge graph, maps detections to
MITRE ATT&CK, runs structured AI incident investigations through a
five-agent multi-agent workflow, and answers analyst questions through a
RAG-backed AI Security Copilot — all presented on a live web dashboard.

Runs fully offline with zero API keys and zero external services required.

---

## What's Implemented

| Module | Where |
|---|---|
| Security Data Pipeline | `data/generate_data.py` |
| AI Threat Correlation Engine — rules + Isolation Forest anomaly detection | `detection/threat_engine.py` |
| Threat Risk Engine | `risk/risk_engine.py` |
| Explainable AI — per-flow reasoning | `risk/risk_engine.py` |
| Security Knowledge Graph — NetworkX | `graph/knowledge_graph.py` |
| Attack Graph Builder | `graph/knowledge_graph.py` |
| AI Incident Investigation — timeline, root cause, related events, affected systems, suspected user, malware family | `investigation/incident_investigator.py` |
| AI Security Copilot — fast-path intents + RAG fallback | `copilot/security_copilot.py` |
| Threat Intelligence Dashboard — Flask + Chart.js | `dashboard/` |
| Notification / Alert Center | `risk/alert_center.py` |
| RAG Pipeline — retrieve -> augment -> generate | `rag/rag_pipeline.py` |
| Vector Database — TF-IDF + cosine kNN | `rag/vector_store.py` |
| Multi-Agent AI Architecture — 5 agents + orchestrator | `agents/` |
| MITRE ATT&CK Auto Mapping | `mitre/mitre_mapping.py` |
| Malware Family Classification | `detection/malware_classifier.py` |
| AI Threat Hunting Agent — multi-flow beaconing detection | `agents/hunting_agent.py` |
| Threat Intelligence Feed Aggregation | `intel/threat_feed.py` |
| Autonomous AI SOC Analyst — autonomous response decisioning | `agents/response_agent.py` |
| Multi-Agent Collaboration — shared state + full transcript | `agents/orchestrator.py` |

---

## Quick Start

```bash
# 1. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the full multi-agent pipeline (generates data, runs all 5 agents)
python main.py

# 4. Launch the web dashboard
python dashboard/app.py
# then open http://localhost:5000

# 5. (Optional) Chat with the Copilot from the terminal instead
python copilot/run_copilot.py

# 6. (Optional) Run the test suite
pytest tests/ -v
```

No API keys or external services required for any of the above — everything
runs fully offline.

---

## How It Works — Multi-Agent Pipeline

`main.py` runs a five-agent workflow (`agents/orchestrator.py`), each agent
reading and writing a shared state dict, with every step logged to
`outputs/agent_log.json` for a full auditable transcript:

1. **CorrelationAgent** (`agents/correlation_agent.py`) — wraps
   `detection/threat_engine.py`: rule-based detection (five explainable
   rules, e.g. "4+ failed logins = possible brute force") plus an
   Isolation Forest anomaly model that flags statistically unusual flows
   even when no rule matches.

2. **ThreatHuntingAgent** (`agents/hunting_agent.py`) — proactively hunts
   for multi-flow beaconing/C2 patterns (repeated long-lived, low-volume
   connections from one source) that no single-flow rule would catch, and
   escalates anything it finds to Suspicious.

3. **RiskAgent** (`agents/risk_agent.py`) — wraps `risk/risk_engine.py`
   (0-100 risk score + plain-English explanation, the Explainable AI
   requirement), `mitre/mitre_mapping.py` (MITRE ATT&CK technique IDs),
   `detection/malware_classifier.py` (likely malware family), and
   `intel/threat_feed.py` (cross-references flows against aggregated
   known-bad IOC feeds).

4. **InvestigationAgent** (`agents/investigation_agent.py`) — builds the
   Security Knowledge Graph (`graph/knowledge_graph.py`, Users -> Source
   IPs -> Destination IPs) and generates structured AI incident reports
   (`investigation/incident_investigator.py`) for the top 10 highest-risk
   assets: timeline, root cause, related events, affected systems,
   suspected user, and possible malware family — every field traceable to
   concrete evidence.

5. **ResponseAgent** (`agents/response_agent.py`) — the Autonomous AI SOC
   Analyst: for each investigated incident, autonomously decides a
   priority level and recommended response action (e.g. auto-isolate +
   credential reset for Critical incidents).

Outputs land in `outputs/`: `processed_logs.csv`, `alerts.json`,
`investigations.json`, `agent_log.json`.

---

## AI Security Copilot (RAG)

`copilot/security_copilot.py` answers analyst questions in two layers:

1. **Fast-path intents** — instant, zero-cost keyword matching for the
   handful of questions asked most often (top attacks, highest risk,
   affected users/systems, MITRE summary, recommendations, malware
   families).
2. **RAG fallback** (`rag/rag_pipeline.py`) — for anything else, retrieves
   the most relevant suspicious-flow "documents" via a TF-IDF vector store
   (`rag/vector_store.py`) and either:
   - summarizes them **extractively** (zero cost, zero setup), or
   - if `ANTHROPIC_API_KEY` is set, generates a natural-language answer
     with an LLM **grounded in that retrieved context** — the standard
     retrieve -> augment -> generate RAG pattern.

---

## Architecture Diagram

See `docs/architecture_diagram.svg` for the full diagram. Summary:

```
Security Data Pipeline (synthetic flow logs)
        |
        v
CorrelationAgent -> ThreatHuntingAgent -> RiskAgent -> InvestigationAgent -> ResponseAgent
        |                                                    |
        |        shared state: DataFrame + Knowledge Graph + Incidents
        |                                                    |
        v                                                    v
Alert Center (Notification Center)          Structured Incident Reports (XAI)
        |                                                    |
        +--------------------+-------------------------------+
                             v
              Threat Intelligence Dashboard (Flask)
                             |
                             v
              AI Security Copilot (fast-path + RAG)
```

---

## Technical Presentation

`docs/presentation.pptx` — an 8-slide overview covering the business
problem, the multi-agent architecture, the AI components, sample detection
results, a sample explainable incident report, and the dashboard/Copilot.

---

## Project Structure

```
cyber-threat-platform/
├── data/
│   ├── generate_data.py         # Security Data Pipeline
│   └── security_logs.csv        # Generated on first run
├── detection/
│   ├── threat_engine.py         # AI Threat Correlation Engine (rules + Isolation Forest)
│   └── malware_classifier.py    # Malware Family Classification
├── risk/
│   ├── risk_engine.py           # Risk scoring + Explainable AI
│   └── alert_center.py          # Notification Center
├── mitre/
│   └── mitre_mapping.py         # MITRE ATT&CK Auto Mapping
├── graph/
│   └── knowledge_graph.py       # Security Knowledge Graph + Attack Graph Builder
├── investigation/
│   └── incident_investigator.py # AI Incident Investigation Engine
├── rag/
│   ├── vector_store.py          # Vector store (TF-IDF + cosine kNN)
│   └── rag_pipeline.py          # RAG: retrieve -> augment -> generate
├── intel/
│   └── threat_feed.py           # Threat Intelligence Feed Aggregation
├── agents/
│   ├── base_agent.py
│   ├── correlation_agent.py
│   ├── hunting_agent.py         # AI Threat Hunting Agent
│   ├── risk_agent.py
│   ├── investigation_agent.py
│   ├── response_agent.py        # Autonomous AI SOC Analyst
│   └── orchestrator.py          # Multi-Agent AI Architecture
├── copilot/
│   ├── security_copilot.py      # Core Copilot logic (fast-path + RAG)
│   └── run_copilot.py           # Terminal interface
├── dashboard/
│   ├── app.py                   # Flask web server + REST API
│   └── templates/
│       └── dashboard.html       # Web dashboard UI
├── tests/
│   └── test_pipeline.py         # pytest suite for core modules
├── docs/
│   ├── architecture_diagram.svg
│   └── presentation.pptx
├── outputs/                     # Generated: processed_logs.csv, alerts.json,
│                                 #   investigations.json, agent_log.json
├── main.py                      # Pipeline orchestrator - run this first
├── requirements.txt
└── README.md
```

---

## Author

Sabahat Fatima — Software Engineering, Fatima Jinnah Women University
Case Study: Ezitech Engineering Framework, AI-001
