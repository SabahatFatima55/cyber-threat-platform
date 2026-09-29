# Deployment Guide

This guide covers running the platform locally (as-shipped) and what changes
are needed to deploy it as a real production SOC system.

---

## 1. Local Development (as-shipped)

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python main.py                  # generates data, runs the multi-agent pipeline
python dashboard/app.py         # http://localhost:5000
# or
python copilot/run_copilot.py   # terminal chat
pytest tests/ -v                # run the test suite
```

No API keys or external services are required. Everything — detection,
scoring, MITRE mapping, the knowledge graph, RAG retrieval, and the
Copilot's extractive summaries — runs fully offline.

### Optional: enable LLM-generated Copilot answers

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python dashboard/app.py
```

With the key set, the Copilot's RAG fallback path calls the Anthropic API
to generate natural-language answers grounded in retrieved incident
context, instead of the extractive summary. Everything else is unaffected.
Never commit a key to source control — always pass it via environment
variable or a secrets manager.

---

## 2. Docker (single container)

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python main.py
EXPOSE 5000
CMD ["python", "dashboard/app.py"]
```

```bash
docker build -t cyber-threat-platform .
docker run -p 5000:5000 -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY cyber-threat-platform
```

For production, run the Flask app behind Gunicorn instead of the dev
server:

```dockerfile
RUN pip install gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "dashboard.app:app"]
```

---

## 3. Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables LLM-generated Copilot answers via the RAG pipeline. Without it, the Copilot still works, using extractive retrieval summaries. |
| `FLASK_ENV` | No | Set to `production` to disable Flask debug mode before real deployment. |

---

## 4. Scaling to the Full Enterprise Case-Study Scope

The as-shipped prototype runs on ~8,000 synthetic flow records and a
single-process Flask app, by design, so every module runs end-to-end on a
laptop with zero setup. Taking it to the case study's full scale
(1.2B events/day, 85,000 employees) requires:

| Component | Prototype | Production |
|---|---|---|
| Data ingestion | CSV file, generated once | Kafka consumers reading real firewall/auth/cloud logs in real time |
| Detection at scale | Pandas in-memory | Spark/Flink streaming jobs; Isolation Forest retrained on a schedule |
| Knowledge graph | NetworkX (in-process, non-persistent) | Neo4j cluster with Cypher queries, so the graph survives restarts and scales past memory |
| Vector store | TF-IDF + sklearn kNN (in-process) | FAISS or ChromaDB with persistent storage; sentence-transformer embeddings instead of TF-IDF |
| Copilot / RAG generation | Extractive fallback, or a single Anthropic API call | LangChain/LlamaIndex-orchestrated RAG chain with conversation memory, streaming responses, and rate limiting |
| Web layer | Flask dev server, single process | FastAPI (async) behind Gunicorn/Uvicorn workers, or Flask + Gunicorn, behind a load balancer |
| State/caching | None | Redis for session state, rate limiting, and hot-path caching (e.g. dashboard summary stats) |
| Persistence | CSV/JSON files in `outputs/` | PostgreSQL for structured records (alerts, incidents, user/asset inventory) |
| Multi-agent orchestration | Sequential in-process agents (`agents/orchestrator.py`) | LangGraph or a message-queue-based agent bus, so agents can run concurrently and be scaled independently |
| Auth / audit logging | None | SSO integration, per-request audit log, RBAC on dashboard/API routes |

The agent boundaries and module interfaces (`run_detection(df)`,
`apply_risk_scoring(df)`, `VectorStore.query(text, k)`, etc.) are written so
that swapping the underlying implementation (e.g. NetworkX → Neo4j) does
not require rewriting the callers — see the "swap point" notes in each
module's docstring.

---

## 5. Health Checks

Once `python main.py` has run at least once, these files must exist for
the dashboard/Copilot to serve real data:

```
outputs/processed_logs.csv
outputs/alerts.json
outputs/investigations.json
outputs/agent_log.json
```

If any are missing, `dashboard/app.py` returns a clear
`FileNotFoundError` telling you to run `python main.py` first — this is
the platform's minimal readiness check.
