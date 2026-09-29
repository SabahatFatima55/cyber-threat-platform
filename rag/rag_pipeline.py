"""
RAG Pipeline (Retrieval-Augmented Generation)
-------------------------------------------------
Builds a searchable "knowledge base" out of every suspicious flow's
explanation, MITRE mapping, and incident context, then answers analyst
questions by:
  1. RETRIEVE: pull the most relevant flows/incidents via VectorStore
  2. AUGMENT:  format retrieved context into a prompt
  3. GENERATE: hand that context + question to an LLM for a natural-
     language answer - OR, if no API key is configured, fall back to a
     clean extractive summary of the retrieved context (still a valid,
     fully functional answer with zero external dependency/cost).

This is the same retrieve -> augment -> generate pattern used by
LangChain/LlamaIndex RAG chains, implemented directly so the whole
platform runs with zero API keys out of the box. Set ANTHROPIC_API_KEY
to unlock the generation step.
"""

from __future__ import annotations
import os
import json
from typing import List, Dict, Any
import pandas as pd

from rag.vector_store import VectorStore

try:
    import anthropic  # optional - only needed if ANTHROPIC_API_KEY is set
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


def build_corpus(df: pd.DataFrame) -> tuple[List[str], List[Dict[str, Any]]]:
    """Turn every suspicious flow into a retrievable text document."""
    sus = df[df["verdict"] == "Suspicious"]
    texts, metadata = [], []
    for _, r in sus.iterrows():
        feed_note = ""
        if r.get("feed_match"):
            feed_note = f" This flow matched a known-bad threat intelligence feed indicator: {r.get('feed_source', '')}."
        family_note = ""
        if r.get("possible_malware_family") and r.get("possible_malware_family") not in ("", "Unclassified"):
            family_note = f" Suspected malware family: {r.get('possible_malware_family')}."
        doc = (
            f"Incident flow #{r['flow_id']} at {r['timestamp']}: "
            f"{r.get('attack_type', 'Unknown')} activity from {r['src_ip']} "
            f"(user: {r.get('user', 'unknown')}) to {r['dst_ip']} on port {r['dst_port']}. "
            f"Risk level: {r.get('risk_level', 'Unknown')} (score {r.get('risk_score', 0)}). "
            f"MITRE techniques: {r.get('mitre_techniques', 'none')}. "
            f"Reasoning: {r.get('explanation', 'no explanation available')}."
            f"{family_note}{feed_note}"
        )
        texts.append(doc)
        metadata.append({
            "flow_id": int(r["flow_id"]),
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "user": r.get("user", ""),
            "attack_type": r.get("attack_type", ""),
            "risk_score": int(r.get("risk_score", 0)),
        })
    return texts, metadata


class RAGPipeline:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.store = VectorStore()
        texts, metadata = build_corpus(df)
        if texts:
            self.store.build(texts, metadata)
        self.llm_enabled = _ANTHROPIC_AVAILABLE and bool(os.environ.get("ANTHROPIC_API_KEY"))
        if self.llm_enabled:
            self._client = anthropic.Anthropic()

    def retrieve(self, question: str, k: int = 6) -> List[Dict[str, Any]]:
        return self.store.query(question, k=k)

    def answer(self, question: str, k: int = 6) -> Dict[str, Any]:
        retrieved = self.retrieve(question, k=k)
        if not retrieved:
            return {
                "answer": "No relevant suspicious flows found in the knowledge base for that question.",
                "sources": [],
                "generation_mode": "none",
            }

        context = "\n".join(f"- {r['text']}" for r in retrieved)

        if self.llm_enabled:
            answer_text = self._generate_with_llm(question, context)
            mode = "llm"
        else:
            answer_text = self._generate_extractive(question, retrieved)
            mode = "extractive"

        return {
            "answer": answer_text,
            "sources": [r["metadata"] for r in retrieved],
            "generation_mode": mode,
        }

    def _generate_with_llm(self, question: str, context: str) -> str:
        prompt = (
            "You are a SOC (Security Operations Center) analyst assistant. "
            "Answer the analyst's question using ONLY the retrieved incident "
            "context below. Be concise, factual, and cite flow numbers when "
            "relevant.\n\n"
            f"Retrieved context:\n{context}\n\n"
            f"Analyst question: {question}\n\nAnswer:"
        )
        try:
            resp = self._client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
            return "\n".join(parts) if parts else self._generate_extractive(question, [])
        except Exception as e:
            return f"[LLM generation failed, falling back to retrieval only: {e}]\n\n" + context

    def _generate_extractive(self, question: str, retrieved: List[Dict[str, Any]]) -> str:
        """Zero-cost fallback: summarize retrieved docs without an LLM call."""
        lines = [f"Based on {len(retrieved)} most relevant incidents in the knowledge base:"]
        for r in retrieved[:5]:
            lines.append(f"  (relevance {r['score']:.2f}) {r['text']}")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    df = pd.read_csv(os.path.join(os.path.dirname(__file__), "..", "outputs", "processed_logs.csv"))
    rag = RAGPipeline(df)
    q = " ".join(sys.argv[1:]) or "What data exfiltration incidents happened?"
    result = rag.answer(q)
    print(json.dumps(result, indent=2))
