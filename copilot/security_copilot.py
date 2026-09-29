"""
AI Security Copilot
----------------------
Answers analyst questions about the current dataset in plain language.

Two layers, matching the case study's "LLM-based Incident Summarization"
+ "RAG Pipeline" AI components:

  1. Intent-based fast path (keyword/pattern matching over the processed
     dataframe) for the handful of questions a SOC analyst asks most
     often - instant, zero-cost, zero-dependency.
  2. RAG fallback (rag/rag_pipeline.py) for anything else - retrieves the
     most relevant suspicious flows via a TF-IDF vector store and either
     summarizes them extractively (no key needed) or, if
     ANTHROPIC_API_KEY is set, generates a natural-language answer with
     an LLM grounded in that retrieved context.

This means the Copilot works fully offline with zero setup, and
upgrades itself automatically the moment an API key is available - no
code change required.
"""

import pandas as pd
import re

from rag.rag_pipeline import RAGPipeline


class SecurityCopilot:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self._rag = None  # built lazily - the TF-IDF fit is not free

    @property
    def rag(self) -> RAGPipeline:
        if self._rag is None:
            self._rag = RAGPipeline(self.df)
        return self._rag

    def answer(self, question: str) -> str:
        q = question.lower().strip()

        if any(k in q for k in ["underperform", "which line", "production"]):
            return self._not_applicable()

        if "attack" in q and ("most" in q or "top" in q or "common" in q):
            return self._top_attacks()

        if "risk" in q and ("highest" in q or "top" in q or "critical" in q):
            return self._top_risk()

        if "which user" in q or "affected user" in q or "who was affected" in q:
            return self._affected_users()

        if "compromised" in q or "which server" in q or "which system" in q or "which machine" in q:
            return self._affected_systems()

        if "timeline" in q or "attack chain" in q or "what happened" in q:
            return self._general_timeline()

        if "mitre" in q or "technique" in q:
            return self._mitre_summary()

        if "recommend" in q or "next action" in q or "what should" in q:
            return self._recommendations()

        if "malware" in q or "family" in q:
            return self._malware_families()

        if "how many" in q and "suspicious" in q:
            return self._suspicious_count()

        # Fallback: anything else goes through the RAG pipeline instead of
        # a canned "I don't understand" - this is what makes the Copilot
        # able to answer open-ended, free-form analyst questions.
        return self._rag_fallback(question)

    def _rag_fallback(self, question: str) -> str:
        result = self.rag.answer(question)
        mode_note = "" if result["generation_mode"] == "llm" else " (retrieval-based answer - set ANTHROPIC_API_KEY for LLM-generated summaries)"
        return result["answer"] + mode_note

    def _not_applicable(self):
        return "This dataset covers network/security flows, not production lines - that question doesn't apply here."

    def _top_attacks(self):
        sus = self.df[self.df["verdict"] == "Suspicious"]
        counts = sus["attack_type"].value_counts().head(5)
        lines = [f"- {k}: {v} flows" for k, v in counts.items()]
        return "Top attack types detected:\n" + "\n".join(lines)

    def _top_risk(self):
        top = self.df.sort_values("risk_score", ascending=False).head(5)
        lines = []
        for _, r in top.iterrows():
            lines.append(
                f"- Flow #{r['flow_id']}: {r['src_ip']} -> {r['dst_ip']}:{r['dst_port']} "
                f"| risk={r['risk_score']} ({r['risk_level']}) | {r['attack_type']}"
            )
        return "Highest-risk flows right now:\n" + "\n".join(lines)

    def _affected_users(self):
        sus = self.df[self.df["verdict"] == "Suspicious"]
        counts = sus["user"].value_counts().head(5)
        lines = [f"- {k}: {v} suspicious flows" for k, v in counts.items()]
        return "Most-affected users:\n" + "\n".join(lines)

    def _affected_systems(self):
        sus = self.df[self.df["verdict"] == "Suspicious"]
        counts = sus["dst_ip"].value_counts().head(5)
        lines = [f"- {k}: targeted {v} times" for k, v in counts.items()]
        return "Most-targeted systems:\n" + "\n".join(lines)

    def _general_timeline(self):
        sus = self.df[self.df["verdict"] == "Suspicious"].sort_values("timestamp").head(5)
        lines = [
            f"- {r['timestamp']}: {r['attack_type']} from {r['src_ip']} -> {r['dst_ip']}:{r['dst_port']}"
            for _, r in sus.iterrows()
        ]
        return "Earliest suspicious events:\n" + "\n".join(lines)

    def _mitre_summary(self):
        sus = self.df[self.df["verdict"] == "Suspicious"]
        all_tech = []
        for val in sus["mitre_techniques"].dropna():
            if val:
                all_tech.extend(val.split(";"))
        if not all_tech:
            return "No MITRE techniques mapped yet."
        counts = pd.Series(all_tech).value_counts().head(5)
        lines = [f"- {k}: seen {v} times" for k, v in counts.items()]
        return "Top MITRE ATT&CK techniques observed:\n" + "\n".join(lines)

    def _recommendations(self):
        sus = self.df[self.df["verdict"] == "Suspicious"]
        recs = []
        if (sus["attack_type"] == "Brute Force").any():
            recs.append("Enforce account lockout / MFA on exposed admin ports (22, 3389, 445).")
        if (sus["attack_type"] == "DDoS").any():
            recs.append("Enable rate-limiting or upstream DDoS protection on public-facing services.")
        if (sus["attack_type"] == "Data Exfiltration").any():
            recs.append("Investigate large outbound transfers; consider DLP rules on sensitive egress ports.")
        if (sus["attack_type"] == "Malware C2").any():
            recs.append("Isolate hosts with long-lived low-volume external connections; check for beaconing malware.")
        if not recs:
            recs.append("No high-priority actions right now - continue monitoring.")
        return "Recommended next actions:\n" + "\n".join(f"- {r}" for r in recs)

    def _suspicious_count(self):
        n = (self.df["verdict"] == "Suspicious").sum()
        total = len(self.df)
        return f"{n} out of {total} flows ({n/total*100:.1f}%) were flagged suspicious."

    def _malware_families(self):
        if "possible_malware_family" not in self.df.columns:
            return "Malware family classification not available - run `python main.py` to regenerate outputs."
        sus = self.df[(self.df["verdict"] == "Suspicious") & (self.df["possible_malware_family"] != "Unclassified") & (self.df["possible_malware_family"] != "")]
        counts = sus["possible_malware_family"].value_counts().head(6)
        if counts.empty:
            return "No malware family could be attributed to current suspicious flows."
        lines = [f"- {k}: {v} matching flows" for k, v in counts.items()]
        return "Suspected malware families observed:\n" + "\n".join(lines)
