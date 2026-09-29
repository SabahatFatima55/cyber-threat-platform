"""
Investigation Agent
----------------------
Wraps the AI Incident Investigation Engine + Knowledge Graph builder.
Produces the structured incident reports (timeline, root cause, related
events, affected systems, suspected user, possible malware family) that
the case study's "AI Incident Investigation" module asks for.
"""

from agents.base_agent import BaseAgent
from graph.knowledge_graph import build_knowledge_graph, graph_stats
from investigation.incident_investigator import generate_all_incidents


class InvestigationAgent(BaseAgent):
    name = "InvestigationAgent"
    role = "Builds the knowledge graph and generates structured incident investigation reports"

    def run(self, state):
        df = state["df"]
        G = build_knowledge_graph(df)
        stats = graph_stats(G)

        incidents = generate_all_incidents(df, G, top_n=10)

        self.log(
            f"Built knowledge graph ({stats['total_nodes']} nodes, {stats['total_edges']} edges) "
            f"and generated {len(incidents)} structured incident reports for top-risk assets.",
            graph_stats=stats, incident_count=len(incidents),
        )
        state["graph"] = G
        state["graph_stats"] = stats
        state["incidents"] = incidents
        return state
