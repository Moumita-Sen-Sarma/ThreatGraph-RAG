from __future__ import annotations

from mcp.server import MCPServer

from threatgraph.graph.client import Neo4jClient
from threatgraph.retrieval.graph import GraphRetriever


mcp = MCPServer(
    "ThreatGraph"
)

neo4j_client = Neo4jClient()

graph_retriever = GraphRetriever(
    neo4j_client
)


@mcp.tool()
def health() -> dict:
    """
    Check whether the ThreatGraph MCP server
    is running.
    """

    return {
        "status": "ok",
        "service": "ThreatGraph MCP",
    }

@mcp.tool()
def find_group_techniques(
    group_name: str,
) -> dict:
    """
    Return MITRE ATT&CK techniques used by
    the specified threat group.
    """

    results = (
        graph_retriever
        .get_group_techniques(
            group_name
        )
    )

    return {
        "group_name": group_name,
        "techniques": results,
        "count": len(results),
    }

@mcp.tool()
def find_group_mitigations(
    group_name: str,
) -> dict:
    """
    Return mitigations associated with techniques
    used by the specified threat group.
    """

    results = (
        graph_retriever
        .get_group_mitigations(
            group_name
        )
    )

    return {
        "group_name": group_name,
        "mitigations": results,
        "count": len(results),
    }