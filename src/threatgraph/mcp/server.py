from __future__ import annotations

from mcp.server import MCPServer

from threatgraph.graph.client import Neo4jClient
from threatgraph.retrieval.graph import GraphRetriever
from threatgraph.retrieval.vector import (
    VectorRetriever,
)
from threatgraph.rag.entity_resolver import (
    EntityResolver,
)
from threatgraph.llm.client import LLMClient

from threatgraph.rag.router import QueryRouter
from threatgraph.rag.graph_rag import GraphRAG
from threatgraph.rag.hybrid_rag import HybridRAG
from threatgraph.rag.fusion import EvidenceFusion
from threatgraph.rag.provenance import (
    ProvenanceNormalizer,
)
from threatgraph.rag.citations import (
    CitationValidator,
)

from threatgraph.guardrails.output import (
    OutputGroundingGuardrail,
)
from threatgraph.guardrails.retrieval import (
    RetrievalGuardrail,
)


mcp = MCPServer(
    "ThreatGraph"
)

neo4j_client = Neo4jClient()

graph_retriever = GraphRetriever(
    neo4j_client
)

entity_resolver = EntityResolver(
    retriever=graph_retriever
)

# vector_retriever = VectorRetriever()
_vector_retriever: VectorRetriever | None = None


def get_vector_retriever() -> VectorRetriever:
    """
    Lazily initialize the vector retriever.

    The embedding model is loaded only when
    vector search is used for the first time.
    """

    global _vector_retriever

    if _vector_retriever is None:
        _vector_retriever = VectorRetriever()

    return _vector_retriever


_hybrid_rag: HybridRAG | None = None


def get_hybrid_rag() -> HybridRAG:
    """
    Lazily initialize the full ThreatGraph
    Hybrid RAG pipeline.
    """

    global _hybrid_rag

    if _hybrid_rag is None:

        llm = LLMClient()

        router = QueryRouter(
            llm=llm
        )

        resolver = EntityResolver(
            retriever=graph_retriever
        )

        graph_rag = GraphRAG(
            retriever=graph_retriever,
            llm=llm,
            router=router,
            resolver=resolver,
        )

        fusion = EvidenceFusion(
            min_vector_score=0.40
        )

        provenance = (
            ProvenanceNormalizer()
        )

        validator = CitationValidator()

        output_guardrail = (
            OutputGroundingGuardrail()
        )

        retrieval_guardrail = (
            RetrievalGuardrail()
        )

        _hybrid_rag = HybridRAG(
            graph_rag=graph_rag,
            vector_retriever=(
                get_vector_retriever()
            ),
            llm=llm,
            fusion=fusion,
            provenance=provenance,
            validator=validator,
            output_guardrail=(
                output_guardrail
            ),
            retrieval_guardrail=(
                retrieval_guardrail
            ),
        )

    return _hybrid_rag



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

@mcp.tool()
def search_evidence(
    query: str,
    top_k: int = 5,
) -> dict:
    """
    Search ThreatGraph's vector index for
    semantically relevant cyber-threat
    intelligence evidence.
    """

    retriever = get_vector_retriever()

    results = retriever.search(
        query,
        top_k=top_k,
    )

    return {
        "query": query,
        "results": results,
        "count": len(results),
    }

@mcp.tool()
def lookup_entity(
    value: str,
) -> dict:
    """
    Resolve a threat-intelligence name, alias,
    ATT&CK ID, or CVE to a canonical entity.
    """

    matches = graph_retriever.find_entity(
        value
    )

    return {
        "query": value,
        "matches": matches,
        "count": len(matches),
    }

@mcp.tool()
def ask_threatgraph(
    question: str,
    top_k: int = 5,
) -> dict:
    """
    Answer a cyber-threat intelligence question
    using ThreatGraph's full Hybrid RAG pipeline.
    """

    rag = get_hybrid_rag()

    result = rag.answer(
        question,
        top_k=top_k,
    )

    return {
        "question": result["question"],
        "answer": result["answer"],
        "route": result["route"],
        "resolved_entities": (
            result["resolved_entities"]
        ),
        "resolution_evidence": (
            result["resolution_evidence"]
        ),
        "graph_evidence": (
            result["graph_evidence"]
        ),
        "vector_evidence": (
            result["vector_evidence"]
        ),
        "citation_validation": (
            result["citation_validation"]
        ),
        "grounding_status": (
            result["grounding_status"]
        ),
        "repair_attempted": (
            result["repair_attempted"]
        ),
    }