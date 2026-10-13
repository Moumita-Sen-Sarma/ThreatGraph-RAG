from threatgraph.graph.client import Neo4jClient
from threatgraph.llm.client import LLMClient
from threatgraph.rag.entity_resolver import (
    EntityResolver,
)
from threatgraph.rag.graph_rag import GraphRAG
from threatgraph.rag.hybrid_rag import HybridRAG
from threatgraph.rag.router import QueryRouter
from threatgraph.retrieval.graph import (
    GraphRetriever,
)
from threatgraph.retrieval.vector import (
    VectorRetriever,
)
from threatgraph.rag.fusion import EvidenceFusion
from threatgraph.rag.provenance import (
    ProvenanceNormalizer,
)

from threatgraph.rag.citations import (
    CitationValidator,
)


def main() -> None:

    neo4j_client = Neo4jClient()

    try:
        # -----------------------------
        # Graph components
        # -----------------------------

        neo4j_client.verify_connection()

        graph_retriever = GraphRetriever(
            neo4j_client
        )

        # -----------------------------
        # Vector component
        # -----------------------------

        vector_retriever = VectorRetriever()

        # -----------------------------
        # Shared LLM
        # -----------------------------

        llm = LLMClient()

        # -----------------------------
        # Query understanding
        # -----------------------------

        router = QueryRouter(
            llm=llm
        )

        resolver = EntityResolver(
            retriever=graph_retriever
        )

        fusion = EvidenceFusion(
            min_vector_score=0.40
        )

        provenance = ProvenanceNormalizer()

        citation_validator = CitationValidator()
        # -----------------------------
        # Graph-RAG
        # -----------------------------

        graph_rag = GraphRAG(
            retriever=graph_retriever,
            llm=llm,
            router=router,
            resolver=resolver,
        )

        # -----------------------------
        # Hybrid RAG
        # -----------------------------

        hybrid_rag = HybridRAG(
            graph_rag=graph_rag,
            vector_retriever=vector_retriever,
            llm=llm,
            fusion=fusion,
            provenance=provenance,
            validator=(
                citation_validator
            ),
        )

        question = (
            "If Cozy Bear performs credential "
            "dumping, what mitigations should "
            "we apply?"
        )

        result = hybrid_rag.answer(
            question,
            top_k=5,
        )

        print("\nQUESTION")
        print("-" * 60)
        print(result["question"])

        print("\nROUTE")
        print("-" * 60)
        print(result["route"])

        print("\nRESOLVED ENTITIES")
        print("-" * 60)
        print(
            result["resolved_entities"]
        )


        print("\nFUSION SUMMARY")
        print("-" * 60)

        print(
            "Raw graph evidence:",
            len(
                result[
                    "raw_graph_evidence"
                ]
            ),
        )

        print(
            "Fused graph evidence:",
            len(
                result[
                    "graph_evidence"
                ]
            ),
        )

        print(
            "Raw vector evidence:",
            len(
                result[
                    "raw_vector_evidence"
                ]
            ),
        )

        print(
            "Fused vector evidence:",
            len(
                result[
                    "vector_evidence"
                ]
            ),
        )

        print("\nGRAPH EVIDENCE")
        print("-" * 60)

        for item in result["graph_evidence"]:

            print(
                item["evidence_id"],
                item["data"],
            )

        print("\nVECTOR EVIDENCE")
        print("-" * 60)

        for item in result["vector_evidence"]:

            document = item["data"]

            print(
                item["evidence_id"],
                document["title"],
                f"score={document['score']:.4f}",
            )

        print("\nFINAL HYBRID ANSWER")
        print("-" * 60)
        print(result["answer"])

        print("\nCITATION VALIDATION")
        print("-" * 60)

        print(
            result["citation_validation"]
        )

    finally:
        neo4j_client.close()


if __name__ == "__main__":
    main()