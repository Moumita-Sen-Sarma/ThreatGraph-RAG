from threatgraph.graph.client import Neo4jClient
from threatgraph.llm.client import LLMClient
from threatgraph.rag.graph_rag import GraphRAG
from threatgraph.retrieval.graph import GraphRetriever


def main() -> None:

    neo4j_client = Neo4jClient()

    try:
        neo4j_client.verify_connection()

        retriever = GraphRetriever(
            neo4j_client
        )

        llm = LLMClient()

        rag = GraphRAG(
            retriever=retriever,
            llm=llm,
        )

        result = (
            rag.answer_group_techniques(
                "APT29"
            )
        )

        print("\nANSWER")
        print("-" * 60)
        print(result["answer"])

        # print("\nGRAPH EVIDENCE")
        # print("-" * 60)

        # for row in result[
        #     "graph_evidence"
        # ][:10]:
        #     print(
        #         row["technique_id"],
        #         row["technique_name"],
        #     )
        

        print("\nAPT29 SOFTWARE")
        print("-" * 60)

        result = rag.answer_group_software(
            "APT29"
        )
        print(result["answer"])


        print("\nT1003 MITIGATIONS")
        print("-" * 60)

        result = rag.answer_technique_mitigations(
            "T1003"
        )
        print(result["answer"])

    finally:
        neo4j_client.close()


if __name__ == "__main__":
    main()