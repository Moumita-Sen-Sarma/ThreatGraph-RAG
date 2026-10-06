from threatgraph.graph.client import Neo4jClient
from threatgraph.llm.client import LLMClient
from threatgraph.rag.graph_rag import GraphRAG
from threatgraph.retrieval.graph import GraphRetriever
from threatgraph.rag.router import QueryRouter
from threatgraph.rag.entity_resolver import EntityResolver


def main() -> None:

    neo4j_client = Neo4jClient()

    try:
        neo4j_client.verify_connection()

        retriever = GraphRetriever(
            neo4j_client
        )

        llm = LLMClient()

        router = QueryRouter(llm=llm)

        resolver = EntityResolver(
            retriever=retriever
        )

        rag = GraphRAG(
            retriever=retriever,
            llm=llm,
            router=router,
            resolver=resolver
        )

        # result = (
        #     rag.answer_group_techniques(
        #         "APT29"
        #     )
        # )

        # print("\nANSWER")
        # print("-" * 60)
        # print(result["answer"])

        # # print("\nGRAPH EVIDENCE")
        # # print("-" * 60)

        # # for row in result[
        # #     "graph_evidence"
        # # ][:10]:
        # #     print(
        # #         row["technique_id"],
        # #         row["technique_name"],
        # #     )
        

        # print("\nAPT29 SOFTWARE")
        # print("-" * 60)

        # result = rag.answer_group_software(
        #     "APT29"
        # )
        # print(result["answer"])


        # print("\nT1003 MITIGATIONS")
        # print("-" * 60)

        # result = rag.answer_technique_mitigations(
        #     "T1003"
        # )
        # print(result["answer"])
    
        # print("\nMULTI-HOP GRAPH-RAG")
        # print("-" * 60)

        # result = (
        #     rag.answer_group_technique_mitigations(
        #         "APT29",
        #         "Credential Dumping",
        #     )
        # )

        # print(result["question"])
        # print(result["answer"])

        # print("\nEvidence:")

        # for row in result["graph_evidence"]:
        #     print(
        #         row["used_technique_id"],
        #         row["used_technique_name"],
        #         "->",
        #         row["mitigation_id"],
        #         row["mitigation_name"],
        #     )
        # question = (
        #     "If APT29 performs Credential Dumping, "
        #     "what mitigations should we apply?"
        # )

        question = (
            "If Cozy Bear performs credential dumping, "
            "what mitigations should we apply?"
        )

        result = rag.answer(
            question
        )

        print("\nQUESTION")
        print("-" * 60)
        print(question)

        print("\nROUTE")
        print("-" * 60)
        print(result["route"])
        # print(result)

        print("\nANSWER")
        print("-" * 60)
        print(result["answer"])

        print("\nGRAPH EVIDENCE")
        print("-" * 60)

        for row in result.get(
            "graph_evidence",
            [],
        ):
            print(row)

    finally:
        neo4j_client.close()


if __name__ == "__main__":
    main()