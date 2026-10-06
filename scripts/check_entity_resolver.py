from threatgraph.graph.client import Neo4jClient
from threatgraph.rag.entity_resolver import EntityResolver
from threatgraph.retrieval.graph import GraphRetriever


def main() -> None:
    client = Neo4jClient()

    try:
        client.verify_connection()

        retriever = GraphRetriever(
            client
        )

        resolver = EntityResolver(
            retriever
        )

        test_values = [
            "APT29",
            "Cozy Bear",
            "T1003",
            "Credential Dumping",
        ]

        for value in test_values:
            print("\nINPUT")
            print("-" * 50)
            print(value)

            result = resolver.resolve(
                value
            )

            print("\nRESOLVED ENTITY")
            print(result)

    finally:
        client.close()


if __name__ == "__main__":
    main()