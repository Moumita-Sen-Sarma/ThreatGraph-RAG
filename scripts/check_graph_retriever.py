from threatgraph.graph.client import Neo4jClient
from threatgraph.retrieval.graph import GraphRetriever


def main() -> None:
    client = Neo4jClient()

    try:
        client.verify_connection()

        retriever = GraphRetriever(client)

        print("\nAPT29 techniques")
        print("-" * 40)

        techniques = retriever.get_group_techniques(
            "APT29"
        )

        for item in techniques[:10]:
            print(
                item["technique_id"],
                item["technique_name"],
            )

        print("\nAPT29 software")
        print("-" * 40)

        software = retriever.get_group_software(
            "APT29"
        )

        for item in software[:10]:
            print(item["software_name"])

        print("\nMitigations for T1003")
        print("-" * 40)

        mitigations = (
            retriever.get_technique_mitigations(
                "T1003"
            )
        )

        for item in mitigations:
            print(
                item["mitigation_id"],
                item["mitigation_name"],
            )

        print("\nAPT29 software → techniques")
        print("-" * 40)

        paths = retriever.get_group_software_techniques(
            "APT29"
        )

        for item in paths[:15]:
            print(
                item["software_name"],
                "->",
                item["technique_id"],
                item["technique_name"],
            )

    finally:
        client.close()


if __name__ == "__main__":
    main()