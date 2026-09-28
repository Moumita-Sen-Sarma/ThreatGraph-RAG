from threatgraph.graph.builder import GraphBuilder
from threatgraph.graph.client import Neo4jClient
from threatgraph.ingestion.mitre import load_mitre_objects


MITRE_PATH = "data/raw/mitre/enterprise-attack.json"


def main() -> None:
    print("Loading MITRE ATT&CK data...")

    data = load_mitre_objects(MITRE_PATH)

    client = Neo4jClient()
    client.verify_connection()

    builder = GraphBuilder(client)

    builder.create_constraints()

    try:
        print("Creating threat groups...")

        for group in data["groups"]:
            builder.create_threat_group(group)

        print("Creating attack techniques...")

        for technique in data["techniques"]:
            builder.create_attack_technique(
                technique
            )

        print("Creating software...")

        for software in data["software"]:
            builder.create_software(software)

        print("Creating mitigations...")

        for mitigation in data["mitigations"]:
            builder.create_mitigation(
                mitigation
            )

        print("Creating campaigns...")

        for campaign in data["campaigns"]:
            builder.create_campaign(campaign)

        print("Node ingestion completed.")

        print("Creating relationships...")

        created_count = 0
        skipped_count = 0

        for relationship in data["relationships"]:
            created = builder.create_relationship(
                relationship
            )

            if created:
                created_count += 1
            else:
                skipped_count += 1

        print(
            f"Relationships created: {created_count}"
        )

        print(
            f"Relationships skipped/not created: "
            f"{skipped_count}"
        )

    finally:
        client.close()


if __name__ == "__main__":
    main()