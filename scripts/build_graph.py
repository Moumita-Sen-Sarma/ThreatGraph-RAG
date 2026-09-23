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

    finally:
        client.close()


if __name__ == "__main__":
    main()