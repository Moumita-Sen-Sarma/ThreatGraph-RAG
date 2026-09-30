from threatgraph.graph.builder import (
    GraphBuilder,
)
from threatgraph.graph.client import (
    Neo4jClient,
)
from threatgraph.ingestion.cisa import (
    load_cisa_kev,
)


CISA_PATH = (
    "data/raw/cisa/"
    "known_exploited_vulnerabilities.json"
)


def main() -> None:
    print("Loading CISA KEV...")

    data = load_cisa_kev(
        CISA_PATH
    )

    client = Neo4jClient()
    client.verify_connection()

    builder = GraphBuilder(
        client
    )

    try:
        print("Creating vendors...")

        for vendor in data["vendors"]:
            builder.create_vendor(
                vendor
            )

        print("Creating products...")

        for product in data["products"]:
            builder.create_product(
                product
            )

        print(
            "Creating vulnerabilities..."
        )

        for vulnerability in (
            data["vulnerabilities"]
        ):
            builder.create_vulnerability(
                vulnerability
            )

        print(
            "Creating CISA relationships..."
        )

        for vulnerability in (
            data["vulnerabilities"]
        ):
            builder.connect_vulnerability(
                vulnerability
            )

        print(
            "CISA graph ingestion completed."
        )

    finally:
        client.close()


if __name__ == "__main__":
    main()