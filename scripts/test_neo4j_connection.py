from threatgraph.graph.client import Neo4jClient


def main() -> None:
    client = Neo4jClient()

    try:
        client.verify_connection()
        print("Neo4j connection successful.")
    finally:
        client.close()


if __name__ == "__main__":
    main()