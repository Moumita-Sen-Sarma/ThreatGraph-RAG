import os

from dotenv import load_dotenv
from neo4j import GraphDatabase


load_dotenv()


class Neo4jClient:
    def __init__(self) -> None:
        self.uri = os.environ["NEO4J_URI"]
        self.username = os.environ["NEO4J_USERNAME"]
        self.password = os.environ["NEO4J_PASSWORD"]
        self.database = os.getenv(
            "NEO4J_DATABASE",
            "neo4j",
        )

        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(
                self.username,
                self.password,
            ),
        )

    def verify_connection(self) -> None:
        """
        Confirm that Python can communicate with Neo4j.
        """
        self.driver.verify_connectivity()

    def close(self) -> None:
        """
        Close the Neo4j connection pool cleanly.
        """
        self.driver.close()