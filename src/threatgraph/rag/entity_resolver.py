from __future__ import annotations
from typing import Optional

from threatgraph.retrieval.graph import GraphRetriever


class EntityResolver:
    """
    Resolve free-form entity names to canonical
    entities stored in Neo4j.
    """

    def __init__(
        self,
        retriever: GraphRetriever,
    ) -> None:
        self.retriever = retriever

    def resolve(
        self,
        value: str,
        expected_label: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Resolve a user-provided string to one
        canonical graph entity.
        """

        candidates = self.retriever.find_entity(
            value
        )

        # Handle hierarchical ATT&CK names such as:
        #
        # OS Credential Dumping:
        # Security Account Manager
        #
        # If the full string does not resolve,
        # try the most specific component first.
        if not candidates and ":" in value:

            parts = [
                part.strip()
                for part in value.split(":")
                if part.strip()
            ]

            for candidate_value in reversed(parts):

                candidates = (
                    self.retriever.find_entity(
                        candidate_value
                    )
                )

                if candidates:
                    break

        if not candidates:
            return None

        if expected_label:
            candidates = [
                candidate
                for candidate in candidates
                if expected_label
                in candidate["labels"]
            ]

        if not candidates:
            return None

        return candidates[0]