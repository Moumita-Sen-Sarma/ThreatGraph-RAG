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

        # For now, return the first matching entity.
        return candidates[0]