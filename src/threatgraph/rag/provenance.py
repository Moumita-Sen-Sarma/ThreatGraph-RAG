from __future__ import annotations


class ProvenanceNormalizer:
    """
    Assign stable evidence IDs to graph and vector
    evidence before sending it to the LLM.

    Graph evidence:
        G1, G2, G3, ...

    Vector evidence:
        V1, V2, V3, ...
    """

    def normalize(
        self,
        graph_evidence: list[dict],
        vector_evidence: list[dict],
    ) -> dict:

        normalized_graph = []

        for index, row in enumerate(
            graph_evidence,
            start=1,
        ):
            normalized_graph.append(
                {
                    "evidence_id": f"G{index}",
                    "evidence_type": "graph",
                    "data": row,
                }
            )

        normalized_vector = []

        for index, document in enumerate(
            vector_evidence,
            start=1,
        ):
            normalized_vector.append(
                {
                    "evidence_id": f"V{index}",
                    "evidence_type": "vector",
                    "data": document,
                }
            )

        return {
            "graph": normalized_graph,
            "vector": normalized_vector,
        }