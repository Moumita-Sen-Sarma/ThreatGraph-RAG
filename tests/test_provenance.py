from threatgraph.rag.provenance import (
    ProvenanceNormalizer,
)


def test_provenance_ids():

    normalizer = ProvenanceNormalizer()

    result = normalizer.normalize(
        graph_evidence=[
            {"name": "graph-one"},
            {"name": "graph-two"},
        ],
        vector_evidence=[
            {"title": "vector-one"},
        ],
    )

    assert (
        result["graph"][0][
            "evidence_id"
        ]
        == "G1"
    )

    assert (
        result["graph"][1][
            "evidence_id"
        ]
        == "G2"
    )

    assert (
        result["vector"][0][
            "evidence_id"
        ]
        == "V1"
    )