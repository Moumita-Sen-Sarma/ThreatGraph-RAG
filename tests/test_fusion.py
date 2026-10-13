from threatgraph.rag.fusion import (
    EvidenceFusion,
)


def test_graph_mitigation_deduplication():

    fusion = EvidenceFusion()

    rows = [
        {
            "group_name": "APT29",
            "requested_technique_id": "T1003",
            "requested_technique_name":
                "OS Credential Dumping",

            "used_technique_id":
                "T1003.002",

            "used_technique_name":
                "Security Account Manager",

            "mitigation_id":
                "M1026",

            "mitigation_name":
                "Privileged Account Management",

            "mitigation_description":
                "Manage privileged accounts.",
        },

        {
            "group_name": "APT29",
            "requested_technique_id": "T1003",
            "requested_technique_name":
                "OS Credential Dumping",

            "used_technique_id":
                "T1003.004",

            "used_technique_name":
                "LSA Secrets",

            "mitigation_id":
                "M1026",

            "mitigation_name":
                "Privileged Account Management",

            "mitigation_description":
                "Manage privileged accounts.",
        },
    ]

    result = (
        fusion.fuse_graph_evidence(
            rows
        )
    )

    # Two raw rows should become
    # one mitigation record.
    assert len(result) == 1

    assert (
        result[0]["mitigation_id"]
        == "M1026"
    )

    # But information about BOTH techniques
    # must still be preserved.
    assert (
        len(
            result[0][
                "supporting_techniques"
            ]
        )
        == 2
    )

def test_vector_score_filtering():

    fusion = EvidenceFusion(
        min_vector_score=0.40
    )

    documents = [
        {
            "document_id": "doc-1",
            "title": "Credential Dumping",
            "source": "MITRE ATT&CK",
            "score": 0.45,
        },

        {
            "document_id": "doc-2",
            "title": "Weak Match",
            "source": "MITRE ATT&CK",
            "score": 0.30,
        },
    ]

    result = (
        fusion.fuse_vector_evidence(
            documents
        )
    )

    assert len(result) == 1

    assert (
        result[0]["document_id"]
        == "doc-1"
    )

def test_vector_deduplication():

    fusion = EvidenceFusion(
        min_vector_score=0.40
    )

    documents = [
        {
            "document_id": "doc-1",
            "title": "Credential Dumping",
            "source": "MITRE ATT&CK",
            "score": 0.45,
        },

        {
            "document_id": "doc-1",
            "title": "Credential Dumping",
            "source": "MITRE ATT&CK",
            "score": 0.44,
        },
    ]

    result = (
        fusion.fuse_vector_evidence(
            documents
        )
    )

    assert len(result) == 1