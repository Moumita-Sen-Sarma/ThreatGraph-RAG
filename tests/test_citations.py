from threatgraph.rag.citations import (
    CitationValidator,
)


def test_valid_citations():

    validator = CitationValidator()

    graph = [
        {
            "evidence_id": "G1",
            "data": {},
        }
    ]

    vector = [
        {
            "evidence_id": "V1",
            "data": {},
        }
    ]

    answer = (
        "Use this mitigation [G1]. "
        "Additional context appears in [V1]."
    )

    result = validator.validate(
        answer,
        graph,
        vector,
    )

    assert (
        result["all_citations_valid"]
        is True
    )

    assert (
        result["invalid_citations"]
        == []
    )


def test_invalid_citation():

    validator = CitationValidator()

    graph = [
        {
            "evidence_id": "G1",
            "data": {},
        }
    ]

    vector = []

    answer = (
        "This statement is supported "
        "by [G9]."
    )

    result = validator.validate(
        answer,
        graph,
        vector,
    )

    assert (
        result["all_citations_valid"]
        is False
    )

    assert (
        result["invalid_citations"]
        == ["G9"]
    )

def test_resolution_citation():

    validator = CitationValidator()

    graph = []
    vector = []

    resolution = [
        {
            "evidence_id": "R1",
            "data": {
                "role": "group",
                "name": "APT29",
            },
        }
    ]

    answer = (
        "Cozy Bear was resolved to APT29 [R1]."
    )

    result = validator.validate(
        answer=answer,
        graph_evidence=graph,
        vector_evidence=vector,
        resolution_evidence=resolution,
    )

    assert (
        result["all_citations_valid"]
        is True
    )

    assert (
        result["invalid_citations"]
        == []
    )

def test_invalid_resolution_citation():

    validator = CitationValidator()

    answer = (
        "Cozy Bear was resolved to APT29 [R99]."
    )

    result = validator.validate(
        answer=answer,
        graph_evidence=[],
        vector_evidence=[],
        resolution_evidence=[
            {
                "evidence_id": "R1",
                "data": {},
            }
        ],
    )

    assert (
        result["all_citations_valid"]
        is False
    )

    assert (
        result["invalid_citations"]
        == ["R99"]
    )