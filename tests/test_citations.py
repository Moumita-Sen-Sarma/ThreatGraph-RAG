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