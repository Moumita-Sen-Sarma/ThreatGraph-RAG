from threatgraph.guardrails.output import (
    OutputGroundingGuardrail,
)


def test_retry_when_citation_invalid():

    guardrail = (
        OutputGroundingGuardrail()
    )

    validation = {
        "all_citations_valid": False,
        "invalid_citations": ["G99"],
    }

    assert (
        guardrail.should_retry(
            validation
        )
        is True
    )


def test_no_retry_when_valid():

    guardrail = (
        OutputGroundingGuardrail()
    )

    validation = {
        "all_citations_valid": True,
        "invalid_citations": [],
    }

    assert (
        guardrail.should_retry(
            validation
        )
        is False
    )