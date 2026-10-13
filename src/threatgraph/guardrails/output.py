from __future__ import annotations


class OutputGroundingGuardrail:
    """
    Decide whether an LLM answer passes citation
    validation.

    The actual citation checking is performed by
    CitationValidator.

    This guardrail decides what to do with the result.
    """

    def should_retry(
        self,
        validation: dict,
    ) -> bool:
        """
        Retry generation when one or more citations
        refer to nonexistent evidence IDs.
        """

        return not validation[
            "all_citations_valid"
        ]

    def failure_answer(self) -> str:
        """
        Safe fallback when citation repair fails.
        """

        return (
            "I could not produce a fully grounded "
            "answer from the retrieved evidence "
            "with valid citations."
        )