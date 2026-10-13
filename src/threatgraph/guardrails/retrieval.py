from __future__ import annotations

import re


class RetrievalGuardrail:
    """
    Inspect retrieved vector documents for
    instruction-like prompt-injection content.

    Retrieved threat-intelligence documents are
    treated as untrusted data, not instructions.
    """

    SUSPICIOUS_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+(all\s+)?prior\s+instructions",
        r"system\s+prompt",
        r"developer\s+message",
        r"reveal\s+.*api\s+key",
        r"reveal\s+.*password",
        r"do\s+not\s+follow\s+.*instructions",
        r"you\s+are\s+chatgpt",
        r"disregard\s+.*instructions",
    ]

    def __init__(self) -> None:
        self.patterns = [
            re.compile(
                pattern,
                re.IGNORECASE,
            )
            for pattern in self.SUSPICIOUS_PATTERNS
        ]

    def inspect_text(
        self,
        text: str,
    ) -> dict:
        """
        Inspect one text block for suspicious
        instruction-like content.
        """

        matches = []

        for pattern in self.patterns:
            if pattern.search(text):
                matches.append(
                    pattern.pattern
                )

        return {
            "suspicious": bool(matches),
            "matches": matches,
        }

    def inspect_documents(
        self,
        documents: list[dict],
    ) -> dict:
        """
        Split retrieved vector documents into
        safe and flagged groups.
        """

        safe_documents = []
        flagged_documents = []

        for document in documents:

            text = document.get(
                "text",
                "",
            )

            inspection = self.inspect_text(
                text
            )

            if inspection["suspicious"]:
                flagged_documents.append(
                    {
                        "document": document,
                        "matches": (
                            inspection["matches"]
                        ),
                    }
                )
            else:
                safe_documents.append(
                    document
                )

        return {
            "safe_documents":
                safe_documents,

            "flagged_documents":
                flagged_documents,
        }