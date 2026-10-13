from __future__ import annotations

from collections import defaultdict


class EvidenceFusion:
    """
    Clean and combine graph and vector evidence
    before the evidence is sent to the LLM.

    Responsibilities:
    1. Deduplicate repeated graph mitigations.
    2. Preserve which techniques support each mitigation.
    3. Remove weak vector matches.
    4. Deduplicate vector documents.
    """

    def __init__(
        self,
        min_vector_score: float = 0.40,
    ) -> None:
        self.min_vector_score = min_vector_score

    def fuse_graph_evidence(
        self,
        rows: list[dict],
    ) -> list[dict]:
        """
        Deduplicate graph evidence.

        For multi-hop mitigation queries, the same
        mitigation may appear for multiple sub-techniques.

        Instead of keeping several repeated rows,
        combine them into one mitigation record while
        preserving all supporting techniques.
        """

        if not rows:
            return []

        # Detect whether these rows are from our
        # group-technique-mitigation multi-hop query.
        is_mitigation_query = all(
            "mitigation_id" in row
            for row in rows
        )

        if not is_mitigation_query:
            return self._deduplicate_generic_graph_rows(
                rows
            )

        grouped = defaultdict(
            lambda: {
                "mitigation_id": None,
                "mitigation_name": None,
                "mitigation_description": None,
                "supporting_techniques": [],
                "group_name": None,
                "requested_technique_id": None,
                "requested_technique_name": None,
            }
        )

        for row in rows:

            mitigation_id = row.get(
                "mitigation_id"
            )

            # If for some reason an ID is absent,
            # use the mitigation name as fallback.
            key = (
                mitigation_id
                or row.get("mitigation_name")
            )

            item = grouped[key]

            item["mitigation_id"] = (
                mitigation_id
            )

            item["mitigation_name"] = (
                row.get("mitigation_name")
            )

            item["mitigation_description"] = (
                row.get("mitigation_description")
                or row.get("description")
            )

            item["group_name"] = (
                row.get("group_name")
            )

            item["requested_technique_id"] = (
                row.get(
                    "requested_technique_id"
                )
            )

            item["requested_technique_name"] = (
                row.get(
                    "requested_technique_name"
                )
            )

            # Some graph queries use technique_id,
            # while the multi-hop query uses
            # used_technique_id.
            technique_id = (
                row.get("used_technique_id")
                or row.get("technique_id")
            )

            technique_name = (
                row.get("used_technique_name")
                or row.get("technique_name")
            )

            if technique_id or technique_name:

                technique = {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                }

                if (
                    technique
                    not in item[
                        "supporting_techniques"
                    ]
                ):
                    item[
                        "supporting_techniques"
                    ].append(
                        technique
                    )

        return list(grouped.values())

    def _deduplicate_generic_graph_rows(
        self,
        rows: list[dict],
    ) -> list[dict]:
        """
        Generic fallback for graph result types that
        are not mitigation records.
        """

        unique_rows = []
        seen = set()

        for row in rows:

            # Convert the dictionary into something
            # hashable so duplicates can be detected.
            fingerprint = tuple(
                sorted(
                    (
                        key,
                        str(value),
                    )
                    for key, value
                    in row.items()
                )
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            unique_rows.append(row)

        return unique_rows

    def fuse_vector_evidence(
        self,
        documents: list[dict],
    ) -> list[dict]:
        """
        Filter weak vector matches and remove
        duplicate documents.
        """

        filtered = []
        seen = set()

        for document in documents:

            score = document.get(
                "score",
                0.0,
            )

            # Remove results below our current
            # similarity threshold.
            if score < self.min_vector_score:
                continue

            # Prefer the stable document ID.
            # If unavailable, fall back to title/source.
            document_key = (
                document.get("document_id")
                or (
                    document.get("title"),
                    document.get("source"),
                )
            )

            if document_key in seen:
                continue

            seen.add(document_key)
            filtered.append(document)

        return filtered

    def fuse(
        self,
        graph_evidence: list[dict],
        vector_evidence: list[dict],
    ) -> dict:
        """
        Clean both evidence sources.
        """

        clean_graph = (
            self.fuse_graph_evidence(
                graph_evidence
            )
        )

        clean_vector = (
            self.fuse_vector_evidence(
                vector_evidence
            )
        )

        return {
            "graph_evidence": clean_graph,
            "vector_evidence": clean_vector,
        }