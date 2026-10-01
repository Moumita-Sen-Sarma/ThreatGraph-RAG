def classify_graph_question(
    question: str,
) -> str:

    q = question.lower()

    if (
        "technique" in q
        and "use" in q
    ):
        return "group_techniques"

    if (
        "software" in q
        or "tool" in q
    ):
        return "group_software"

    if (
        "mitigation" in q
        or "mitigate" in q
    ):
        return "technique_mitigations"

    return "unknown"