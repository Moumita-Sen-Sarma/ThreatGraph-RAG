from threatgraph.rag.router import QueryRouter


class FakeLLM:
    """
    Fake LLM used so pytest does not call
    the real API.
    """

    def generate(
        self,
        instructions: str,
        prompt: str,
    ) -> str:

        assert "APT29" in prompt
        assert "Credential Dumping" in prompt

        return """
        {
            "intent": "group_technique_mitigations",
            "group_name": "APT29",
            "technique": "Credential Dumping"
        }
        """


def test_router_extracts_graph_query():
    router = QueryRouter(
        llm=FakeLLM()
    )

    result = router.route(
        (
            "If APT29 performs Credential Dumping, "
            "what mitigations should we apply?"
        )
    )

    assert (
        result.intent
        == "group_technique_mitigations"
    )

    assert result.group_name == "APT29"

    assert (
        result.technique
        == "Credential Dumping"
    )