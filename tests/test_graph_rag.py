from threatgraph.rag.graph_rag import GraphRAG


class FakeGraphRetriever:

    def get_group_techniques(
        self,
        group_name: str,
    ) -> list[dict]:

        assert group_name == "APT29"

        return [
            {
                "technique_id": "T1003",
                "technique_name":
                    "OS Credential Dumping",
                "description":
                    "Credential dumping."
            }
        ]


class FakeLLM:

    def generate(
        self,
        instructions: str,
        prompt: str,
    ) -> str:

        assert "T1003" in prompt
        assert "OS Credential Dumping" in prompt

        return (
            "APT29 is associated with "
            "T1003 OS Credential Dumping."
        )


def test_graph_rag_group_techniques():

    rag = GraphRAG(
        retriever=FakeGraphRetriever(),
        llm=FakeLLM(),
    )

    result = (
        rag.answer_group_techniques(
            "APT29"
        )
    )

    assert "T1003" in result["answer"]

    assert len(
        result["graph_evidence"]
    ) == 1