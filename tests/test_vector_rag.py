from threatgraph.rag.vector_rag import VectorRAG


class FakeRetriever:
    def search(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict]:
        return [
            {
                "score": 0.9,
                "title": "OS Credential Dumping",
                "source": "MITRE ATT&CK",
                "document_type": "attack_technique",
                "text": (
                    "Adversaries may dump credentials "
                    "from operating system stores."
                ),
                "metadata": {},
            }
        ]


class FakeLLM:
    def generate(
        self,
        instructions: str,
        prompt: str,
    ) -> str:
        assert "OS Credential Dumping" in prompt

        return (
            "Attackers may dump credentials "
            "[SOURCE 1]."
        )


def test_vector_rag_answer():
    rag = VectorRAG(
        retriever=FakeRetriever(),
        llm=FakeLLM(),
    )

    result = rag.answer(
        "How can attackers obtain credentials?"
    )

    assert "SOURCE 1" in result["answer"]

    assert len(result["sources"]) == 1

    assert (
        result["sources"][0]["title"]
        == "OS Credential Dumping"
    )