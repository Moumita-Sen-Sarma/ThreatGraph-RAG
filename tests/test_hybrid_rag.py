from threatgraph.rag.hybrid_rag import HybridRAG
from threatgraph.rag.fusion import EvidenceFusion
from threatgraph.rag.provenance import ProvenanceNormalizer
from threatgraph.rag.citations import CitationValidator


class FakeGraphRAG:

    def retrieve(
        self,
        question: str,
    ) -> dict:

        return {
            "route": {
                "intent":
                    "group_technique_mitigations",
                "group_name":
                    "Cozy Bear",
                "technique":
                    "credential dumping",
            },
            "resolved_entities": {
                "group": {
                    "name": "APT29",
                },
                "technique": {
                    "name":
                        "OS Credential Dumping",
                    "external_id":
                        "T1003",
                },
            },
            "graph_evidence": [
                {
                    "group_name":
                        "APT29",
                    "used_technique_id":
                        "T1003.002",
                    "used_technique_name":
                        "Security Account Manager",
                    "mitigation_id":
                        "M1027",
                    "mitigation_name":
                        "Password Policies",
                }
            ],
            "error": None,
        }


class FakeVectorRetriever:

    def search(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict]:

        return [
            {
                "score": 0.91,
                "title":
                    "OS Credential Dumping",
                "source":
                    "MITRE ATT&CK",
                "document_type":
                    "attack_technique",
                "text":
                    (
                        "Credential dumping may "
                        "expose operating system "
                        "credentials."
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

        assert "[G1]" in prompt
        assert "[V1]" in prompt

        assert "M1027" in prompt

        return (
            "Password Policies (M1027) are supported by "
            "the graph evidence [G1]. "
            "Additional context appears in [V1]."
        )


def test_hybrid_rag_answer():

    fusion = EvidenceFusion(
        min_vector_score=0.0
    )

    normalizer = ProvenanceNormalizer()
    validator = CitationValidator()

    rag = HybridRAG(
    graph_rag=FakeGraphRAG(),
    vector_retriever=FakeVectorRetriever(),
    llm=FakeLLM(),
    fusion=fusion,
    provenance=normalizer,
    validator=validator,
)

    result = rag.answer(
        (
            "If Cozy Bear performs credential "
            "dumping, what mitigations apply?"
        )
    )

    assert "M1027" in result["answer"]

    assert (
        len(result["graph_evidence"])
        == 1
    )

    assert (
        len(result["vector_evidence"])
        == 1
    )