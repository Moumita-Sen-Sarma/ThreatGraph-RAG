from threatgraph.rag.graph_rag import GraphRAG
from threatgraph.rag.query_models import GraphQuery
from typing import Optional


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



class FakeRouter:
    def route(
        self,
        question: str,
    ) -> GraphQuery:
        return GraphQuery(
            intent="group_techniques",
            group_name="APT29",
            technique=None,
        )

class FakeResolver:
    def resolve(
        self,
        value: str,
        expected_label: Optional[str] = None,
    ) -> Optional[dict]:

        if expected_label == "ThreatGroup":
            return {
                "labels": ["CTIEntity", "ThreatGroup"],
                "stix_id": "intrusion-set--123",
                "external_id": None,
                "name": "APT29",
                "aliases": ["Cozy Bear"],
            }

        if expected_label == "AttackTechnique":
            return {
                "labels": ["CTIEntity", "AttackTechnique"],
                "stix_id": "attack-pattern--123",
                "external_id": "T1003",
                "name": "OS Credential Dumping",
                "aliases": [],
            }

        return None

def test_graph_rag_group_techniques():

    rag = GraphRAG(
        retriever=FakeGraphRetriever(),
        llm=FakeLLM(),
        router=FakeRouter(),
        resolver=FakeResolver()
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