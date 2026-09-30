from threatgraph.models.schema import (
    AttackTechnique,
)
from threatgraph.retrieval.documents import (
    mitre_to_documents,
)


def test_technique_to_document():

    technique = AttackTechnique(
        stix_id="attack-pattern--123",
        external_id="T1003",
        name="OS Credential Dumping",
        description="Credential dumping.",
        platforms=["Windows"],
    )

    data = {
        "techniques": [technique],
        "groups": [],
        "software": [],
        "mitigations": [],
    }

    documents = mitre_to_documents(
        data
    )

    assert len(documents) == 1

    document = documents[0]

    assert (
        document.title
        == "OS Credential Dumping"
    )

    assert "T1003" in document.text

    assert "Windows" in document.text