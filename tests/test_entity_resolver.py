from threatgraph.rag.entity_resolver import (
    EntityResolver,
)


class FakeRetriever:

    def find_entity(
        self,
        value: str,
    ) -> list[dict]:

        if value.lower() == "cozy bear":
            return [
                {
                    "labels": [
                        "CTIEntity",
                        "ThreatGroup",
                    ],
                    "stix_id":
                        "intrusion-set--123",
                    "external_id": None,
                    "cve_id": None,
                    "name": "APT29",
                    "aliases": [
                        "Cozy Bear"
                    ],
                }
            ]

        if (
            "security account manager"
            in value.lower()
        ):
            return [
                {
                    "labels": [
                        "CTIEntity",
                        "AttackTechnique",
                    ],
                    "stix_id":
                        "attack-pattern--456",
                    "external_id":
                        "T1003.002",
                    "cve_id": None,
                    "name":
                        "Security Account Manager",
                    "aliases": [],
                }
            ]

        return []


def test_resolve_alias():
    resolver = EntityResolver(
        FakeRetriever()
    )

    result = resolver.resolve(
        "Cozy Bear",
        expected_label="ThreatGroup",
    )

    assert result is not None

    assert result["name"] == "APT29"

def test_resolve_hierarchical_technique_name():

    resolver = EntityResolver(
        FakeRetriever()
    )

    result = resolver.resolve(
        (
            "OS Credential Dumping: "
            "Security Account Manager"
        ),
        expected_label="AttackTechnique",
    )

    assert result is not None

    assert (
        result["name"]
        == "Security Account Manager"
    )

    assert (
        result["external_id"]
        == "T1003.002"
    )

def test_resolve_technique_in_longer_phrase():

    resolver = EntityResolver(
        FakeRetriever()
    )

    result = resolver.resolve(
        "Security Account Manager credential dumping",
        expected_label="AttackTechnique",
    )

    assert result is not None

    assert result["name"] == (
        "Security Account Manager"
    )

    assert result["external_id"] == "T1003.002"