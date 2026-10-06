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