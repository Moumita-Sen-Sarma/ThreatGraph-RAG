from threatgraph.ingestion.mitre import (
    get_external_id,
    is_revoked_or_deprecated,
    parse_relationship,
    parse_campaign
)

def test_get_external_id() -> None:
    obj = {
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1003",
            }
        ]
    }

    assert get_external_id(obj) == "T1003"


def test_get_external_id_missing() -> None:
    obj = {
        "external_references": []
    }

    assert get_external_id(obj) is None


def test_revoked_object() -> None:
    obj = {
        "revoked": True
    }

    assert is_revoked_or_deprecated(obj) is True


def test_deprecated_object() -> None:
    obj = {
        "x_mitre_deprecated": True
    }

    assert is_revoked_or_deprecated(obj) is True


def test_active_object() -> None:
    obj = {}

    assert is_revoked_or_deprecated(obj) is False

def test_parse_relationship() -> None:
    obj = {
        "id": "relationship--123",
        "source_ref": "intrusion-set--abc",
        "target_ref": "attack-pattern--xyz",
        "relationship_type": "uses",
        "description": "Example relationship",
    }

    relationship = parse_relationship(obj)

    assert relationship.stix_id == "relationship--123"
    assert relationship.source_ref == "intrusion-set--abc"
    assert relationship.target_ref == "attack-pattern--xyz"
    assert relationship.relationship_type == "uses"

def test_parse_campaign() -> None:
    obj = {
        "id": "campaign--123",
        "name": "Example Campaign",
        "description": "Example description",
        "aliases": ["Example Alias"],
    }

    campaign = parse_campaign(obj)

    assert campaign.stix_id == "campaign--123"
    assert campaign.name == "Example Campaign"
    assert campaign.aliases == ["Example Alias"]