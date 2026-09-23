from threatgraph.ingestion.mitre import (
    get_external_id,
    is_revoked_or_deprecated,
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