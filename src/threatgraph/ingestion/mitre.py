from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatgraph.models.schema import (
    AttackRelationship,
    AttackTechnique,
    Mitigation,
    Software,
    ThreatGroup,
    Campaign
)


def get_external_id(obj: dict[str, Any]) -> str | None:
    """
    Extract the human-readable MITRE ATT&CK ID.

    Example:
        STIX object id:
            attack-pattern--abc...

        ATT&CK external id:
            T1003
    """
    for reference in obj.get("external_references", []):
        external_id = reference.get("external_id")

        if external_id:
            return external_id

    return None


def is_revoked_or_deprecated(obj: dict[str, Any]) -> bool:
    """
    Return True if a MITRE ATT&CK object should be ignored.

    MITRE may keep revoked or deprecated objects in the STIX bundle
    for historical compatibility, but we do not want to use them
    in the current ThreatGraph.
    """
    return bool(
        obj.get("revoked", False)
        or obj.get("x_mitre_deprecated", False)
    )


def parse_threat_group(obj: dict[str, Any]) -> ThreatGroup:
    """
    Convert a STIX intrusion-set object into our ThreatGroup schema.
    """
    return ThreatGroup(
        stix_id=obj["id"],
        name=obj["name"],
        description=obj.get("description"),
        aliases=obj.get("aliases", []),
    )


def parse_attack_technique(
    obj: dict[str, Any]
) -> AttackTechnique:
    """
    Convert a STIX attack-pattern object into our
    AttackTechnique schema.
    """
    return AttackTechnique(
        stix_id=obj["id"],
        external_id=get_external_id(obj),
        name=obj["name"],
        description=obj.get("description"),
        platforms=obj.get("x_mitre_platforms", []),
    )


def parse_software(obj: dict[str, Any]) -> Software:
    """
    Convert a STIX malware or tool object into our Software schema.
    """
    aliases = obj.get("x_mitre_aliases", [])

    # Some software objects may expose aliases differently.
    # Fall back to an empty list if none exist.
    return Software(
        stix_id=obj["id"],
        name=obj["name"],
        description=obj.get("description"),
        aliases=aliases,
    )


def parse_mitigation(obj: dict[str, Any]) -> Mitigation:
    """
    Convert a STIX course-of-action object into our
    Mitigation schema.
    """
    return Mitigation(
        stix_id=obj["id"],
        external_id=get_external_id(obj),
        name=obj["name"],
        description=obj.get("description"),
    )

def parse_relationship(
    obj: dict[str, Any]
) -> AttackRelationship:
    """
    Convert a STIX relationship object into our
    normalized AttackRelationship schema.
    """
    return AttackRelationship(
        stix_id=obj["id"],
        source_ref=obj["source_ref"],
        target_ref=obj["target_ref"],
        relationship_type=obj["relationship_type"],
        description=obj.get("description"),
    )


def parse_campaign(obj: dict[str, Any]) -> Campaign:
    """
    Convert a STIX campaign object into our Campaign schema.
    """
    return Campaign(
        stix_id=obj["id"],
        name=obj["name"],
        description=obj.get("description"),
        aliases=obj.get("aliases", []),
    )


def load_mitre_objects(
    path: str | Path,
) -> dict[str, list]:
    """
    Load the MITRE ATT&CK STIX bundle and normalize
    the object types needed for ThreatGraph.
    """
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        bundle = json.load(file)

    groups: list[ThreatGroup] = []
    techniques: list[AttackTechnique] = []
    software: list[Software] = []
    mitigations: list[Mitigation] = []
    relationships: list[AttackRelationship] = []
    campaigns: list[Campaign] = []

    for obj in bundle.get("objects", []):
        if is_revoked_or_deprecated(obj):
            continue

        object_type = obj.get("type")

        if object_type == "intrusion-set":
            groups.append(parse_threat_group(obj))

        elif object_type == "attack-pattern":
            techniques.append(parse_attack_technique(obj))

        elif object_type in {"malware", "tool"}:
            software.append(parse_software(obj))

        elif object_type == "course-of-action":
            mitigations.append(parse_mitigation(obj))

        elif object_type == "relationship":
            relationships.append(parse_relationship(obj))
        elif object_type == "campaign":
            campaigns.append(parse_campaign(obj))

    return {
        "groups": groups,
        "techniques": techniques,
        "software": software,
        "mitigations": mitigations,
        "relationships": relationships,
        "campaigns": campaigns,
    }