from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CTIEntity(BaseModel):
    stix_id: str
    name: str
    description: Optional[str] = None
    source: str = "MITRE ATT&CK"


class ThreatGroup(CTIEntity):
    aliases: list[str] = Field(default_factory=list)


class AttackTechnique(CTIEntity):
    external_id: Optional[str] = None
    is_subtechnique: bool = False
    platforms: list[str] = Field(default_factory=list)


class Software(CTIEntity):
    software_types: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)


class Mitigation(CTIEntity):
    external_id: Optional[str] = None


class AttackRelationship(BaseModel):
    stix_id: str
    source_ref: str
    target_ref: str
    relationship_type: str
    description: Optional[str] = None
    source: str = "MITRE ATT&CK"


class AttackData(BaseModel):
    groups: list[ThreatGroup] = Field(default_factory=list)
    techniques: list[AttackTechnique] = Field(default_factory=list)
    software: list[Software] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    relationships: list[AttackRelationship] = Field(default_factory=list)