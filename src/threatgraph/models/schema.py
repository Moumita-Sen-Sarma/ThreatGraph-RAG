from typing import Optional

from pydantic import BaseModel, Field


class ThreatGroup(BaseModel):
    stix_id: str
    name: str
    description: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)


class AttackTechnique(BaseModel):
    stix_id: str
    external_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    platforms: list[str] = Field(default_factory=list)


class Software(BaseModel):
    stix_id: str
    name: str
    description: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)


class Mitigation(BaseModel):
    stix_id: str
    external_id: Optional[str] = None
    name: str
    description: Optional[str] = None

class AttackRelationship(BaseModel):
    stix_id: str
    source_ref: str
    target_ref: str
    relationship_type: str
    description: Optional[str] = None