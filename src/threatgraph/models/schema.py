from typing import Optional

from pydantic import BaseModel, Field


class ThreatGroup(BaseModel):
    stix_id: str
    name: str
    description: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)

class Campaign(BaseModel):
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

class Vulnerability(BaseModel):
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    description: Optional[str] = None
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    required_action: Optional[str] = None
    known_ransomware_use: Optional[str] = None
    notes: Optional[str] = None
    source: str = "CISA KEV"


class Vendor(BaseModel):
    name: str


class Product(BaseModel):
    name: str
    vendor: str