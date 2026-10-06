from typing import Literal, Optional

from pydantic import BaseModel


class GraphQuery(BaseModel):
    intent: Literal[
        "group_techniques",
        "group_software",
        "technique_mitigations",
        "group_technique_mitigations",
        "unknown",
    ]

    group_name: Optional[str] = None

    technique: Optional[str] = None