from pydantic import BaseModel
from typing import Dict, List


class Incident(BaseModel):
    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: List[str]


class IncidentRequest(BaseModel):
    profile: str
    runId: str
    agentName: str
    publicMarker: str

    sensitive: Dict

    incident: Incident

    toolCatalog: List[Dict]

    policy: Dict
