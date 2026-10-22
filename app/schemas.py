from pydantic import BaseModel
from typing import Dict
from typing import List

class IncidentRequest(BaseModel):

    profile: str
    runId: str
    agentName: str
    publicMarker: str

    sensitive: Dict

    incident: Dict

    toolCatalog: List[Dict]

    policy: Dict