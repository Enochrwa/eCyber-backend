from pydantic import BaseModel
from typing import Optional, List
import datetime

class ThreatBase(BaseModel):
    threat_type: Optional[str] = None
    category: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    rule_id: Optional[str] = None
    # Add other common fields from ThreatLog model that might be useful

class ThreatCreate(ThreatBase):
    # Fields required for creating a new threat, if direct creation is allowed via API
    pass

class ThreatResponse(ThreatBase):
    id: int
    timestamp: datetime.datetime
    # Potentially more fields from ThreatLog or derived fields

    class Config:
        from_attributes = True

class PaginatedThreatResponse(BaseModel):
    total: int
    threats: List[ThreatResponse]
