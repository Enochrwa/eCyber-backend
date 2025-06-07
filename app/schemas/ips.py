# backend/app/schemas/ips.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum

class IPSAction(str, Enum):
    alert = "alert"
    block = "block"
    throttle = "throttle"
    quarantine = "quarantine"

class IPSSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class IPSCategory(str, Enum):
    exploit = "exploit"
    malware = "malware"
    policy = "policy"
    scan = "scan"
    dos = "dos"
    lateral = "lateral"
    credential = "credential"

class IPSRuleBase(BaseModel):
    rule_id: str = Field(..., max_length=64)
    name: str = Field(..., max_length=256)
    description: Optional[str] = None
    action: IPSAction
    severity: IPSSeverity
    category: IPSCategory
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    direction: Optional[str] = None
    pattern: Optional[str] = None
    threshold: Optional[int] = None
    window: Optional[int] = None
    is_active: bool = True
    tags: Optional[Dict] = None
    references: Optional[List[str]] = None
    owner_id: Optional[int] = None  # Add this field

class IPSRuleCreate(IPSRuleBase):
    pass

class IPSRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    action: Optional[IPSAction] = None
    is_active: Optional[bool] = None
    threshold: Optional[int] = None
    tags: Optional[Dict] = None

class IPSRule(IPSRuleBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    false_positives: int = 0
    true_positives: int = 0
    last_triggered: Optional[datetime] = None

    class Config:
        from_attributes = True

class IPSEventBase(BaseModel):
    rule_id: str
    action: IPSAction
    severity: IPSSeverity
    category: IPSCategory
    source_ip: str
    source_port: Optional[int] = None
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: str
    packet_summary: str
    raw_packet: Optional[str] = None
    session_data: Optional[Dict] = None
    threat_intel: Optional[Dict] = None

class IPSEvent(IPSEventBase):
    id: int
    timestamp: datetime
    mitigated: bool = False
    mitigation_time: Optional[datetime] = None
    false_positive: bool = False
    sensor_id: Optional[str] = None

    class Config:
        from_attributes = True

class IPSStats(BaseModel):
    total_events: int
    events_by_severity: Dict[str, int]
    events_by_category: Dict[str, int]
    top_rules: List[Dict[str, int]]
    top_source_ips: List[Dict[str, int]]
    top_destination_ips: List[Dict[str, int]]
    mitigation_stats: Dict[str, int]