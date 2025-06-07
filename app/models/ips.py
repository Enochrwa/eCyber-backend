# backend/app/models/ips.py
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float, Boolean,ForeignKey,Enum
from .base import Base

from sqlalchemy.orm import relationship



class IPSAction(str, PyEnum):
    ALERT = "alert"
    BLOCK = "block"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"

class IPSSeverity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IPSCategory(str, PyEnum):
    EXPLOIT = "exploit"
    MALWARE = "malware"
    POLICY = "policy"
    SCAN = "scan"
    DOS = "dos"
    LATERAL = "lateral"
    CREDENTIAL = "credential"

class IPSRule(Base):
    __tablename__ = "ips_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), unique=True, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    action = Column(Enum(IPSAction), nullable=False)
    severity = Column(Enum(IPSSeverity), nullable=False)
    category = Column(Enum(IPSCategory), nullable=False)
    protocol = Column(String(16))
    source_ip = Column(String(256))
    source_port = Column(String(128))
    destination_ip = Column(String(256))
    destination_port = Column(String(128))
    direction = Column(String(16))  # inbound, outbound, any
    pattern = Column(Text)  # Regex pattern for content inspection
    threshold = Column(Integer)  # Event threshold before action
    window = Column(Integer)  # Time window in seconds for threshold
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    tags = Column(JSON)  # Additional metadata
    references = Column(JSON)  # CVE IDs, vendor advisories
    false_positives = Column(Integer, default=0)
    true_positives = Column(Integer, default=0)
    last_triggered = Column(DateTime(timezone=True))
    owner = Column(String(128))  # Rule creator/maintainer

    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="ips_rules", foreign_keys=[owner_id])

    def __repr__(self):
        return f"<IPSRule {self.rule_id} - {self.name}>"
    
    
class IPSEvent(Base):
    __tablename__ = "ips_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    rule_id = Column(String(64), index=True)
    action = Column(Enum(IPSAction), nullable=False)
    severity = Column(Enum(IPSSeverity), nullable=False)
    category = Column(Enum(IPSCategory), nullable=False)
    source_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_ip = Column(String(45), index=True)
    destination_port = Column(Integer)
    protocol = Column(String(16))
    packet_summary = Column(Text)
    raw_packet = Column(Text)  # Hex dump
    session_data = Column(JSON)  # Related session/flow info
    threat_intel = Column(JSON)  # Enrichment data
    mitigated = Column(Boolean, default=False)
    mitigation_time = Column(DateTime(timezone=True))
    analyst_notes = Column(Text)
    false_positive = Column(Boolean, default=False)
    sensor_id = Column(String(64))  # Which sensor detected this
   

    def __repr__(self):
        return f"<IPSEvent {self.id} - {self.rule_id}>"