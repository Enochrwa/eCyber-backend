# backend/app/models/threat.py
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float, Boolean,ForeignKey
from sqlalchemy.sql import func
from .base import Base
from sqlalchemy.orm import relationship

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    threat_type = Column(String(50), index=True)  # malware, ddos, intrusion, etc.
    category = Column(String(50))  # network, endpoint, application
    source_ip = Column(String(45), index=True)
    source_mac = Column(String(17))
    destination_ip = Column(String(45), index=True)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    severity = Column(String(20))  # critical, high, medium, low
    confidence = Column(Float)  # 0.0 to 1.0
    description = Column(Text)
    raw_packet = Column(Text) 
    raw_data = Column(Text)# Hex dump or summary
    action_taken = Column(String(50))  # blocked, alerted, quarantined
    mitigation_status = Column(String(20))  # pending, completed, failed
    analyst_notes = Column(Text)
    false_positive = Column(Boolean, default=False)
    whitelisted = Column(Boolean, default=False)
    rule_id = Column(String(50))  # ID of detection rule that triggered
    sensor_id = Column(String(50))  # Which sensor detected this
    enrichment_data = Column(JSON)  # Threat intel enrichment
    related_events = Column(JSON)  # IDs of related events
    workflow_status = Column(String(20), default="new")  # new, in_progress, resolved
    closed_at = Column(DateTime(timezone=True))
    closed_by = Column(String(50))
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    user = relationship("User", back_populates="threat_logs")

    def __repr__(self):
        return f"<ThreatLog {self.id} {self.threat_type} {self.severity}>"
