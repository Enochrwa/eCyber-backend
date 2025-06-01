# backend/app/models/system.py
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.sql import func
from .base import Base


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    component = Column(String(50), index=True)  # auth, network, api, etc.
    level = Column(String(20), index=True)  # debug, info, warning, error, critical
    message = Column(Text)
    details = Column(JSON)  # Structured log data
    user_id = Column(Integer)  # If action was user-initiated
    source_ip = Column(String(45))
    request_id = Column(String(50))  # For tracing requests
    resolved = Column(Boolean, default=False)
    resolution_notes = Column(Text)
    stack_trace = Column(Text)  # For error logs
    duration_ms = Column(Integer)  # For performance logs

    def __repr__(self):
        return f"<SystemLog {self.id} {self.component}.{self.level}>"
