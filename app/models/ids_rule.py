# backend/app/models/ids_rule.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from .base import Base


class IDSRule(Base):
    __tablename__ = "ids_rules"
    __table_args__ = {"sqlite_autoincrement": True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    action = Column(String(10), nullable=False)
    protocol = Column(String(10))
    source_ip = Column(String(50))
    source_port = Column(String(20))
    destination_ip = Column(String(50))
    destination_port = Column(String(20))
    pattern = Column(String(500))
    content_modifiers = Column(JSON)
    threshold = Column(Integer)
    window = Column(Integer)
    active = Column(Boolean, default=True)
    severity = Column(String(10), default="medium")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<IDSRule {self.id} - {self.name}>"
