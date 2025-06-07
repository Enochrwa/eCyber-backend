from sqlalchemy import (
    Column,
    Integer,
    String,
    Enum,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
)
from sqlalchemy.sql import func
from .base import Base
from enum import Enum as PyEnum


class FirewallAction(str, PyEnum):
    ALLOW = "allow"
    DENY = "deny"


class FirewallDirection(str, PyEnum):
    IN = "in"
    OUT = "out"
    BOTH = "both"


class FirewallProtocol(str, PyEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    action = Column(Enum(FirewallAction), nullable=False)
    direction = Column(Enum(FirewallDirection), nullable=False)
    source_ip = Column(String(100))
    destination_ip = Column(String(100))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(Enum(FirewallProtocol), default=FirewallProtocol.ANY)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<FirewallRule {self.id} - {self.name}>"


class FirewallLog(Base):
    __tablename__ = "firewall_logs"
    __table_args__ = (
        Index("ix_firewall_action_timestamp", "action", "timestamp"),
        Index("ix_firewall_protocol", "protocol"),
    )

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    rule_id = Column(Integer, ForeignKey("firewall_rules.id"))
    action = Column(Enum(FirewallAction), nullable=False)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    protocol = Column(String(10), nullable=False)
    matched_rule = Column(String(500), nullable=False)

    def __repr__(self):
        return f"<FirewallLog {self.id} - {self.action} {self.source_ip}>"
