from sqlalchemy import Column, Integer, String, Enum, DateTime, JSON, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base
from enum import Enum as PyEnum


class LogType(str, PyEnum):
    SECURITY = "security"
    SYSTEM = "system"
    NETWORK = "network"
    AUDIT = "audit"


class LogLevel(str, PyEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum(LogType), nullable=False)
    level = Column(Enum(LogLevel), nullable=False)
    message = Column(String(500), nullable=False)
    source = Column(String(100), nullable=False)
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    action = Column(String)
    user_id = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # nullable=True if logs can exist without users
    user = relationship(
        "User", back_populates="logs"
    )  # Add corresponding relationship in User model
    def __repr__(self):
        return f"<Log {self.id} - {self.type} {self.level}>"


class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    threat_type = Column(String(100), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    protocol = Column(String(10))
    length = Column(Integer)
    raw_data = Column(Text)
