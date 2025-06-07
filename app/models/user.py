# backend/app/models/user.py
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base
from .ips import IPSRule  # Make sure to import IPSRule


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    two_factor_secret = Column(String, nullable=True)
    is_two_factor_enabled = Column(Boolean, default=False, nullable=False)
    password_reset_token = Column(String, nullable=True)
    password_reset_expires = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    logs = relationship("Log", back_populates="user")
    threat_logs = relationship("ThreatLog", back_populates="user")
    ips_rules = relationship("IPSRule", back_populates="owner")
