# backend/app/models/config.py
from sqlalchemy import Column, Integer, String, Text, JSON, DateTime, Boolean
from sqlalchemy.sql import func
from .base import Base


class AppConfig(Base):
    __tablename__ = "app_configs"

    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String(100), unique=True, index=True)
    config_value = Column(Text)
    value_type = Column(String(20))  # string, number, boolean, json
    description = Column(Text)
    is_secret = Column(Boolean, default=False)
    version = Column(Integer, default=1)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    updated_by = Column(String(50))
    metadata_ = Column("metadata", JSON)  # Additional metadata

    def __repr__(self):
        return f"<AppConfig {self.config_key}={self.config_value}>"
