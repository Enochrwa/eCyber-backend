
# backend/app/models/blocklist.py
from sqlalchemy import Column, String, DateTime
from .base import Base
from datetime import datetime

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    ip = Column(String(45), primary_key=True)
    reason = Column(String(255))
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

    def __repr__(self):
        return f"<BlockedIP {self.ip}>"