# backend/app/models/packet.py
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from .base import Base
import ipaddress


class Packets(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=False)
    size = Column(Integer, nullable=False)
    flags = Column(String(20), nullable=True)
    payload = Column(Text, nullable=True)
    dns_query = Column(String(255), nullable=True)
    http_method = Column(String(10), nullable=True)
    http_path = Column(String(255), nullable=True)

    def __init__(self, **kwargs):
        # Validate IP addresses before creation
        for field in ["src_ip", "dst_ip"]:
            value = kwargs.get(field)
            if value and not self.valid_ip(value):
                raise ValueError(f"Invalid IP format for {field}: {value}")

        super().__init__(**kwargs)

    @staticmethod
    def valid_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
        
    @classmethod
    def get_column_names(cls):
        """Safe column name access without __table__"""
        return ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                'protocol', 'size', 'flags', 'payload', 'dns_query',
                'http_method', 'http_path']
