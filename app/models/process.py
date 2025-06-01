from sqlalchemy import Column, Integer, String, Float, DateTime, Text,Boolean
from sqlalchemy.sql import func
from .base import Base


class ProcessActivity(Base):
    __tablename__ = "process_activities"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    hostname = Column(String(100))
    pid = Column(Integer)
    ppid = Column(Integer)
    name = Column(String(255))
    exe_path = Column(Text)
    cmdline = Column(Text)
    username = Column(String(100))
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    num_threads = Column(Integer)
    status = Column(String(50))
    create_time = Column(Float)  # Process creation timestamp
    connections = Column(Text)  # JSON-serialized network connections
    hashes = Column(Text)  # MD5/SHA1/SHA256 of process binary
    signed = Column(Boolean)  # Is binary signed?
    signature = Column(Text)  # Signer info if signed
    anomaly_score = Column(Float)  # For UEBA integration

    def __repr__(self):
        return f"<Process {self.pid} ({self.name})>"
