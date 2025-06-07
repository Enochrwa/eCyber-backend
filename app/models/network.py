# backend/app/models/network.py
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float, Boolean
from datetime import datetime
from .base import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), index=True)
    source_ip = Column(String(45), index=True)
    source_mac = Column(String(17))
    source_port = Column(Integer)
    destination_ip = Column(String(45), index=True)
    destination_mac = Column(String(17))
    destination_port = Column(Integer)
    protocol = Column(String(10))
    packet_size = Column(Integer)
    ttl = Column(Integer)
    flags = Column(String(20))
    service = Column(String(50))
    payload_summary = Column(Text)
    raw_packet_hex = Column(Text)
    risk_score = Column(Float)
    is_malicious = Column(Boolean, default=False)
    threat_class = Column(String(50))
    mitigation_action = Column(String(50))
    geo_data = Column(JSON)  # {country, city, isp, coordinates}
    device_info = Column(JSON)  # {os, device_type, vendor}
    network_context = Column(JSON)  # {vlan, subnet, gateway}
    behavioral_analysis = Column(JSON)  # {baseline_deviation, anomaly_score}
    rule_matches = Column(JSON)  # List of matched detection rules
    session_id = Column(String(64), index=True)
    flow_duration = Column(Float)  # In seconds
    bytes_transferred = Column(Integer)
    packets_in_flow = Column(Integer)
    direction = Column(String(10))  # inbound/outbound/internal
    user_identity = Column(String(100))  # If authenticated
    application_layer = Column(JSON)  # HTTP/DNS/SSH details
    enrichment_data = Column(JSON)  # Threat intel enrichment
    confidence_score = Column(Float)  # Detection confidence
    false_positive = Column(Boolean, default=False)
    whitelisted = Column(Boolean, default=False)
    processed_by = Column(JSON)  # List of processing modules
