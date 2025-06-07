# backend/app/schemas/network.py
from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum
import socket

class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    OTHER = "OTHER"


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class ThreatClass(str, Enum):
    PORT_SCAN = "port_scan"
    DDoS = "ddos"
    MALWARE = "malware"
    EXPLOIT = "exploit"
    DATA_EXFIL = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class NetworkEventBase(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    source_ip: str
    source_mac: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: str
    destination_mac: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Protocol
    packet_size: int
    ttl: Optional[int] = None
    flags: Optional[str] = None
    service: Optional[str] = None
    payload_summary: Optional[str] = None
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    is_malicious: bool = False
    threat_class: Optional[ThreatClass] = None
    mitigation_action: Optional[str] = None
    geo_data: Optional[Dict[str, Any]] = None
    device_info: Optional[Dict[str, Any]] = None
    network_context: Optional[Dict[str, Any]] = None
    behavioral_analysis: Optional[Dict[str, Any]] = None
    rule_matches: Optional[List[Dict[str, Any]]] = None
    session_id: Optional[str] = None
    flow_duration: Optional[float] = None
    bytes_transferred: Optional[int] = None
    packets_in_flow: Optional[int] = None
    direction: Direction
    user_identity: Optional[str] = None
    application_layer: Optional[Dict[str, Any]] = None
    enrichment_data: Optional[Dict[str, Any]] = None
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    false_positive: bool = False
    whitelisted: bool = False
    processed_by: List[str] = []

    @validator("source_ip", "destination_ip")
    def validate_ip_address(cls, v):
        try:
            socket.inet_aton(v)
        except socket.error:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class NetworkEventCreate(NetworkEventBase):
    raw_packet_hex: Optional[str] = None


class NetworkEvent(NetworkEventBase):
    id: int

    class Config:
        from_attributes = True


class NetworkStats(BaseModel):
    total_packets: int
    protocols: Dict[str, int]
    top_talkers: Dict[str, int]
    threat_distribution: Dict[str, int]
    bandwidth_usage: Dict[str, float]
    risk_score_distribution: Dict[str, int]
    recent_alerts: List[NetworkEvent]
