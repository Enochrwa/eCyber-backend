# backend/app/services/monitoring/protocol_analysis/utils.py
import math
import ipaddress
from datetime import datetime
from typing import Dict, Any

def is_internal_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).isoformat()

def calculate_entropy(data: bytes) -> float:
    """Calculate byte entropy of packet payload"""
    if not data:
        return 0.0
        
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
        
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
        
    return entropy


