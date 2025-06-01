# backend/app/services/monitoring/protocol_analysis/dns_tunneling.py
import re
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from typing import Dict, Optional
import logging
from collections import deque, defaultdict

logger = logging.getLogger("dns_tunneling")

class DNSTunnelingDetector:
    def __init__(self):
        self.suspicious_domains = set()
        self.domain_length_threshold = 40
        self.entropy_threshold = 4.5
        self.client_stats = defaultdict(lambda: {
            "query_count": 0,
            "unique_domains": set(),
            "long_domains": 0,
            "high_entropy": 0,
            "last_queries": deque(maxlen=10)
        })
        
        # Pre-compiled regex patterns
        self.domain_pattern = re.compile(
            r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", 
            re.IGNORECASE
        )
        self.base64_pattern = re.compile(
            r"([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
        )
        self.hex_pattern = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain shows signs of tunneling"""
        domain = domain.lower()
        
        # Check domain length
        if len(domain) > self.domain_length_threshold:
            return True
            
        # Check entropy
        if self._calculate_entropy(domain) > self.entropy_threshold:
            return True
            
        # Check for encoded patterns
        subdomains = domain.split('.')
        for sub in subdomains[:-1]:  # Skip TLD
            if (self.base64_pattern.fullmatch(sub) or 
                self.hex_pattern.fullmatch(sub)):
                return True
                
        # Check for non-standard characters
        if not self.domain_pattern.fullmatch(domain):
            return True
            
        return False

    def analyze_dns(self, packet) -> Optional[dict]:
        """Analyze DNS packet for tunneling indicators"""
        if not packet.haslayer(DNSQR):
            return None
            
        dns = packet[DNS]
        query = dns[DNSQR].qname.decode('utf-8', 'ignore').rstrip('.')
        src_ip = packet[IP].src
        
        # Update client statistics
        client_stat = self.client_stats[src_ip]
        client_stat["query_count"] += 1
        client_stat["unique_domains"].add(query)
        client_stat["last_queries"].append(query)
        
        result = {
            "timestamp": packet.time,
            "src_ip": src_ip,
            "query": query,
            "is_suspicious": False,
            "indicators": [],
            "risk_score": 0
        }
        
        # Check individual domain
        if self._is_suspicious_domain(query):
            result["is_suspicious"] = True
            result["indicators"].append("suspicious_domain")
            result["risk_score"] += 40
            client_stat["long_domains"] += 1
            
        # Check client behavior patterns
        unique_ratio = len(client_stat["unique_domains"]) / client_stat["query_count"]
        if unique_ratio > 0.8:  # High ratio of unique domains
            result["risk_score"] += 20
            result["indicators"].append("high_unique_ratio")
            
        if client_stat["query_count"] > 50:  # Excessive queries
            result["risk_score"] += 15
            result["indicators"].append("high_query_volume")
            
        # Check for known tunneling patterns
        if any("data" in q.lower() for q in client_stat["last_queries"]):
            result["risk_score"] += 25
            result["indicators"].append("data_exfiltration_pattern")
            
        # Mark as suspicious if risk score crosses threshold
        if result["risk_score"] >= 50:
            result["is_suspicious"] = True
            self.suspicious_domains.add(query)
            logger.warning(
                f"Potential DNS tunneling detected from {src_ip}: "
                f"{query} (score: {result['risk_score']})"
            )
            
        return result if result["is_suspicious"] else None