# backend/app/services/monitoring/protocol_analysis/tls_fingerprinting.py
import hashlib
import json
from typing import Dict, Optional
from scapy.layers.ssl_tls import SSL, TLS
from scapy.layers.inet import TCP
import logging
from collections import defaultdict

logger = logging.getLogger("tls_fingerprinter")

class TLSFingerprinter:
    def __init__(self):
        self.fingerprint_db = self._load_known_fingerprints()
        self.suspicious_clients = defaultdict(int)

    def _load_known_fingerprints(self) -> Dict[str, dict]:
        """Load known TLS fingerprints from file"""
        try:
            with open("data/tls_fingerprints.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("No TLS fingerprint database found")
            return {}
        except json.JSONDecodeError:
            logger.error("Invalid TLS fingerprint database")
            return {}

    def _generate_fingerprint(self, tls_packet) -> str:
        """Generate a fingerprint from TLS Client Hello"""
        fp_parts = []
        
        if hasattr(tls_packet, "cipher_suites"):
            fp_parts.append(f"ciphers:{','.join(str(c) for c in tls_packet.cipher_suites)}")
        
        if hasattr(tls_packet, "compression_methods"):
            fp_parts.append(f"compression:{','.join(str(c) for c in tls_packet.compression_methods)}")
        
        if hasattr(tls_packet, "extensions"):
            ext_list = []
            for ext in tls_packet.extensions:
                ext_type = ext.type if hasattr(ext, "type") else 0
                ext_list.append(str(ext_type))
            fp_parts.append(f"extensions:{','.join(ext_list)}")
        
        if hasattr(tls_packet, "version"):
            fp_parts.append(f"version:{tls_packet.version}")
        
        fingerprint_str = '|'.join(fp_parts)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

    def analyze_tls(self, packet) -> Optional[dict]:
        """Analyze TLS packet and return fingerprint info"""
        if not packet.haslayer(TLS) or not packet[TCP].dport == 443:
            return None

        tls_layer = packet[TLS]
        if not tls_layer.type == 0x16:  # Handshake
            return None

        fingerprint = self._generate_fingerprint(tls_layer)
        result = {
            "timestamp": packet.time,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "fingerprint": fingerprint,
            "known_app": None,
            "risk_score": 0,
            "ja3_hash": self._generate_ja3(tls_layer)
        }

        # Check against known fingerprints
        if fingerprint in self.fingerprint_db:
            known_info = self.fingerprint_db[fingerprint]
            result.update(known_info)
        else:
            result["known_app"] = "Unknown"
            result["risk_score"] = 30  # Medium risk for unknown fingerprints
            self.suspicious_clients[packet[IP].src] += 1

        # Check for suspicious behavior patterns
        if self.suspicious_clients[packet[IP].src] > 5:
            result["risk_score"] = min(100, result["risk_score"] + 30)
            result["tags"] = ["repeated_unknown_fingerprint"]

        return result

    def _generate_ja3(self, tls_packet) -> str:
        """Generate JA3 fingerprint (standardized TLS fingerprint)"""
        try:
            # JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            version = str(tls_packet.version)
            ciphers = "-".join(str(c) for c in tls_packet.cipher_suites)
            extensions = "-".join(str(ext.type) for ext in tls_packet.extensions)
            
            # Get curves and formats from extensions
            curves = ""
            formats = ""
            for ext in tls_packet.extensions:
                if ext.type == 10:  # supported_groups
                    curves = "-".join(str(g) for g in ext.groups)
                elif ext.type == 11:  # ec_point_formats
                    formats = "-".join(str(f) for f in ext.ec_point_fmt)
            
            ja3_str = ",".join([version, ciphers, extensions, curves, formats])
            return hashlib.md5(ja3_str.encode()).hexdigest()
        except Exception as e:
            logger.error(f"JA3 generation failed: {e}")
            return ""