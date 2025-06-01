import re
from typing import List, Dict, Optional, Any, Callable
import yaml
from pathlib import Path
import logging
from dataclasses import dataclass, asdict, field
from scapy.all import Packet
import socketio
from datetime import datetime
from functools import partial
from scapy.layers import http, dns, smb
from scapy.all import (
    sniff,
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    Raw,
    ICMP,
    conf,
    IPv6,
    ARP,
    Dot11,
    PPPoE,
)
import hashlib
from concurrent.futures import ThreadPoolExecutor
import asyncio
from ...core.logger import setup_logger
logger = logging.getLogger(__name__)

# Constants
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB max payload to scan
RULE_CACHE_SIZE = 1000  # LRU cache size for rule matches

@dataclass
class SignatureRule:
    id: str
    name: str
    protocol: str
    pattern: str
    action: str
    severity: str
    description: str
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    mitre_attacks: List[str] = field(default_factory=list)
    compiled_pattern: Optional[re.Pattern] = field(init=False, default=None)
    is_valid: bool = field(init=False, default=True)

    def __post_init__(self):
        """Compile regex and validate rule"""
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
            # Test pattern with empty string to catch some regex errors
            self.compiled_pattern.search("")
        except re.error as e:
            logger.error(f"Invalid regex in rule {self.id}: {str(e)}")
            self.is_valid = False
        except Exception as e:
            logger.error(f"Unexpected error compiling rule {self.id}: {str(e)}")
            self.is_valid = False

    def match(self, text: str) -> bool:
        """Safely match text against the rule"""
        if not self.is_valid:
            return False
            
        try:
            return bool(self.compiled_pattern.search(text))
        except (re.error, UnicodeError) as e:
            logger.warning(f"Error matching rule {self.id}: {str(e)}")
            return False

class SignatureEngine:
    def __init__(self, sio: socketio.AsyncServer = None, rule_files: List[str] = None):
        self.sio = sio
        self.rules: Dict[str, SignatureRule] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._match_cache = {}
        self.logger = setup_logger("signature_engine")

        # Protocol handlers mapping
        self.protocol_handlers: Dict[str, Callable] = {
            "http": self._match_http,
            "dns": self._match_dns,
            "tcp": self._match_tcp,
            "udp": self._match_udp,
            "icmp": self._match_icmp,
            "ip": self._match_ip,
            "ssh": self._match_ssh,
            "ftp": self._match_ftp,
            "smtp": self._match_smtp,
            "smb": self._match_smb,
            "any": self._match_any,
        }

        # Load rules
        if rule_files:
            self.load_rules_from_files(rule_files)
        else:
            self.load_default_rules()

    def load_rules_from_files(self, rule_files: List[str]) -> bool:
        """Load rules from YAML files with validation"""
        success = True
        for rule_file in rule_files:
            try:
                with open(rule_file, "r") as f:
                    rules_data = yaml.safe_load(f) or {}
                    for rule_dict in rules_data.get("rules", []):
                        try:
                            rule = SignatureRule(**rule_dict)
                            if rule.is_valid:
                                self.rules[rule.id] = rule
                            else:
                                logger.warning(f"Skipping invalid rule {rule.id}")
                        except Exception as e:
                            logger.error(f"Error loading rule from {rule_file}: {str(e)}")
                            success = False
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {str(e)}")
                success = False

        logger.info(f"Loaded {len(self.rules)} rules from {len(rule_files)} files")
        return success

    def load_default_rules(self) -> None:
        """Load built-in rules covering modern threats"""
        default_rules = [
            {
                "id": "http-sqli-1",
                "name": "SQL Injection Attempt",
                "protocol": "http",
                "pattern": r"(union\s+select|1=1|sleep\(\d+\)|or\s+1=1)",
                "action": "alert",
                "severity": "high",
                "description": "Detects common SQL injection patterns in HTTP requests",
            },
            {
                "id": "http-xss-1",
                "name": "Cross-Site Scripting (XSS) Attempt",
                "protocol": "http",
                "pattern": r"(<script>|javascript:|onerror=|onload=)",
                "action": "alert",
                "severity": "medium",
                "description": "Detects possible XSS attack vectors in web traffic",
            },
            {
                "id": "http-rce-1",
                "name": "Remote Command Execution Attempt",
                "protocol": "http",
                "pattern": r"(;|&&|\|\||`|base64\s+-d|bash\s+-c)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects possible RCE payloads in web requests",
            },
            {
                "id": "dns-exfil-1",
                "name": "DNS Exfiltration Attempt",
                "protocol": "dns",
                "pattern": r"([a-z0-9]{20,}\.(exfil|data|steal)\.(com|net|org))",
                "action": "alert",
                "severity": "critical",
                "description": "Detects potential data exfiltration via DNS tunneling",
            },
            {
                "id": "ssh-brute-1",
                "name": "SSH Brute Force",
                "protocol": "ssh",
                "pattern": r"(Failed password for.*from)",
                "action": "alert",
                "severity": "high",
                "description": "Detects brute force attempts against SSH",
            },
            {
                "id": "ftp-login-1",
                "name": "FTP Anonymous Login",
                "protocol": "ftp",
                "pattern": r"(USER anonymous)",
                "action": "alert",
                "severity": "medium",
                "description": "Detects anonymous FTP login attempt",
            },
            {
                "id": "smtp-phish-1",
                "name": "SMTP Phishing Attempt",
                "protocol": "smtp",
                "pattern": r"(Subject:.*(urgent|verify|account|password))",
                "action": "alert",
                "severity": "high",
                "description": "Detects phishing attempt via email",
            },
            {
                "id": "scan-nmap-1",
                "name": "Nmap Port Scan",
                "protocol": "any",
                "pattern": r"(Nmap scan report for)",
                "action": "alert",
                "severity": "low",
                "description": "Detects basic port scanning activity",
            },
            {
                "id": "malware-c2-1",
                "name": "Malware C2 Beaconing",
                "protocol": "http",
                "pattern": r"(\/gate\.php|\/connect\.php|\/api\/v1\/report)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects common malware command-and-control beacon paths",
            },
            {
                "id": "smb-exploit-1",
                "name": "SMB Exploit Attempt",
                "protocol": "smb",
                "pattern": r"(\\x90\\x90\\x90|EternalBlue|MS17-010)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects possible SMB exploitation attempts",
            },
            {
                "id": "generic-dos-1",
                "name": "Possible DoS Attempt",
                "protocol": "any",
                "pattern": r"(SYN\s+flood|ICMP\s+flood)",
                "action": "alert",
                "severity": "high",
                "description": "Detects denial-of-service patterns",
            },
            {
                "id": "ransomware-indicator-1",
                "name": "Ransomware File Access Pattern",
                "protocol": "filesystem",
                "pattern": r"(\.encrypted|\.locked|\.crypto|\.crypt)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects access to known ransomware-encrypted files",
            },
        ]

        for rule_dict in default_rules:
            try:
                rule = SignatureRule(**rule_dict)
                if rule.is_valid:
                    self.rules[rule.id] = rule
                else:
                    logger.warning(f"Skipping invalid default rule {rule.id}")
            except Exception as e:
                logger.error(f"Error loading default rule: {str(e)}")

    def scan_packet(self, packet) -> Optional[Dict]:
        """
        Scan a packet against all signature rules.
        Returns matched rule or None if no match.
        """
        try:
            # Check TCP flags first (for port scans)
            if hasattr(packet, "tcp"):
                tcp = packet.tcp
                for rule in self.rules:
                    if rule.get("flags") and tcp.flags == rule["flags"]:
                        return self._create_alert(rule, packet)

            # Check payload content for other rules
            payload = self._get_packet_payload(packet)
            if payload:
                for rule_id, pattern in self.compiled_rules.items():
                    if pattern.search(payload):
                        rule = next(r for r in self.rules if r["id"] == rule_id)
                        return self._create_alert(rule, packet)

            return None

        except Exception as e:
            self.logger.error(f"Error scanning packet: {str(e)}", exc_info=True)
            return None

    def _create_alert(self, rule: Dict, packet) -> Dict:
        """Create alert dictionary from matched rule"""
        src_ip = packet.ip.src if hasattr(packet, "ip") else "unknown"
        dst_ip = packet.ip.dst if hasattr(packet, "ip") else "unknown"

        alert =  {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "action": rule["action"],
            "timestamp": datetime.now().isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": rule["protocol"],
            "packet_summary": packet.summary(),
            "matched_content": self._get_matched_content(packet, rule),
        }
        self.sio.emit("scan_packet", alert)
        return alert
    
    def _get_matched_content(self, packet, rule: Dict) -> str:
        """Extract the specific content that triggered the rule"""
        if rule.get('flags'):
            return f"TCP Flags: {packet.tcp.flags}" if hasattr(packet, 'tcp') else "Flags matched"

        payload = self._get_packet_payload(packet)
        if payload and rule.get('pattern'):
            match = re.search(rule['pattern'], payload, re.IGNORECASE)
            return match.group(0) if match else "Pattern matched"

        return "Unknown match"
    def _get_packet_payload(self, packet) -> Optional[str]:
        """Extract payload from packet for inspection"""
        try:
            if hasattr(packet, 'http'):
                return str(packet.http)
            elif hasattr(packet, 'dns'):
                return str(packet.dns)
            elif hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'payload'):
                    return str(packet.tcp.payload)
            return None
        except Exception:
            return None

    async def detect(self, packet: Packet) -> Optional[Dict]:
        """Analyze packet against all rules (async)"""
        try:
            # Skip packets that are too large
            if len(packet) > MAX_PAYLOAD_SIZE:
                return None

            # Check cache first
            packet_hash = self._packet_hash(packet)
            if cached := self._match_cache.get(packet_hash):
                return cached

            # Run detection in thread pool
            loop = asyncio.get_event_loop()
            threat = await loop.run_in_executor()
            self._executor,
            partial(self._detect_sync, packet)

            # Cache result
            if threat and len(self._match_cache) >= RULE_CACHE_SIZE:
                self._match_cache.pop(next(iter(self._match_cache)))
            if threat:
                self._match_cache[packet_hash] = threat

            return threat
        except Exception as e:
            logger.error(f"Detection error: {str(e)}")
            return None

    def _detect_sync(self, packet: Packet) -> Optional[Dict]:
        """Synchronous detection for thread pool"""
        for rule in self.rules.values():
            if not rule.is_valid:
                continue

            try:
                handler = self.protocol_handlers.get(rule.protocol)
                if handler and handler(packet, rule):
                    return self._create_threat_event(packet, rule)
            except Exception as e:
                logger.error(f"Error processing rule {rule.id}: {str(e)}")

        return None

    def _create_threat_event(self, packet: Packet, rule: SignatureRule) -> Dict:
        """Create standardized threat event"""
        return {
            "rule_id": rule.id,
            "threat_name": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "source_ip": packet[IP].src if IP in packet else None,
            "dest_ip": packet[IP].dst if IP in packet else None,
            "source_port": packet[TCP].sport if TCP in packet else None,
            "dest_port": packet[TCP].dport if TCP in packet else None,
            "protocol": rule.protocol.upper(),
            "packet_summary": packet.summary(),
            "references": rule.references,
            "cve_ids": rule.cve_ids,
            "mitre_attacks": rule.mitre_attacks,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _packet_hash(self, packet: Packet) -> str:
        """Create consistent hash for packet caching"""
        key_parts = [
            packet.summary(),
            str(packet[IP].src) if IP in packet else "",
            str(packet[IP].dst) if IP in packet else "",
            str(packet[TCP].sport) if TCP in packet else "",
            str(packet[TCP].dport) if TCP in packet else ""
        ]
        return hashlib.sha256("|".join(key_parts).encode()).hexdigest()

    # Protocol Handlers with Enhanced Detection
    def _match_ftp(self, packet: Packet, rule: SignatureRule) -> bool:
        """
        Match FTP commands and responses (typically port 21).
        Checks for common commands like USER, PASS, RETR, STOR, etc.
        """
        if not (TCP in packet and (packet[TCP].dport == 21 or packet[TCP].sport == 21) and Raw in packet):
            return False

        try:
            payload = bytes(packet[Raw].load)
            decoded = payload.decode('utf-8', errors='replace').strip()

            # Skip FTP keep-alives or empty commands
            if not decoded or len(decoded) > 4096:
                return False

            # Optional: Check for specific FTP commands (for precision)
            ftp_commands = ["USER", "PASS", "RETR", "STOR", "CWD", "MKD", "RMD", "LIST"]
            if any(cmd in decoded.upper() for cmd in ftp_commands):
                return rule.match(decoded)

            return False
        except Exception as e:
            # PROD_CLEANUP: logger.debug(f"FTP match error: {str(e)}")
            return False
    def _match_smtp(self, packet: Packet, rule: SignatureRule) -> bool:
        """
        Match SMTP commands and content (port 25).
        Looks for headers like HELO, MAIL FROM, RCPT TO, DATA, etc.
        """
        if not (TCP in packet and (packet[TCP].dport == 25 or packet[TCP].sport == 25) and Raw in packet):
            return False

        try:
            payload = bytes(packet[Raw].load)
            decoded = payload.decode('utf-8', errors='replace')

            # Skip if it's too short or too large to be valid
            if not decoded or len(decoded) > 8192:
                return False

            smtp_keywords = ["HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT"]
            if any(keyword in decoded.upper() for keyword in smtp_keywords):
                return rule.match(decoded)

            return False
        except Exception as e:
            # PROD_CLEANUP: logger.debug(f"SMTP match error: {str(e)}")
            return False

    def _match_http(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match HTTP traffic including fragmented packets"""
        if not (TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80)):
            return False

        try:
            payload = bytes(packet[TCP].payload)
            if not payload:
                return False

            # Handle chunked HTTP
            if b"Transfer-Encoding: chunked" in payload[:512]:
                return False  # Skip chunked for now

            decoded = payload.decode('utf-8', errors='replace')
            return rule.match(decoded)
        except Exception as e:
            # PROD_CLEANUP: logger.debug(f"HTTP match error: {str(e)}")
            return False

    def _match_dns(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match DNS queries with subdomain analysis"""
        if not (UDP in packet and packet[UDP].dport == 53 and DNS in packet):
            return False

        try:
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                query = dns.qd.qname.decode('utf-8', errors='replace') if dns.qd else ""
                return rule.match(query)
        except Exception as e:
            pass
            # PROD_CLEANUP: logger.debug(f"DNS match error: {str(e)}")

        return False

    def _match_smb(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match SMB traffic with protocol awareness"""
        if not (TCP in packet and packet[TCP].dport in [139, 445] and Raw in packet):
            return False

        try:
            payload = bytes(packet[Raw].load)
            return rule.match(payload.decode('latin1', errors='replace'))
        except Exception:
            return False

    def _match_ssh(self, packet: Packet, rule: SignatureRule) -> bool:
        if not (TCP in packet and packet[TCP].dport == 22 and Raw in packet):
            return False

        try:
            payload = bytes(packet[Raw].load)
            return rule.match(payload.decode('utf-8', errors='replace'))
        except Exception:
            return False

    # Generic protocol handlers
    def _match_tcp(self, packet: Packet, rule: SignatureRule) -> bool:
        if not (TCP in packet and Raw in packet):
            return False
        return self._match_payload(bytes(packet[Raw].load), rule)

    def _match_udp(self, packet: Packet, rule: SignatureRule) -> bool:
        if not (UDP in packet and Raw in packet):
            return False
        return self._match_payload(bytes(packet[Raw].load), rule)

    def _match_icmp(self, packet: Packet, rule: SignatureRule) -> bool:
        if not (ICMP in packet and Raw in packet):
            return False
        return self._match_payload(bytes(packet[Raw].load), rule)

    def _match_ip(self, packet: Packet, rule: SignatureRule) -> bool:
        if not (IP in packet and Raw in packet):
            return False
        return self._match_payload(bytes(packet[Raw].load), rule)

    def _match_any(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match any packet payload"""
        if Raw not in packet:
            return False
        return self._match_payload(bytes(packet[Raw].load), rule)

    def _match_payload(self, payload: bytes, rule: SignatureRule) -> bool:
        """Safe payload matching with encoding fallback"""
        if not payload:
            return False

        try:
            decoded = payload.decode('utf-8', errors='replace')
            if len(decoded) > 10000:  # Skip very large payloads
                return False
            return rule.match(decoded)
        except Exception as e:
            # PROD_CLEANUP: logger.debug(f"Payload match error: {str(e)}")
            return False

    async def emit_threat(self, threat_data: Dict) -> None:
        """Send threat to connected clients"""
        if not self.sio:
            return

        try:
            await self.sio.emit('threat_detected', threat_data)
        except Exception as e:
            logger.error(f"Failed to emit threat: {str(e)}")

    async def get_rules_status(self) -> Dict:
        """Get current rules status for API"""
        return {
            "total_rules": len(self.rules),
            "active_rules": sum(1 for r in self.rules.values() if r.is_valid),
            "last_updated": datetime.utcnow().isoformat()
        }

    async def update_rule(self, rule_id: str, rule_data: Dict) -> bool:
        """Dynamically update a rule"""
        try:
            if rule_id in self.rules:
                # Update existing rule
                updated_rule = SignatureRule(**{**asdict(self.rules[rule_id]), **rule_data})
                if updated_rule.is_valid:
                    self.rules[rule_id] = updated_rule
                    return True
            else:
                # Add new rule
                new_rule = SignatureRule(**rule_data)
                if new_rule.is_valid:
                    self.rules[rule_id] = new_rule
                    return True
        except Exception as e:
            logger.error(f"Error updating rule {rule_id}: {str(e)}")

        return False

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False

    def shutdown(self) -> None:
        """Cleanup resources"""
        self._executor.shutdown(wait=True)
