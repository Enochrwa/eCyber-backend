# backend/app/services/detection/signature.py
import re
import time
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime
import socketio
from scapy.all import IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet
from ...models.ids_rule import IDSRule
from ...models.threat import ThreatLog
from ...database import get_db


class IdsSignatureEngine:
    def __init__(self, sio: socketio.AsyncServer):
        self.sio = sio
        self.rules: List[IDSRule] = []
        self.rule_cache = {}
        self.threshold_tracker = defaultdict(lambda: defaultdict(int))
        self.last_rule_update = 0
        self._compile_regex_patterns()

    def _compile_regex_patterns(self):
        """Pre-compile all regex patterns for performance"""
        self.compiled_patterns = {}
        for rule in self.rules:
            if rule.pattern:
                try:
                    flags = 0
                    if any(mod in rule.content_modifiers for mod in ["nocase", "i"]):
                        flags |= re.IGNORECASE
                    self.compiled_patterns[rule.id] = re.compile(
                        rule.pattern.encode(), flags
                    )
                except re.error:
                    # PROD_CLEANUP: print(f"Invalid regex pattern in rule {rule.id}: {rule.pattern}")

    def load_rules(self, db_session):
        """Load rules from database with caching"""
        current_time = time.time()
        if current_time - self.last_rule_update < 30:  # 30s cache
            return

        self.rules = db_session.query(IDSRule).filter(IDSRule.active == True).all()
        self._compile_regex_patterns()
        self.last_rule_update = current_time

    def _ip_match(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if IP matches the rule pattern (supports CIDR)"""
        if not rule_ip:
            return True

        if "/" in rule_ip:
            from ipaddress import ip_network, ip_address

            return ip_address(packet_ip) in ip_network(rule_ip)
        return rule_ip == packet_ip

    def _port_match(self, rule_port: str, packet_port: int) -> bool:
        """Check if port matches the rule pattern (supports ranges)"""
        if not rule_port:
            return True

        if ":" in rule_port:
            min_port, max_port = map(int, rule_port.split(":"))
            return min_port <= packet_port <= max_port
        return int(rule_port) == packet_port

    def _check_threshold(self, rule: IDSRule, src_ip: str) -> bool:
        """Implement threshold-based rule triggering"""
        if not rule.threshold:
            return True

        key = f"{rule.id}_{src_ip}"
        current_time = int(time.time())
        window_start = current_time - rule.window

        # Cleanup old entries
        self.threshold_tracker[key] = {
            ts: count
            for ts, count in self.threshold_tracker[key].items()
            if ts >= window_start
        }

        total = sum(self.threshold_tracker[key].values())
        if total >= rule.threshold:
            return False

        self.threshold_tracker[key][current_time] = (
            self.threshold_tracker[key].get(current_time, 0) + 1
        )
        return True

    async def process_packet(self, packet: Packet, db_session):
        """Main packet processing method"""
        self.load_rules(db_session)

        if not IP in packet:
            return

        ip_layer = packet[IP]
        transport_layer = (
            packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        )

        for rule in self.rules:
            # Protocol check
            if rule.protocol != "any" and (
                (rule.protocol == "tcp" and not TCP in packet)
                or (rule.protocol == "udp" and not UDP in packet)
                or (rule.protocol == "icmp" and not ICMP in packet)
            ):
                continue

            # IP/Port matching
            if not self._ip_match(rule.source_ip, ip_layer.src):
                continue
            if not self._ip_match(rule.destination_ip, ip_layer.dst):
                continue
            if transport_layer and (
                not self._port_match(rule.source_port, transport_layer.sport)
                or not self._port_match(rule.destination_port, transport_layer.dport)
            ):
                continue

            # Content inspection
            pattern_match = True
            if rule.pattern and Raw in packet:
                compiled = self.compiled_patterns.get(rule.id)
                if compiled:
                    pattern_match = bool(compiled.search(bytes(packet[Raw])))

            if not pattern_match:
                continue

            # Threshold check
            if not self._check_threshold(rule, ip_layer.src):
                continue

            # Rule matched - take action
            await self._handle_rule_match(rule, packet, db_session)

    async def _handle_rule_match(self, rule: IDSRule, packet: Packet, db_session):
        """Handle matched rule actions"""
        ip_layer = packet[IP]
        transport_layer = (
            packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        )

        # Create threat log
        threat = ThreatLog(
            timestamp=datetime.now(),
            threat_type="signature_match",
            category="network",
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            destination_port=transport_layer.dport if transport_layer else None,
            protocol=rule.protocol,
            severity=rule.severity,
            confidence=0.9,  # High confidence for signature matches
            description=f"Matched rule: {rule.name}",
            raw_packet=str(packet.summary()),
            action_taken=rule.action,
            rule_id=f"SIG-{rule.id}",
            sensor_id="signature_engine",
        )
        db_session.add(threat)
        db_session.commit()

        # Emit real-time alert
        await self.sio.emit(
            "ids_alert",
            {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "source_ip": ip_layer.src,
                "destination_ip": ip_layer.dst,
                "protocol": rule.protocol,
                "timestamp": datetime.now().isoformat(),
                "action_taken": rule.action,
                "packet_summary": packet.summary(),
            },
        )

        # TODO: Implement blocking if action is BLOCK
        if rule.action == "block":
            pass  # Will integrate with firewall in next phase
