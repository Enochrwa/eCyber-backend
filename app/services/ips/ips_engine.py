# backend/app/services/ips/engine.py
import asyncio
import re
import multiprocessing
import signal
import psutil
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import socket
import ipaddress
import logging
import heapq
from functools import lru_cache
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager, Queue, Lock, Value
import socketio
import redis

import os
import requests


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_KEY")  # or set directly for testing
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_KEY")

from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff
from scapy.packet import Packet
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..prevention.app_blocker import ApplicationBlocker
from ..prevention.firewall import FirewallManager
from ..detection.rate_limiter import DistributedRateLimiter
from ...models.ips import IPSRule, IPSEvent, IPSAction
from ...core.security import get_db
from ...database import AsyncSessionLocal

logger = logging.getLogger("ips_engine")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class EnhancedIPSEngine:
    def __init__(self, sio: socketio.AsyncServer, app_blocker: ApplicationBlocker):
        self.sio = sio
        self.app_blocker = app_blocker
        self.process_pool = ProcessPoolExecutor(max_workers=psutil.cpu_count())
        self.manager = Manager()
        self.packet_queue = Queue(maxsize=10000)
        self.rule_cache = self.manager.dict()
        self.redis = redis.Redis(host="localhost", port=6379, db=0)
        self.lock = Lock()
        self.workers = []
        self.running = Value("b", True)
        self.mitigation_queue = Queue()
        self.fw_manager = FirewallManager(sio)
        self.load_balancer = LoadBalancer()
        self.metrics = IPSEngineMetrics()

        # Initialize subsystems
        self.rule_processor = RuleProcessor()
        self.session_tracker = DistributedSessionTracker(self.redis)
        self.threat_intel = ThreatIntelClient()
        self.packet_capturer = PacketCapturer(self.packet_queue)
        self.mitigation_executor = MitigationExecutor(
            self.mitigation_queue, self.fw_manager, self.app_blocker, self.sio
        )

    async def initialize(self):
        """Initialize all engine components"""
        await self.load_rules()
        self.mitigation_executor.start()
        self.packet_capturer.start()
        self._start_workers()
        logger.info("IPS Engine initialized with %d workers", psutil.cpu_count())

    def _start_workers(self):
        """Start packet processing workers"""
        for _ in range(psutil.cpu_count()):
            worker = multiprocessing.Process(
                target=self._worker_main,
                args=(self.packet_queue, self.mitigation_queue),
            )
            worker.start()
            self.workers.append(worker)

    async def load_rules(self):
        """Load and preprocess detection rules"""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(IPSRule).where(IPSRule.is_active == True))
            rules = result.scalars().all()

            preprocessed = [self.rule_processor.preprocess_rule(rule) for rule in rules]
            self.rule_cache.update({r.rule_id: r for r in preprocessed})

            logger.info("Loaded %d active rules", len(preprocessed))
            self.metrics.update_rules_loaded(len(preprocessed))

    def _worker_main(self, packet_queue: Queue, mitigation_queue: Queue):
        """Worker process main loop"""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        while self.running.value:
            try:
                packet = packet_queue.get(timeout=1)
                if packet:
                    self.process_packet(packet, mitigation_queue)
            except Exception as e:
                logger.error("Worker error: %s", str(e))
                self.metrics.log_error()

    def process_packet(self, packet: Packet, mitigation_queue: Queue):
        """Core packet processing pipeline"""
        try:
            decoded = self._decode_packet(packet)
            if not decoded:
                return

            matched_rules = self.rule_processor.match_packet(decoded, self.rule_cache)

            for rule, matches in matched_rules:
                if self._check_threshold(rule, decoded["src_ip"]):
                    event = self._create_event(rule, decoded)
                    mitigation_queue.put((rule, event))
                    self.metrics.update_detections()

        except Exception as e:
            logger.error("Packet processing failed: %s", str(e))
            self.metrics.log_error()

    def _decode_packet(self, packet: Packet) -> Optional[Dict]:
        """Decode packet layers into structured data"""
        if not IP in packet:
            return None

        decoded = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "payload": b"",
            "timestamp": datetime.now().isoformat(),
        }

        layer = packet[IP].payload
        while layer:
            if isinstance(layer, TCP):
                decoded.update(
                    {
                        "protocol": "tcp",
                        "src_port": layer.sport,
                        "dst_port": layer.dport,
                        "flags": layer.flags,
                    }
                )
            elif isinstance(layer, UDP):
                decoded.update(
                    {
                        "protocol": "udp",
                        "src_port": layer.sport,
                        "dst_port": layer.dport,
                    }
                )
            elif isinstance(layer, ICMP):
                decoded.update(
                    {"protocol": "icmp", "type": layer.type, "code": layer.code}
                )

            if hasattr(layer, "payload"):
                if isinstance(layer.payload, Raw):
                    decoded["payload"] = bytes(layer.payload.load)
                    break
                layer = layer.payload
            else:
                break

        return decoded

    def _check_threshold(self, rule: IPSRule, src_ip: str) -> bool:
        """Check rate limiting thresholds using Redis"""
        if not rule.threshold:
            return True

        key = f"ips:threshold:{rule.rule_id}:{src_ip}"
        current = self.redis.incr(key)

        if current == 1:
            self.redis.expire(key, rule.window)

        return current >= rule.threshold

    def _create_event(self, rule: IPSRule, packet: Dict) -> Dict:
        """Create detection event structure"""
        return {
            "rule_id": rule.rule_id,
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet["protocol"],
            "payload": packet["payload"].hex(),
            "timestamp": packet["timestamp"],
            "severity": rule.severity,
            "category": rule.category,
        }

    async def shutdown(self):
        """Graceful shutdown procedure"""
        self.running.value = False
        self.packet_capturer.stop()
        self.mitigation_executor.stop()

        for worker in self.workers:
            worker.terminate()
            worker.join()

        await self.fw_manager.cleanup()
        logger.info("IPS Engine shutdown complete")


class MitigationExecutor:
    """Handles mitigation actions in a dedicated process"""

    def __init__(
        self,
        queue: Queue,
        fw_manager: FirewallManager,
        app_blocker: ApplicationBlocker,
        sio: socketio.AsyncServer,
    ):
        self.queue = queue
        self.fw_manager = fw_manager
        self.app_blocker = app_blocker
        self.sio = sio
        self.running = Value("b", True)
        self.process = None

    def start(self):
        """Start mitigation executor"""
        self.process = multiprocessing.Process(target=self._run)
        self.process.start()

    def _run(self):
        """Main mitigation loop"""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        while self.running.value:
            try:
                item = self.queue.get(timeout=1)
                if item:
                    rule, event = item
                    self._execute_mitigation(rule, event)
            except Exception as e:
                logger.error("Mitigation error: %s", str(e))

    def _execute_mitigation(self, rule: IPSRule, event: Dict):
        """Execute mitigation action based on rule"""
        try:
            if rule.action == IPSAction.BLOCK:
                self._handle_block(event["src_ip"], rule)
            elif rule.action == IPSAction.THROTTLE:
                self._handle_throttle(event["src_ip"], rule)
            elif rule.action == IPSAction.QUARANTINE:
                self._handle_quarantine(event["src_ip"], rule)

            self._log_event(event)
            self._send_alert(event, rule)

        except Exception as e:
            logger.error("Mitigation failed: %s", str(e))

    def _handle_block(self, ip: str, rule: IPSRule):
        """Execute blocking actions"""
        self.fw_manager.block_ip(ip, f"IPS Block: {rule.name}")
        self.app_blocker.add_to_blocklist(ip, reason=rule.description)
        logger.info("Blocked IP %s via rule %s", ip, rule.rule_id)

    def _handle_throttle(self, ip: str, rule: IPSRule):
        """Execute throttling actions"""
        self.fw_manager.throttle_ip(ip, rate_limit=rule.threshold, window=rule.window)
        logger.info("Throttled IP %s via rule %s", ip, rule.rule_id)

    def _handle_quarantine(self, ip: str, rule: IPSRule):
        """Execute quarantine actions"""
        self.fw_manager.quarantine_ip(ip)
        self.app_blocker.quarantine_device(ip)
        logger.info("Quarantined IP %s via rule %s", ip, rule.rule_id)

    def _log_event(self, event: Dict):
        """Log event to database"""

        async def _async_log():
            async with AsyncSessionLocal() as db:
                db_event = IPSEvent(**event)
                db.add(db_event)
                await db.commit()

        asyncio.run(_async_log())

    def _send_alert(self, event: Dict, rule: IPSRule):
        """Send real-time alert"""
        alert = {
            **event,
            "action": rule.action,
            "rule_name": rule.name,
            "severity": rule.severity,
            "mitigation_time": datetime.now().isoformat(),
        }
        asyncio.run(self.sio.emit("ips_alert", alert))

    def stop(self):
        """Stop mitigation executor"""
        self.running.value = False
        if self.process:
            self.process.join()


class RuleProcessor:
    """Optimized rule processing with precompiled patterns"""

    def preprocess_rule(self, rule: IPSRule) -> IPSRule:
        """Precompile and optimize detection rules"""
        processed = {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "protocol": rule.protocol.lower() if rule.protocol else None,
            "source_ips": self._parse_ip_ranges(rule.source_ip),
            "dest_ips": self._parse_ip_ranges(rule.destination_ip),
            "source_ports": self._parse_ports(rule.source_port),
            "dest_ports": self._parse_ports(rule.destination_port),
            "pattern": re.compile(rule.pattern.encode()) if rule.pattern else None,
            "action": rule.action,
            "severity": rule.severity,
            "threshold": rule.threshold,
            "window": rule.window,
            "category": rule.category,
        }
        return IPSRule(**processed)

    def match_packet(self, packet: Dict, rules: Dict) -> List[Tuple[IPSRule, Dict]]:
        """Match packet against all rules"""
        matched = []

        for rule in rules.values():
            if self._matches_rule(packet, rule):
                matched.append((rule, packet))

        return matched

    def _matches_rule(self, packet: Dict, rule: IPSRule) -> bool:
        """Check if packet matches rule criteria"""
        return (
            self._match_protocol(packet, rule)
            and self._match_ips(packet, rule)
            and self._match_ports(packet, rule)
            and self._match_payload(packet, rule)
        )

    def _match_protocol(self, packet: Dict, rule: IPSRule) -> bool:
        return not rule.protocol or packet["protocol"] == rule.protocol

    def _match_ips(self, packet: Dict, rule: IPSRule) -> bool:
        src_match = not rule.source_ips or any(
            packet["src_ip"] in net for net in rule.source_ips
        )
        dest_match = not rule.dest_ips or any(
            packet["dst_ip"] in net for net in rule.dest_ips
        )
        return src_match and dest_match

    def _match_ports(self, packet: Dict, rule: IPSRule) -> bool:
        src_port = packet.get("src_port")
        dest_port = packet.get("dst_port")

        src_match = not rule.source_ports or (
            src_port and src_port in rule.source_ports
        )
        dest_match = not rule.dest_ports or (dest_port and dest_port in rule.dest_ports)
        return src_match and dest_match

    def _match_payload(self, packet: Dict, rule: IPSRule) -> bool:
        return not rule.pattern or rule.pattern.search(packet["payload"])

    def _parse_ip_ranges(self, ip_spec: str) -> List[ipaddress.ip_network]:
        """Parse IP ranges/CIDRs into network objects"""
        if not ip_spec:
            return []

        networks = []
        for part in ip_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                networks.extend(
                    ipaddress.summarize_address_range(
                        ipaddress.ip_address(start), ipaddress.ip_address(end)
                    )
                )
            else:
                networks.append(ipaddress.ip_network(part, strict=False))
        return networks

    def _parse_ports(self, port_spec: str) -> Optional[Set[int]]:
        """Parse port specifications into sets"""
        if not port_spec:
            return None

        ports = set()
        for part in port_spec.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return ports


class PacketCapturer:
    """High-performance packet capture with multiprocessing"""

    def __init__(self, queue: Queue):
        self.queue = queue
        self.running = Value("b", True)
        self.process = None

    def start(self):
        """Start packet capture"""
        self.process = multiprocessing.Process(
            target=self._capture_packets, args=(self.queue, self.running)
        )
        self.process.start()

    def _capture_packets(self, queue: Queue, running: Value):
        """Packet capture main loop"""
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        def _enqueue(packet):
            if running.value:
                try:
                    queue.put(packet, timeout=0.1)
                except Exception as e:
                    logger.warning("Packet queue full, dropping packet")

        sniff(prn=_enqueue, filter="ip", store=False, count=0, quiet=True)

    def stop(self):
        """Stop packet capture"""
        self.running.value = False
        if self.process:
            self.process.terminate()
            self.process.join()


class IPSEngineMetrics:
    """Real-time engine performance monitoring"""

    def __init__(self):
        self.detections = 0
        self.processed_packets = 0
        self.errors = 0
        self.rule_updates = 0

    def update_detections(self):
        self.detections += 1

    def update_processed(self):
        self.processed_packets += 1

    def log_error(self):
        self.errors += 1

    def update_rules_loaded(self, count: int):
        self.rule_updates += 1


class LoadBalancer:
    """Dynamic workload distribution"""

    def __init__(self):
        self.worker_load = defaultdict(int)
        self.last_balance = datetime.now()

    def get_worker(self):
        """Get least busy worker"""
        return min(self.worker_load, key=self.worker_load.get)

    def update_load(self, worker_id: str, load: int):
        self.worker_load[worker_id] = load

    def balance_check(self):
        if (datetime.now() - self.last_balance).seconds > 60:
            self._rebalance()
            self.last_balance = datetime.now()

    def _rebalance(self):
        avg_load = sum(self.worker_load.values()) / len(self.worker_load)
        for worker in self.worker_load:
            if self.worker_load[worker] > avg_load * 1.3:
                self._adjust_workload(worker)


class DistributedSessionTracker:
    """Cluster-aware session tracking using Redis"""

    def __init__(self, redis: redis.Redis):
        self.redis = redis

    def track_connection(self, src_ip: str, protocol: str):
        key = f"ips:sessions:{src_ip}:{protocol}"
        self.redis.incr(key)
        self.redis.expire(key, 3600)  # 1 hour TTL

    def get_connection_count(self, src_ip: str, protocol: str) -> int:
        key = f"ips:sessions:{src_ip}:{protocol}"
        return int(self.redis.get(key) or 0)


class ThreatIntelClient:
    def __init__(self):
        self.abuseipdb_key = ABUSEIPDB_API_KEY
        self.virustotal_key = VIRUSTOTAL_API_KEY

    def check_ip(self, ip: str) -> Dict:
        results = {"score": 0, "tags": [], "sources": []}

        # ---- AbuseIPDB ----
        try:
            abuse_resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            data = abuse_resp.json().get("data", {})
            if data.get("abuseConfidenceScore", 0) > 0:
                results["score"] += data["abuseConfidenceScore"]
                results["tags"].append("abuseipdb")
                results["sources"].append("AbuseIPDB")
        except Exception as e:
            print(f"[TI] AbuseIPDB lookup failed: {e}")

        # ---- VirusTotal ----
        try:
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key},
            )
            data = vt_resp.json().get("data", {}).get("attributes", {})
            malicious_votes = data.get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_votes > 0:
                results["score"] += malicious_votes * 10
                results["tags"].append("virustotal")
                results["sources"].append("VirusTotal")
        except Exception as e:
            print(f"[TI] VirusTotal IP lookup failed: {e}")

        return results

    def check_domain(self, domain: str) -> Dict:
        results = {"score": 0, "tags": [], "sources": []}

        try:
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.virustotal_key},
            )
            data = vt_resp.json().get("data", {}).get("attributes", {})
            malicious_votes = data.get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_votes > 0:
                results["score"] += malicious_votes * 10
                results["tags"].append("virustotal")
                results["sources"].append("VirusTotal")
        except Exception as e:
            print(f"[TI] VirusTotal domain lookup failed: {e}")

        return results


# Usage example
async def main():
    sio = socketio.AsyncServer()
    app_blocker = ApplicationBlocker()
    engine = EnhancedIPSEngine(sio, app_blocker)

    try:
        await engine.initialize()
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await engine.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
