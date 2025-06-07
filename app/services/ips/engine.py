import asyncio
import re
import json
import logging
import multiprocessing
from multiprocessing import Queue
import signal
from queue import Full, Empty as QueueEmpty
import os
import time
import socket
import ipaddress
import requests
import platform
import subprocess
import asyncio
from typing import Optional, Dict, Any
import aiohttp
from dataclasses import asdict
import psutil


import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
from pathlib import Path
import socketio
import psutil
from scapy.all import IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet
import numpy as np
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import partial, lru_cache
import zlib
import heapq

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("enterprise_ips")
logger.setLevel(logging.DEBUG)

# Constants
MAX_PACKET_QUEUE_SIZE = 10000
RULE_RELOAD_INTERVAL = 300  # 5 minutes
STATS_REPORT_INTERVAL = 60  # 1 minute
MEMORY_MONITOR_INTERVAL = 30  # 30 seconds
HEARTBEAT_INTERVAL = 3  # 10 seconds


@dataclass
class RuleMatchResult:
    rule_id: str
    action: str
    severity: str
    category: str
    description: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class PacketContext:
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    payload: bytes
    timestamp: datetime
    packet_hash: str
    packet_size: int
    is_internal: bool
    direction: str  # 'inbound' or 'outbound'


class ThreatIntel:
    CACHE_FILE = "threat_feeds_cache.json"
    CACHE_EXPIRY_HOURS = 24

    def __init__(self):
        self.malicious_ips = set()
        self.tor_exit_nodes = set()
        self.last_cache_update = datetime.utcnow()

    @classmethod
    async def create(cls):
        self = cls()
        await self.load_from_cache()
        await self.fetch_and_cache_feeds()
        return self

    async def load_threat_feeds(self):
        """Load threat intelligence feeds, using cached data if available."""
        if self._is_cache_valid():
            # logger.info("Loading threat feeds from cache...")
            await self.load_from_cache()
        else:
            # logger.info("Fetching threat feeds from the web...")
            await self.fetch_and_cache_feeds()

    def _is_cache_valid(self) -> bool:
        if not os.path.exists("threat_feeds_cache.json"):
            return False
        try:
            with open("threat_feeds_cache.json", "r") as f:
                cache = json.load(f)
                timestamp = datetime.fromisoformat(cache.get("timestamp"))
                return datetime.utcnow() - timestamp < timedelta(
                    hours=self.CACHE_EXPIRY_HOURS
                )
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")
            return False

    async def load_from_cache(self):
        try:
            with open("threat_feeds_cache.json", "r") as f:
                cache = json.load(f)
                self.malicious_ips = set(cache.get("malicious_ips", []))
                self.tor_exit_nodes = set(cache.get("tor_exit_nodes", []))
        except FileNotFoundError:
            pass
            # no cache yet: that's OK, we'll fill it later
            # logger.info("No cache file found, will fetch feeds on background startup")
        except Exception as e:
            logger.error(f"Error reading cache: {e}")

    async def fetch_and_cache_feeds(self):
        try:
            firehol_url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
            tor_url = "https://check.torproject.org/exit-addresses"
            headers = {"User-Agent": "EnterpriseIPS/1.0 Threat Feed Fetcher"}

            # Fetch FireHOL list with retries
            firehol_ips = []
            for attempt in range(3):
                try:
                    async with aiohttp.ClientSession(headers=headers) as session:
                        async with session.get(firehol_url) as resp:
                            resp.raise_for_status()
                            text = await resp.text()
                            firehol_ips = text.splitlines()
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt == 2:
                        logger.error(f"FireHOL fetch failed after 3 attempts: {str(e)}")
                    await asyncio.sleep(2**attempt)
                except Exception as e:
                    logger.error(f"Unexpected error fetching FireHOL: {str(e)}")
                    await asyncio.sleep(2**attempt)

            self.malicious_ips = set(
                ip.strip() for ip in firehol_ips if ip and not ip.startswith("#")
            )

            # Fetch TOR exit nodes with retries
            tor_exit_ips = []
            for attempt in range(3):
                try:
                    async with aiohttp.ClientSession(headers=headers) as session:
                        async with session.get(tor_url) as resp:
                            resp.raise_for_status()
                            text = await resp.text()
                            tor_exit_ips = [
                                line.split()[1]
                                for line in text.splitlines()
                                if line.startswith("ExitAddress")
                            ]
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt == 2:
                        logger.error(
                            f"TOR exit nodes fetch failed after 3 attempts: {str(e)}"
                        )
                    await asyncio.sleep(2**attempt)
                except Exception as e:
                    logger.error(f"Unexpected error fetching TOR exits: {str(e)}")
                    await asyncio.sleep(2**attempt)

            self.tor_exit_nodes = set(tor_exit_ips)

            # Save results atomically
            try:
                self._save_cache()
                # logger.info(
                #     "Threat feeds updated: %d malicious IPs, %d TOR exit nodes",
                #     len(self.malicious_ips),
                #     len(self.tor_exit_nodes),
                # )
            except Exception as save_error:
                logger.error(f"Failed to save cache: {str(save_error)}")

        except Exception as e:
            logger.error(f"Critical failure in feed update: {str(e)}")
            # logger.info("Attempting to fall back to cached data...")

            try:
                # Try loading last successful cache
                self._load_cache()
                cache_time = getattr(self, "last_cache_update", None)
                logger.warning(
                    "Using cached threat data from %s",
                    cache_time.isoformat() if cache_time else "unknown time",
                )

                if cache_time:
                    cache_age = (
                        datetime.now(timezone.utc) - cache_time
                    ).total_seconds()
                    logger.warning("Cache is %.2f hours old", cache_age / 3600)
                    if cache_age > 86400:  # 24 hours
                        logger.error(
                            "Cached data is older than 24 hours - consider manual update"
                        )

            except Exception as load_error:
                logger.critical("Failed to load cached data: %s", str(load_error))
                # Maintain previous state if available
                if not hasattr(self, "malicious_ips"):
                    self.malicious_ips = set()
                if not hasattr(self, "tor_exit_nodes"):
                    self.tor_exit_nodes = set()

            finally:
                logger.warning(
                    "Current threat data: %d IPs, %d TOR nodes",
                    len(self.malicious_ips),
                    len(self.tor_exit_nodes),
                )

    def _save_cache(self):
        """Save current threat data to disk cache"""
        try:
            cache_data = {
                "malicious_ips": list(self.malicious_ips),
                "tor_exit_nodes": list(self.tor_exit_nodes),
                "timestamp": datetime.now().isoformat(),
            }

            with open("threat_feeds_cache.json", "w") as f:
                json.dump(cache_data, f)

            self.last_cache_update = datetime.now()
            # logger.debug("Threat data cached successfully")

        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def _load_cache(self):
        """Load threat data from disk cache"""
        try:
            with open("threat_feeds_cache.json", "r") as f:
                cache_data = json.load(f)

            self.malicious_ips = set(cache_data.get("malicious_ips", []))
            self.tor_exit_nodes = set(cache_data.get("tor_exit_nodes", []))
            self.last_cache_update = datetime.fromisoformat(cache_data["timestamp"])
            # logger.info("Loaded cached threat data from %s", self.last_cache_update)

        except FileNotFoundError:
            logger.warning("No cache file found - starting with empty threat data")
            self.malicious_ips = set()
            self.tor_exit_nodes = set()
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            # Maintain existing data if available
            if not hasattr(self, "malicious_ips"):
                self.malicious_ips = set()
            if not hasattr(self, "tor_exit_nodes"):
                self.tor_exit_nodes = set()

    def check_ip(self, ip: str) -> Dict:
        """Check if IP is in threat intelligence databases."""
        result = {
            "malicious": ip in self.malicious_ips,
            "tor_exit": ip in self.tor_exit_nodes,
            "threat_score": (
                90
                if ip in self.malicious_ips
                else (70 if ip in self.tor_exit_nodes else 0)
            ),
            "last_checked": datetime.utcnow().isoformat(),
        }
        return result


class RuleManager:

    def __init__(self, rule_file: str, config: Optional[Dict[str, Any]] = None):
        self.rule_file = rule_file
        self.rules = []
        self.rule_hash = ""
        self.last_loaded = None
        self.config = config or {}
        self.load_rules()

    def _calculate_rules_hash(self) -> str:
        """Calculate hash of rule file for change detection"""
        with open(self.rule_file, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

    def load_rules(self):
        """Load rules from JSON file"""
        try:
            current_hash = self._calculate_rules_hash()
            if current_hash == self.rule_hash:
                return False

            with open(self.rule_file) as f:
                rules_data = json.load(f)
                self.rules = rules_data
                self.rule_hash = current_hash
                self.last_loaded = datetime.now()
                ids = [rule["id"] for rule in rules_data]
                if len(set(ids)) != len(ids):
                    raise ValueError("Duplicate rule IDs found!")

                # logger.info(f"Loaded {len(self.rules)} rules from {self.rule_file}")
                self.validate_rules()
                return True
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return False

    def validate_rules(self):
        # logger.info("Validating IPS rules...")
        valid_actions = {"block", "alert", "throttle", "quarantine"}
        required_fields = {"id", "action", "severity", "description"}

        for idx, rule in enumerate(self.rules):
            context = f"Rule[{idx}] ID={rule.get('id', 'N/A')}"

            # Check required fields
            for field in required_fields:
                if field not in rule:
                    raise ValueError(f"{context} - Missing required field: {field}")

            # Validate action
            if rule["action"] not in valid_actions:
                raise ValueError(f"{context} - Invalid action: {rule['action']}")

            # Validate port format if present
            for port_field in ["source_port", "destination_port"]:
                if port_field in rule:
                    if not isinstance(rule[port_field], str):
                        raise ValueError(
                            f"{context} - {port_field} must be a string (e.g. '80', '1-1024', '80,443')"
                        )

            # Validate pattern is string if exists
            if "pattern" in rule and not isinstance(rule["pattern"], str):
                raise ValueError(f"{context} - Pattern must be a string")

            # Validate protocol is lowercase string if present
            if "protocol" in rule and not isinstance(rule["protocol"], str):
                raise ValueError(f"{context} - Protocol must be a string")

        # logger.info(f"✔️ All {len(self.rules)} rules validated successfully.")

    def get_rules_for_protocol(self, protocol: str) -> List[Dict]:
        """Get rules filtered by protocol"""
        return [
            rule
            for rule in self.rules
            if rule.get("protocol", "").lower() == protocol.lower()
        ]


class RateLimiter:
    def __init__(self, max_requests: int, time_window: timedelta):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)

    def check_rate_limit(self, key: str) -> bool:
        """Check if rate limit is exceeded"""
        now = datetime.now()
        window_start = now - self.time_window

        # Clean up old requests
        while self.requests[key] and self.requests[key][0] < window_start:
            self.requests[key].popleft()

        if len(self.requests[key]) >= self.max_requests:
            return False

        self.requests[key].append(now)
        return True


class PacketProcessor:
    def __init__(self, rule_manager: RuleManager, threat_intel: ThreatIntel):
        self.rule_manager = rule_manager
        self.threat_intel = threat_intel
        self.sequence_tracker = {}
        self.rate_limiters = {
            "strict": RateLimiter(10, timedelta(minutes=1)),
            "normal": RateLimiter(100, timedelta(minutes=5)),
            "lenient": RateLimiter(1000, timedelta(hours=1)),
        }
        self.session_tracker = SessionTracker()
        self.anomaly_detector = AnomalyDetector()
        self.packet_cache = PacketCache(max_size=10000, ttl=300)
        self.match_history = MatchHistoryTracker(
            ttl_seconds=rule_manager.config.get("match_ttl", 60)
        )

    def create_packet_context(self, packet: Packet) -> PacketContext:
        """Create context object from packet"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = None
        src_port = None
        dst_port = None
        payload = bytes()

        if TCP in packet:
            protocol = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            protocol = "icmp"
            payload = bytes(packet[ICMP].payload)

        packet_hash = hashlib.sha256(payload).hexdigest()
        is_internal = self._is_internal_ip(src_ip)
        direction = "inbound" if is_internal else "outbound"

        return PacketContext(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            timestamp=datetime.now(),
            packet_hash=packet_hash,
            packet_size=len(packet),
            is_internal=is_internal,
            direction=direction,
        )

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _ip_match(self, rule_ip: str, packet_ip: str, context: PacketContext) -> bool:
        """Enhanced IP matching with internal/private network support"""
        if not rule_ip:
            return True
        try:
            # Handle special cases first
            rule_ip_lower = rule_ip.lower()
            if rule_ip_lower == "tor":
                return self.threat_intel.check_ip(packet_ip).get("tor_exit", False)
            if rule_ip_lower == "malicious":
                return self.threat_intel.check_ip(packet_ip).get("malicious", False)
            if rule_ip_lower in ("internal", "private"):
                return context.is_internal

            # Existing CIDR/range matching
            if "-" in rule_ip:  # IP range
                start, end = rule_ip.split("-")
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                packet_ip_obj = ipaddress.ip_address(packet_ip)
                return start_ip <= packet_ip_obj <= end_ip
            elif "/" in rule_ip:  # CIDR
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:  # Exact match
                return rule_ip == packet_ip
        except ValueError:
            logger.error(f"Invalid IP pattern: {rule_ip}")
            return False

    def _port_match(self, rule_port: str, packet_port: int) -> bool:
        """Check if port matches rule pattern"""
        if not rule_port:
            return True
        try:
            if "-" in rule_port:  # Port range
                start, end = map(int, rule_port.split("-"))
                return start <= packet_port <= end
            elif "," in rule_port:  # Port list
                ports = list(map(int, rule_port.split(",")))
                return packet_port in ports
            else:  # Exact port
                return int(rule_port) == packet_port
        except ValueError:
            logger.error(f"Invalid port pattern: {rule_port}")
            return False

    def _content_match(self, rule: Dict, context: PacketContext) -> bool:
        """Enhanced content matching with protocol-specific inspection"""
        match_results = []
        payload = context.payload

        # Check TCP flags if rule specifies them
        if rule.get("flags") and context.protocol == "tcp":
            required_flags = set(rule["flags"].split(","))
            actual_flags = set(context.tcp_flags) if context.tcp_flags else set()
            match_results.append(required_flags.issubset(actual_flags))

        # Check SNI pattern for TLS
        if rule.get("sni_pattern") and context.protocol == "tls":
            sni = self._extract_sni(payload)
            if sni:
                match_results.append(re.search(rule["sni_pattern"], sni) is not None)
            else:
                match_results.append(False)

        # Check hex/regex pattern
        if rule.get("pattern"):
            try:
                if rule["pattern"].startswith("\\x"):  # Hex pattern
                    hex_pattern = rule["pattern"].replace("\\x", "")
                    hex_bytes = bytes.fromhex(hex_pattern)
                    match_results.append(hex_bytes in payload)
                else:  # Regex pattern
                    payload_str = payload.decode("utf-8", errors="ignore")
                    match_results.append(
                        re.search(rule["pattern"], payload_str, re.IGNORECASE)
                        is not None
                    )
            except (re.error, ValueError) as e:
                logger.error(f"Content match error: {e}")
                match_results.append(False)

        # Sequence number analysis (state tracking)
        if rule.get("sequence_analysis") and context.protocol == "tcp":
            key = (context.src_ip, context.src_port, context.dst_ip, context.dst_port)
            prev_seq = self.sequence_tracker.get(key, None)

            # Basic sequence number analysis
            if prev_seq and context.tcp_seq <= prev_seq:
                match_results.append(True)  # Detect out-of-order or retransmission
            else:
                match_results.append(False)
            self.sequence_tracker[key] = context.tcp_seq

        # logger.debug(f"[PAYLOAD]: {context.payload.decode(errors='ignore')[:200]}")
        # logger.debug(f"[PATTERN]: {rule.get('pattern')}")

        # All specified pattern checks must pass
        return all(match_results) if match_results else True

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Extract Server Name Indication from TLS Client Hello"""
        try:
            # TLS Record Layer (Handshake) offset
            if payload[0] != 0x16:  # Handshake type
                return None

            # Skip to Client Hello (offset 5 for TLS header)
            client_hello = payload[5:]

            # Client Hello should start with \x01
            if client_hello[0] != 0x01:
                return None

            # Skip session ID (1 byte length + session ID)
            session_id_len = client_hello[34]
            offset = 35 + session_id_len

            # Skip cipher suites (2 bytes length + suites)
            cipher_len = int.from_bytes(client_hello[offset : offset + 2], "big")
            offset += 2 + cipher_len

            # Skip compression methods (1 byte length + methods)
            comp_len = client_hello[offset]
            offset += 1 + comp_len

            # Extensions length
            ext_len = int.from_bytes(client_hello[offset : offset + 2], "big")
            offset += 2

            # Parse extensions
            while offset < len(client_hello) and offset < 35 + ext_len:
                ext_type = int.from_bytes(client_hello[offset : offset + 2], "big")
                ext_len = int.from_bytes(client_hello[offset + 2 : offset + 4], "big")
                if ext_type == 0x00:  # SNI extension
                    server_name_list = client_hello[offset + 4 : offset + 4 + ext_len]
                    name_type = server_name_list[0]
                    name_len = int.from_bytes(server_name_list[1:3], "big")
                    return server_name_list[3 : 3 + name_len].decode("utf-8")
                offset += 4 + ext_len

            return None
        except (IndexError, UnicodeDecodeError):
            return None

    def _entropy_check(self, payload: bytes, threshold: float) -> bool:
        """Check if payload entropy exceeds threshold"""
        if not payload:
            return False
        freq = defaultdict(int)
        for byte in payload:
            freq[byte] += 1
        total = len(payload)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * np.log2(p)
        return entropy >= threshold

    def _check_threshold(self, rule: Dict, src_ip: str) -> bool:
        """Check if event threshold is reached"""
        if not rule.get("threshold"):
            return True
        return self.session_tracker.check_threshold(
            rule["id"], src_ip, rule["threshold"], rule.get("window", 10)
        )

    def process_packet(self, packet: Packet) -> List[RuleMatchResult]:
        """Process a single packet against all rules"""
        if not IP in packet:
            return []

        context = self.create_packet_context(packet)
        matched_rules = []

        # Check against all rules for the packet's protocol
        protocol_rules = self.rule_manager.get_rules_for_protocol(context.protocol)

        for rule in protocol_rules:
            if self.match_history.should_skip(context.src_ip, rule["id"]):
                continue
            if not self._ip_match(rule.get("source_ip"), context.src_ip, context):
                continue
            if not self._ip_match(rule.get("destination_ip"), context.dst_ip, context):
                continue
            if not self._port_match(rule.get("source_port"), context.src_port):
                continue
            if not self._port_match(rule.get("destination_port"), context.dst_port):
                continue
            if not self._content_match(rule.get("pattern"), context.payload):
                continue
            if not self._check_threshold(rule, context.src_ip):
                continue
            if rule.get("entropy_threshold") and not self._entropy_check(
                context.payload, rule["entropy_threshold"]
            ):
                continue

            # Rule matched
            matched_rules.append(
                RuleMatchResult(
                    rule_id=rule["id"],
                    action=rule["action"],
                    severity=rule["severity"],
                    category=rule.get("category", "unknown"),
                    description=rule["description"],
                    metadata={
                        "mitre_tactic": rule.get("mitre_tactic"),
                        "mitre_technique": rule.get("mitre_technique"),
                        "cve": rule.get("cve"),
                    },
                )
            )

        # Check for anomalies
        anomaly_rules = self.anomaly_detector.detect(context)
        matched_rules.extend(anomaly_rules)

        return matched_rules


class MatchHistoryTracker:
    def __init__(self, ttl_seconds: int = 60):
        self.ttl = timedelta(seconds=ttl_seconds)
        self.match_history = {}
        self.lock = multiprocessing.Lock()

    def should_skip(self, ip: str, rule_id: str) -> bool:
        key = f"{ip}:{rule_id}"
        now = datetime.now()
        with self.lock:
            self._cleanup(now)
            last_match = self.match_history.get(key)
            if last_match and (now - last_match) < self.ttl:
                # logger.debug(f"Skipping repeated match: {key}")
                return True
            self.match_history[key] = now
            return False

    def _cleanup(self, now):
        expired = [k for k, t in self.match_history.items() if (now - t) > self.ttl]
        for key in expired:
            del self.match_history[key]


class SessionTracker:
    def __init__(self):
        self.session_counts = defaultdict(int)
        self.session_timers = defaultdict(datetime)
        self.lock = multiprocessing.Lock()

    def check_threshold(
        self, rule_id: str, src_ip: str, threshold: int, window: int
    ) -> bool:
        """Check if event threshold is reached within time window"""
        key = f"{rule_id}:{src_ip}"
        now = datetime.now()

        with self.lock:
            # Reset counter if window expired
            if (
                key in self.session_timers
                and (now - self.session_timers[key]).total_seconds() > window
            ):
                self.session_counts[key] = 0

            self.session_counts[key] += 1
            self.session_timers[key] = now

            return self.session_counts[key] >= threshold


class AnomalyDetector:
    def __init__(self):
        self.baselines = {
            "tcp": {"mean_packet_size": 512, "std_dev": 128},
            "udp": {"mean_packet_size": 256, "std_dev": 64},
            "http": {"mean_packet_size": 1024, "std_dev": 256},
        }
        self.port_scan_threshold = 50  # Ports per minute
        self.port_scan_window = timedelta(minutes=1)
        self.port_scan_counts = defaultdict(int)
        self.port_scan_timers = defaultdict(datetime)

    def detect(self, context: PacketContext) -> List[RuleMatchResult]:
        """Detect anomalies in packet context"""
        results = []

        # Packet size anomaly
        if context.protocol in self.baselines:
            baseline = self.baselines[context.protocol]
            z_score = (context.packet_size - baseline["mean_packet_size"]) / baseline[
                "std_dev"
            ]
            if abs(z_score) > 3:  # 3 standard deviations
                results.append(
                    RuleMatchResult(
                        rule_id="ANOMALY-001",
                        action="alert",
                        severity="medium",
                        category="anomaly",
                        description=f"Abnormal {context.protocol} packet size ({context.packet_size} bytes, z-score: {z_score:.2f})",
                        confidence=min(0.9, abs(z_score) / 10),
                    )
                )

        # Port scan detection
        if context.protocol in ["tcp", "udp"]:
            key = f"{context.src_ip}:{context.protocol}"
            now = datetime.now()

            # Reset counter if window expired
            if (
                key in self.port_scan_timers
                and (now - self.port_scan_timers[key]) > self.port_scan_window
            ):
                self.port_scan_counts[key] = 0

            self.port_scan_counts[key] += 1
            self.port_scan_timers[key] = now

            if self.port_scan_counts[key] >= self.port_scan_threshold:
                results.append(
                    RuleMatchResult(
                        rule_id="ANOMALY-002",
                        action="alert",
                        severity="high",
                        category="scan",
                        description=f"Potential {context.protocol} port scan from {context.src_ip} ({self.port_scan_counts[key]} ports in last minute)",
                        confidence=min(
                            0.95, self.port_scan_counts[key] / self.port_scan_threshold
                        ),
                    )
                )

        return results


class PacketCache:
    def __init__(self, max_size: int = 10000, ttl: int = 300):
        self.max_size = max_size
        self.ttl = timedelta(seconds=ttl)
        self.cache = {}
        self.lru = []
        self.lock = multiprocessing.Lock()

    def add_packet(self, packet_hash: str, timestamp: datetime):
        """Add packet to cache"""

        with self.lock:
            # Clean up expired entries
            self._cleanup()

            if packet_hash not in self.cache and len(self.cache) < self.max_size:
                self.cache[packet_hash] = timestamp
                heapq.heappush(self.lru, (timestamp, packet_hash))

    def check_packet(self, packet_hash: str) -> bool:
        """Check if packet is in cache"""
        with self.lock:
            self._cleanup()
            return packet_hash in self.cache

    def _cleanup(self):
        """Remove expired entries"""
        now = datetime.now()
        while self.lru and (now - self.lru[0][0]) > self.ttl:
            _, packet_hash = heapq.heappop(self.lru)
            self.cache.pop(packet_hash, None)


class MitigationEngine:
    def __init__(
        self,
        sio: socketio.AsyncServer,
        threat_intel: ThreatIntel,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.sio = sio
        self.threat_intel = threat_intel  # Store ThreatIntel instance
        self.config = config or {}
        self.blocked_ips = set()
        self.throttled_ips = set()
        self.quarantined_ips = set()
        self.lock = asyncio.Lock()
        self.firewall_backend = self._detect_firewall_backend()
        # Initialize aiohttp.ClientSession with a default timeout
        default_timeout = self.config.get(
            "default_api_timeout", 10
        )  # Default to 10 seconds
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=default_timeout)
        )
        self._init_platform_specifics()
        # Ensure dashboard_config is initialized, e.g., from self.config or defaults
        self.dashboard_config = self.config.get(
            "dashboard_config",
            {
                "base_url": "http://localhost:5000",  # Example default
                "api_key": "secret-key",  # Example default
                "max_retries": 3,
                "retry_delay": 2,
            },
        )

    async def mitigate(self, match: RuleMatchResult, context: PacketContext):
        """Route mitigation action to the appropriate method"""
        action = match.action.lower()
        ip = context.src_ip

        if action == "block":
            await self._block_ip(ip, match)
        elif action == "throttle":
            await self._throttle_ip(ip, match)
        elif action == "quarantine":
            await self._quarantine_ip(ip, match)
        elif action == "alert":
            # logger.info(f"ALERT only: {match.description} for IP {ip}")
            # For 'alert' actions, we still want to notify the frontend and potentially SIEM
            await self._send_mitigation_event(
                "alert", ip, match, success=True
            )  # success is true as it's an alert
        else:
            logger.warning(f"Unknown mitigation action: {action}")

    def _init_platform_specifics(self):
        """Initialize platform-specific configurations"""
        self.os_type = platform.system().lower()
        self.supported_actions = {
            "block": self._block_ip_impl,
            "throttle": self._throttle_ip_impl,
            "quarantine": self._quarantine_ip_impl,
        }

        # Platform-specific command templates
        self.command_templates = {
            "linux": {
                # block: Inserts rule at the beginning of INPUT chain for precedence.
                "block": "iptables -I INPUT 1 -s {ip} -j DROP",
                "unblock": "iptables -D INPUT -s {ip} -j DROP",
                # throttle: Accepts packets if within limit. Depends on a subsequent general DROP rule for the IP to be effective for rate limiting.
                # For more robust throttling, consider custom chains with hashlimit module.
                "throttle": "iptables -I INPUT -s {ip} -m limit --limit {limit}/minute --limit-burst 10 -j ACCEPT",
                "quarantine": "iptables -I INPUT 1 -s {ip} -j DROP && "  # Host block
                "iptables -I OUTPUT 1 -d {ip} -j DROP",  # Host block for outbound
            },
            "windows": {
                "block": "netsh advfirewall firewall add rule name='IPS Block {ip}' dir=in action=block remoteip={ip} profile=any enable=yes",
                # throttle: Windows Firewall 'rate' parameter behavior is not a direct packet-dropping throttle.
                # This rule allows if rate is below specified value; actual excess packet dropping is not guaranteed.
                "throttle": "netsh advfirewall firewall add rule name='IPS Throttle {ip}' dir=in action=allow remoteip={ip} profile=any enable=yes security=notrequired remoteport=any localport=any protocol=any interfacetype=any",  # Rate parameter removed as it's unclear/unreliable.
                "quarantine": "netsh advfirewall firewall add rule name='IPS Quarantine In {ip}' dir=in action=block remoteip={ip} profile=any enable=yes && "
                "netsh advfirewall firewall add rule name='IPS Quarantine Out {ip}' dir=out action=block remoteip={ip} profile=any enable=yes",
            },
            "darwin": {
                "block": "pfctl -t blocked_ips -T add {ip}",  # Assumes 'blocked_ips' table is defined and used in pf.conf
                # throttle: Limits new connection creation rate from the source IP. Does not throttle bandwidth/packet rate of existing connections.
                "throttle": "echo 'block in quick from {ip} max-src-conn-rate {limit}/60' | pfctl -f -",
                "quarantine": "pfctl -t quarantined_ips -T add {ip} && "  # Assumes 'quarantined_ips' tables are defined
                "pfctl -t quarantined_ips_out -T add {ip}",
            },
        }

    @lru_cache(maxsize=1)
    def _detect_firewall_backend(self) -> str:
        """Detect available firewall backend"""
        try:
            if platform.system().lower() == "linux":
                # Check for iptables
                subprocess.run(
                    ["iptables", "-L"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return "iptables"
            elif platform.system().lower() == "windows":
                # Check for Windows Firewall
                subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofile"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return "windows_firewall"
            elif platform.system().lower() == "darwin":
                # Check for pfctl on macOS
                subprocess.run(
                    ["pfctl", "-E"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return "pf"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Fallback to API-based if available in config
        if self.config.get("firewall_api"):
            return "api"

        return "in_memory"  # Fallback to in-memory tracking only

    async def _execute_command(self, command: str) -> bool:
        """Execute a shell command safely"""
        try:
            proc = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(
                    f"Command failed: {command}\nError: {stderr.decode().strip()}"
                )
                return False
            return True
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False

    async def _call_firewall_api(self, action: str, ip: str, **kwargs) -> bool:
        """Call external firewall API if configured"""
        if not self.config.get("firewall_api"):
            return False

        endpoint = f"{self.config['firewall_api']}/{action}"
        headers = {
            "Authorization": f"Bearer {self.config.get('firewall_api_key', '')}",
            "Content-Type": "application/json",
        }

        payload = {
            "ip": ip,
            "rule_id": kwargs.get("rule_id"),
            "severity": kwargs.get("severity"),
            "duration": kwargs.get("duration", 3600),  # Default 1 hour
        }

        try:
            async with self.session.post(
                endpoint, json=payload, headers=headers
            ) as resp:
                if resp.status == 200:
                    return True
                logger.error(f"Firewall API error: {await resp.text()}")
                return False
        except Exception as e:
            logger.error(f"Firewall API call failed: {e}")
            return False

    async def _block_ip_impl(self, ip: str, **kwargs) -> bool:
        """Platform-specific IP blocking implementation"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("block", ip, **kwargs)

        if self.firewall_backend == "in_memory":
            return True  # Just track in memory

        template = self.command_templates.get(self.os_type, {}).get("block")
        if not template:
            logger.error(f"No block command template for OS: {self.os_type}")
            return False

        command = template.format(ip=ip, **kwargs)
        return await self._execute_command(command)

    async def _throttle_ip_impl(self, ip: str, **kwargs) -> bool:
        """Platform-specific IP throttling implementation"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("throttle", ip, **kwargs)

        if self.firewall_backend == "in_memory":
            return True

        template = self.command_templates.get(self.os_type, {}).get("throttle")
        if not template:
            logger.error(f"No throttle command template for OS: {self.os_type}")
            return False

        # Default to 30 packets per minute if not specified
        limit = kwargs.get("limit", 30)
        command = template.format(ip=ip, limit=limit, **kwargs)
        return await self._execute_command(command)

    async def _quarantine_ip_impl(self, ip: str, **kwargs) -> bool:
        """Platform-specific IP quarantine implementation"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("quarantine", ip, **kwargs)

        if self.firewall_backend == "in_memory":
            return True

        template = self.command_templates.get(self.os_type, {}).get("quarantine")
        if not template:
            logger.error(f"No quarantine command template for OS: {self.os_type}")
            return False

        command = template.format(ip=ip, **kwargs)
        return await self._execute_command(command)

    async def _block_ip(self, ip: str, match: RuleMatchResult):
        """Robust IP blocking with multiple fallback mechanisms"""
        async with self.lock:
            if ip in self.blocked_ips:
                return

            success = False
            mitigation_data = {
                "rule_id": match.rule_id,
                "severity": match.severity,
                "description": match.description,
                "duration": 86400,  # 24 hours by default
            }

            # Try primary blocking method
            try:
                success = await self._block_ip_impl(ip, **mitigation_data)

                # Fallback to alternative methods if primary fails
                if not success and self.firewall_backend != "in_memory":
                    logger.warning(f"Primary block failed for {ip}, trying fallback")
                    success = await self._call_firewall_api(
                        "block", ip, **mitigation_data
                    )

            except Exception as e:
                logger.error(f"Block IP error: {e}")
                success = False

            if success:
                self.blocked_ips.add(ip)
                logger.warning(
                    f"Successfully blocked IP {ip} due to rule {match.rule_id}"
                )
                await self._send_mitigation_event("block", ip, match, success=True)

                # Additional actions for blocked IPs
                await self._post_block_actions(ip, match)
            else:
                logger.error(f"Failed to block IP {ip}")
                await self._send_mitigation_event("block", ip, match, success=False)

    async def _throttle_ip(self, ip: str, match: RuleMatchResult):
        """Robust IP throttling with rate limiting"""
        async with self.lock:
            if ip in self.throttled_ips:
                return

            success = False
            mitigation_data = {
                "rule_id": match.rule_id,
                "severity": match.severity,
                "description": match.description,
                "limit": 30,  # Default to 30 packets/min
            }

            try:
                success = await self._throttle_ip_impl(ip, **mitigation_data)

                if not success and self.firewall_backend != "in_memory":
                    logger.warning(f"Primary throttle failed for {ip}, trying fallback")
                    success = await self._call_firewall_api(
                        "throttle", ip, **mitigation_data
                    )

            except Exception as e:
                logger.error(f"Throttle IP error: {e}")
                success = False

            if success:
                self.throttled_ips.add(ip)
                logger.warning(
                    f"Successfully throttled IP {ip} due to rule {match.rule_id}"
                )
                await self._send_mitigation_event("throttle", ip, match, success=True)
            else:
                logger.error(f"Failed to throttle IP {ip}")
                await self._send_mitigation_event("throttle", ip, match, success=False)

    async def _quarantine_ip(self, ip: str, match: RuleMatchResult):
        """Robust IP quarantine with full isolation"""
        async with self.lock:
            if ip in self.quarantined_ips:
                return

            success = False
            mitigation_data = {
                "rule_id": match.rule_id,
                "severity": match.severity,
                "description": match.description,
                "duration": 86400,  # 24 hours by default
            }

            try:
                # Try primary quarantine method
                success = await self._quarantine_ip_impl(ip, **mitigation_data)

                # Fallback to blocking if quarantine fails
                if not success and self.firewall_backend != "in_memory":
                    logger.warning(f"Primary quarantine failed for {ip}, trying block")
                    success = await self._block_ip_impl(ip, **mitigation_data)

            except Exception as e:
                logger.error(f"Quarantine IP error: {e}")
                success = False

            if success:
                self.quarantined_ips.add(ip)
                logger.warning(
                    f"Successfully quarantined IP {ip} due to rule {match.rule_id}"
                )
                await self._send_mitigation_event("quarantine", ip, match, success=True)

                # Additional quarantine actions
                await self._post_quarantine_actions(ip, match)
            else:
                logger.error(f"Failed to quarantine IP {ip}")
                await self._send_mitigation_event(
                    "quarantine", ip, match, success=False
                )

    async def _post_block_actions(self, ip: str, match: RuleMatchResult):
        """Additional actions to take after blocking an IP"""
        try:
            # 1. Update threat intelligence feeds
            if self.config.get("threat_intel_api"):
                await self._update_threat_intel(ip, "blocked")

            # 2. Notify SIEM/SOC systems - This is now handled by _send_mitigation_event calling _notify_frontend_and_siem
            # await self._notify_frontend_and_siem(ip, match, action="block") # Old direct call

            # 3. Log to external logging system
            await self._log_to_external_systems(ip, match, "block")

        except Exception as e:
            logger.error(f"Post-block actions failed: {e}")

    async def _post_quarantine_actions(self, ip: str, match: RuleMatchResult):
        """Additional actions to take after quarantining an IP"""
        try:
            # 1. Isolate from internal networks
            if self._is_internal_ip(ip):
                await self._isolate_from_internal(ip)

            # 2. Initiate forensic collection
            await self._collect_forensic_data(ip)

            # 3. Notify incident response team
            await self._notify_incident_response(ip, match)

        except Exception as e:
            logger.error(f"Post-quarantine actions failed: {e}")

    async def _send_mitigation_event(
        self, action: str, ip: str, match: RuleMatchResult, success: bool
    ):
        """Send mitigation event notification with rich details"""
        # This method will now call the new _notify_frontend_and_siem
        # The specific 'ips_mitigation' event might become redundant or be a summary event
        # For now, let's call the new comprehensive notification method
        await self._notify_frontend_and_siem(ip, match, action, success)

        # Original simpler event emission (can be removed or kept for specific high-level overview)
        # event_data = {
        #     "timestamp": datetime.now().isoformat(),
        #     "action": action,
        #     "ip": ip,
        #     "rule": asdict(match),
        #     "success": success,
        #     "platform": self.os_type,
        #     "firewall_backend": self.firewall_backend,
        #     "mitigation_chain": [
        #         {
        #             "method": self.firewall_backend,
        #             "success": success,
        #             "timestamp": datetime.now().isoformat(),
        #         }
        #     ],
        # }
        # try:
        #     await self.sio.emit("ips_mitigation_summary", event_data) # Renamed to avoid conflict
        # except Exception as e:
        #     logger.error(f"Failed to send summary mitigation event: {e}")

    async def cleanup(self):
        """Clean up resources"""
        await self.session.close()
        # Remove all temporary blocks/throttles if needed
        if self.config.get("cleanup_on_exit", False):
            await self._cleanup_rules()

    async def _cleanup_rules(self):
        """Clean up firewall rules on shutdown"""
        if self.firewall_backend == "in_memory":
            return

        # logger.info("Cleaning up firewall rules...")

        async with self.lock:
            # Unblock all blocked IPs
            for ip in list(self.blocked_ips):
                await self._unblock_ip(ip)

            # Remove all throttles
            for ip in list(self.throttled_ips):
                await self._unthrottle_ip(ip)

            # Remove quarantines
            for ip in list(self.quarantined_ips):
                await self._unquarantine_ip(ip)

    async def _unblock_ip(self, ip: str) -> bool:
        """Remove IP block"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("unblock", ip)

        template = self.command_templates.get(self.os_type, {}).get("unblock")
        if not template:
            return False

        command = template.format(ip=ip)
        success = await self._execute_command(command)
        if success:
            self.blocked_ips.discard(ip)
        return success

    async def _unthrottle_ip(self, ip: str) -> bool:
        """Remove IP throttle"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("unthrottle", ip)

        # On most systems, removing the block is equivalent to unthrottling
        return await self._unblock_ip(ip)

    async def _unquarantine_ip(self, ip: str) -> bool:
        """Remove IP quarantine"""
        if self.firewall_backend == "api":
            return await self._call_firewall_api("unquarantine", ip)

        template = self.command_templates.get(self.os_type, {}).get("unquarantine")
        if not template:
            return False

        command = template.format(ip=ip)
        success = await self._execute_command(command)
        if success:
            self.quarantined_ips.discard(ip)
        return success

    # Helper methods for additional functionality
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal/private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    async def _update_threat_intel(self, ip: str, action: str) -> bool:
        """Update threat intelligence feeds"""
        threat_intel_api_url = self.config.get("threat_intel_api")
        if not threat_intel_api_url:
            # logger.debug(
            #     "Threat intelligence API URL not configured. Skipping update for IP %s.",
            #     ip,
            # )
            return False

        api_key = self.config.get("threat_intel_api_key", "")
        payload = {"ip": ip, "action": action, "source": "EnterpriseIPS"}
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        # Timeout for this specific call, otherwise session default is used.
        # Explicit timeout example: timeout=aiohttp.ClientTimeout(total=self.config.get("threat_intel_api_timeout", 15)))

        try:
            # logger.debug(
            #     f"Attempting to update threat intel for IP {ip} (action: {action}) via {threat_intel_api_url}"
            # )
            async with self.session.post(
                threat_intel_api_url, json=payload, headers=headers
            ) as resp:
                response_text = await resp.text()
                if resp.status == 200:
                    # logger.info(
                    #     f"Successfully updated threat intelligence for IP {ip} (action: {action}). Response: {response_text}"
                    # )
                    return True
                else:
                    logger.warning(
                        f"Failed to update threat intelligence for IP {ip}. Status: {resp.status}. Response: {response_text}"
                    )
                    return False
        except (
            asyncio.TimeoutError
        ):  # This will be caught if the session's default timeout is exceeded
            logger.error(
                f"Timeout updating threat intelligence for IP {ip} at {threat_intel_api_url}."
            )
            return False
        except aiohttp.ClientError as e:
            logger.error(f"Client error updating threat intelligence for IP {ip}: {e}")
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error updating threat intelligence for IP {ip}: {e}",
                exc_info=True,
            )
            return False

    async def _notify_frontend_and_siem(
        self, ip: str, match: RuleMatchResult, action: str, success: bool = True
    ) -> None:
        """
        Notify frontend via Socket.IO and optionally send to SIEM.
        Primary purpose is real-time frontend updates.
        """
        # Determine Socket.IO event name
        event_name_map = {
            "block": "ips_ip_blocked",
            "throttle": "ips_ip_throttled",
            "quarantine": "ips_ip_quarantined",
            "alert": "ips_threat_detected",
        }
        event_name = event_name_map.get(action.lower(), "ips_security_event")

        # Construct event payload
        event_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "action_taken": action,
            "ip_address": ip,
            "rule_details": {
                "id": match.rule_id,
                "description": match.description,
                "severity": match.severity,
                "category": match.category,
                "confidence": getattr(match, "confidence", 1.0),
                "metadata": getattr(match, "metadata", {}),
            },
            "geo_data": await self._get_geo_data(ip),
            "threat_intel": self.threat_intel.check_ip(
                ip
            ),  # Accessing via self.threat_intel
            "success": success,  # Include success status of the action
            # "raw_packet_sample": "TODO: Add sanitized sample if needed", # Optional
        }

        # Emit to frontend via Socket.IO
        try:
            await self.sio.emit(event_name, event_payload)
            # logger.info(f"Emitted frontend event '{event_name}' for IP {ip}")
        except Exception as e:
            logger.error(f"Failed to emit frontend event '{event_name}': {e}")

        # Retain SIEM functionality (attempt to send to dashboard)
        # This part is largely from the original _send_to_siem method
        if not hasattr(self, "dashboard_config") or not self.dashboard_config.get(
            "base_url"
        ):
            logger.debug(
                "Dashboard configuration not available or base_url not set, skipping SIEM submission."
            )
            return

        dashboard_url = f"{self.dashboard_config.get('base_url', '')}/api/events"
        headers = {
            "Authorization": f"Bearer {self.dashboard_config.get('api_key', '')}",
            "Content-Type": "application/json",
            "User-Agent": "EnterpriseIPS/1.0",
        }

        # Reconstruct event_data for SIEM, can be same as frontend or different
        siem_event_data = {
            "timestamp": event_payload["timestamp"],
            "event_type": "ips_security_event",  # Generic type for SIEM
            "action": event_payload["action_taken"],
            "source": "ips_engine",
            "ip_address": event_payload["ip_address"],
            "rule": event_payload["rule_details"],  # Nested rule details
            "mitigation_details": {
                "platform": self.os_type,
                "firewall_backend": self.firewall_backend,
                "success": success,
                "attempts": 0,  # Initial attempt
            },
            "geo_data": event_payload["geo_data"],
            "threat_intel": event_payload["threat_intel"],
            "related_events": [],
        }

        max_retries = self.dashboard_config.get("max_retries", 3)
        retry_delay = self.dashboard_config.get("retry_delay", 2)  # seconds
        timeout = aiohttp.ClientTimeout(total=self.dashboard_config.get("timeout", 10))

        for attempt in range(1, max_retries + 1):
            siem_event_data["mitigation_details"]["attempts"] = attempt
            try:
                async with self.session.post(
                    dashboard_url,
                    json=siem_event_data,
                    headers=headers,
                    timeout=timeout,
                ) as response:
                    if response.status == 200:
                        # logger.info(
                        #     f"Successfully sent SIEM event for {ip} (action: {action}) to dashboard"
                        # )
                        return  # Successfully sent to SIEM

                    if response.status == 401:
                        logger.error(
                            "SIEM Dashboard API authentication failed. Check API key."
                        )
                        return  # Auth error, don't retry
                    elif response.status == 429:
                        custom_retry_after = response.headers.get("Retry-After")
                        wait_time = (
                            int(custom_retry_after)
                            if custom_retry_after
                            else (retry_delay * attempt)
                        )
                        logger.warning(
                            f"SIEM rate limited (HTTP 429). Retrying after {wait_time}s. Attempt {attempt}/{max_retries}."
                        )
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        logger.warning(
                            f"SIEM dashboard API returned {response.status} for {ip}. Attempt {attempt}/{max_retries}. Error: {await response.text()}"
                        )
                        await asyncio.sleep(retry_delay * attempt)

            except asyncio.TimeoutError:
                logger.warning(
                    f"SIEM dashboard timeout for {ip}. Attempt {attempt}/{max_retries}"
                )
                await asyncio.sleep(retry_delay * attempt)
            except aiohttp.ClientConnectionError as e:  # More specific network errors
                logger.warning(
                    f"SIEM dashboard connection error for {ip}: {e}. Attempt {attempt}/{max_retries}"
                )
                await asyncio.sleep(retry_delay * attempt)
            except Exception as e:  # Catch other unexpected errors
                logger.error(
                    f"Unexpected error sending to SIEM dashboard for {ip}: {e}. Attempt {attempt}/{max_retries}"
                )
                await asyncio.sleep(retry_delay * attempt)

        # If all retries fail
        logger.error(
            f"Failed to send SIEM event for {ip} (action: {action}) to dashboard after {max_retries} attempts."
        )
        siem_event_data["mitigation_details"][
            "success"
        ] = False  # Mark as failed for SIEM
        await self._store_failed_event(siem_event_data)  # Store for later retry

    async def _get_geo_data(self, ip: str) -> dict:
        """Get geolocation data for IP (with local cache)"""
        if not hasattr(self, "_geo_cache"):
            self._geo_cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour cache

        if ip in self._geo_cache:
            return self._geo_cache[ip]

        if not hasattr(self, "geoip_config"):
            return {}

        try:
            # Use your preferred GeoIP service (MaxMind, IPAPI, etc.)
            # Example: geo_url = f"https://ipapi.co/{ip}/json/" or from config
            geo_url_template = self.config.get("geoip_service_url_template")
            if not geo_url_template:
                logger.debug("GeoIP service URL template not configured.")
                return {}

            geo_url = geo_url_template.format(ip=ip)
            params = self.config.get("geoip_service_params", {})
            # Example params: {"key": "YOUR_API_KEY"} if needed by the service

        except KeyError as e:  # If service_url_template is missing in geoip_config
            logger.error(f"GeoIP configuration missing key: {e}")
            return {}
        except Exception as e:  # Catch other unexpected errors during config access
            logger.error(f"Error accessing GeoIP configuration: {e}", exc_info=True)
            return {}

        try:
            # Using session's default timeout unless overridden here
            async with self.session.get(geo_url, params=params) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        self._geo_cache[ip] = data
                        return data
                    except aiohttp.ContentTypeError:  # Non-JSON response
                        logger.error(
                            f"GeoIP service returned non-JSON response for {ip}. Status: {response.status}. Response: {await response.text()[:200]}"
                        )
                        return {}
                    except Exception as e:  # Includes json.JSONDecodeError
                        logger.error(
                            f"GeoIP JSON parsing failed for {ip}: {e}. Response: {await response.text()[:200]}",
                            exc_info=True,
                        )
                        return {}
                else:
                    logger.warning(
                        f"GeoIP lookup for {ip} failed with status {response.status}. Response: {await response.text()[:200]}"
                    )
                    return {}
        except asyncio.TimeoutError:
            logger.error(f"Timeout during GeoIP lookup for {ip} at {geo_url}.")
            return {}
        except aiohttp.ClientError as e:
            logger.error(f"Client error during GeoIP lookup for {ip}: {e}")
            return {}
        except Exception as e:
            logger.error(
                f"Unexpected error during GeoIP lookup for {ip}: {e}", exc_info=True
            )
            return {}

    async def _store_failed_event(self, event_data: dict):
        """Store failed events for later delivery"""
        if not hasattr(self, "failed_events_queue"):
            self.failed_events_queue = asyncio.Queue(maxsize=1000)

        try:
            # Compress the event data to save space
            compressed = zlib.compress(json.dumps(event_data).encode("utf-8"))
            await self.failed_events_queue.put(compressed)

            # Start background delivery if not already running
            if not hasattr(self, "_retry_task"):
                self._retry_task = asyncio.create_task(self._retry_failed_events())
        except asyncio.QueueFull:
            logger.error("Failed events queue full, dropping event")
        except Exception as e:
            logger.error(f"Failed to store event for retry: {str(e)}")

    async def _retry_failed_events(self):
        """Background task to retry failed events"""
        # logger.info("Starting failed events retry handler")
        while True:
            try:
                # Wait for new events with timeout
                try:
                    compressed = await asyncio.wait_for(
                        self.failed_events_queue.get(), timeout=300  # 5 minutes
                    )
                    event_data = json.loads(zlib.decompress(compressed).decode("utf-8"))
                except asyncio.TimeoutError:
                    if self.failed_events_queue.empty():
                        # logger.info("No more failed events to retry")
                        del self._retry_task
                        return
                    continue

                # Update the event timestamp before retrying
                event_data["timestamp"] = datetime.utcnow().isoformat()
                event_data["mitigation_details"]["attempts"] += 1

                # Use the normal send method
                success = await self._send_to_siem(
                    event_data["ip_address"],
                    RuleMatchResult(**event_data["rule"]),
                    event_data["action"],
                )

                if success:
                    self.failed_events_queue.task_done()
                else:
                    # Put back in queue if still failing
                    await self.failed_events_queue.put(compressed)
                    await asyncio.sleep(60)  # Wait longer between retries

            except Exception as e:
                logger.error(f"Failed event retry handler error: {str(e)}")
                await asyncio.sleep(30)

    async def _isolate_from_internal(self, ip: str) -> bool:
        """Isolate IP from internal networks using multiple methods.

        Attempts various isolation techniques in order:
        1. VLAN/Port isolation via network controller API
        2. NAC (Network Access Control) quarantine
        3. Local firewall rules blocking internal traffic
        4. DNS sinkholing for internal domains

        Returns True if any isolation method succeeds.
        """
        # logger.info(f"Attempting to isolate internal IP: {ip}")
        isolation_methods = {
            "Network Controller": self._isolate_via_network_controller,
            "NAC": self._isolate_via_nac,
            "Local Firewall": self._isolate_via_local_firewall,
            "DNS Sinkhole": self._isolate_via_dns,
        }

        for method_name, method_func in isolation_methods.items():
            try:
                if await method_func(ip):
                    # logger.info(f"Successfully isolated IP {ip} using {method_name}.")
                    return True
                # Failure of a single method is logged within the method itself
            except Exception as e:
                logger.error(
                    f"Exception during isolation method {method_name} for IP {ip}: {e}",
                    exc_info=True,
                )

        logger.warning(f"Failed to isolate IP {ip} using all available methods.")
        return False

    async def _isolate_via_network_controller(self, ip: str) -> bool:
        """Isolate by moving device to quarantine VLAN using network controller API"""
        network_controller_api = self.config.get("network_controller_api")
        if not network_controller_api:
            logger.debug(
                "Network controller API not configured. Skipping isolation via network controller."
            )
            return False

        endpoints = {  # These are examples, actual endpoints will vary
            "cisco_ise": "/api/v1/network-device/isolation",  # Fictional
            "aruba_clearpass": "/api/quarantine",  # Fictional
            "fortinet_fortigate": "/api/v2/monitor/user/quarantine/",  # Fictional
        }
        controller_type = self.config.get(
            "network_controller_type", "cisco_ise"
        )  # Example default
        endpoint = endpoints.get(controller_type)

        if not endpoint:
            logger.warning(
                f"Unsupported network controller type for isolation: {controller_type}"
            )
            return False

        payload = {
            "ip_address": ip,
            "duration": "86400",  # 24 hours
            "reason": "IPS Automated Quarantine",
            "quarantine_profile": "strict_isolation",  # Example profile
        }
        headers = {
            "Authorization": f"Bearer {self.config.get('network_controller_key')}",
            "Content-Type": "application/json",
        }
        url = f"{network_controller_api}{endpoint}"

        try:
            # Using session's default timeout unless overridden here explicitly
            async with self.session.post(url, json=payload, headers=headers) as resp:
                response_text = await resp.text()
                if resp.status in (200, 201, 202):  # Accepted or OK
                    # logger.info(
                    #     f"Successfully isolated IP {ip} via network controller {controller_type} (URL: {url}). Status: {resp.status}"
                    # )
                    return True
                else:
                    logger.warning(
                        f"Failed to isolate IP {ip} via network controller {controller_type} (URL: {url}). Status: {resp.status}. Response: {response_text}"
                    )
                    return False
        except asyncio.TimeoutError:
            logger.error(
                f"Timeout isolating IP {ip} via network controller {controller_type} at {url}."
            )
            return False
        except aiohttp.ClientError as e:
            logger.error(
                f"Client error isolating IP {ip} via network controller {controller_type}: {e}"
            )
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error isolating IP {ip} via network controller: {e}",
                exc_info=True,
            )
            return False

    async def _isolate_via_nac(self, ip: str) -> bool:
        """Isolate using Network Access Control system"""
        nac_api_url = self.config.get("nac_api")
        if not nac_api_url:
            logger.debug("NAC API URL not configured. Skipping isolation via NAC.")
            return False

        nac_type = self.config.get(
            "nac_type", "default"
        )  # e.g. 'cisco_ise', 'aruba_clearpass'
        mac_address = await self._get_mac_from_ip(ip)
        if (
            not mac_address and nac_type != "default_ip_based"
        ):  # Some NACs might need MAC
            logger.warning(
                f"MAC address for IP {ip} not found, which might be required for NAC type {nac_type}."
            )

        payload = {
            "ip_address": ip,
            "mac_address": mac_address,
            "action": "quarantine",
            "duration": "24h",  # Standard duration
            "reason": "IPS Automated Isolation",
            "policy_name": self.config.get(
                "nac_quarantine_policy", "IPS_Default_Quarantine"
            ),
        }
        headers = {
            "Authorization": f"Bearer {self.config.get('nac_api_key')}",
            "Content-Type": "application/json",
        }

        try:
            # Using session's default timeout
            async with self.session.post(
                nac_api_url, json=payload, headers=headers
            ) as resp:
                response_text = await resp.text()
                if resp.status in (
                    200,
                    201,
                    202,
                    204,
                ):  # OK, Created, Accepted, No Content
                    # logger.info(
                    #     f"Successfully isolated/quarantined IP {ip} via NAC ({nac_api_url}). Status: {resp.status}"
                    # )
                    return True
                else:
                    logger.warning(
                        f"Failed to isolate IP {ip} via NAC ({nac_api_url}). Status: {resp.status}. Response: {response_text}"
                    )
                    return False
        except asyncio.TimeoutError:
            logger.error(f"Timeout isolating IP {ip} via NAC at {nac_api_url}.")
            return False
        except aiohttp.ClientError as e:
            logger.error(f"Client error isolating IP {ip} via NAC: {e}")
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error isolating IP {ip} via NAC: {e}", exc_info=True
            )
            return False

    async def _isolate_via_local_firewall(self, ip: str) -> bool:
        """Create local firewall rules to block internal communication for a given IP."""
        current_os = platform.system().lower()
        # logger.info(f"Attempting local firewall isolation for IP {ip} on {current_os}.")

        commands = []
        if current_os == "linux":
            # For machine acting as gateway/firewall (FORWARD chain)
            commands.extend(
                [
                    f"iptables -I FORWARD 1 -s {ip} -d 10.0.0.0/8 -j DROP",
                    f"iptables -I FORWARD 1 -d {ip} -s 10.0.0.0/8 -j DROP",
                    f"iptables -I FORWARD 1 -s {ip} -d 172.16.0.0/12 -j DROP",
                    f"iptables -I FORWARD 1 -d {ip} -s 172.16.0.0/12 -j DROP",
                    f"iptables -I FORWARD 1 -s {ip} -d 192.168.0.0/16 -j DROP",
                    f"iptables -I FORWARD 1 -d {ip} -s 192.168.0.0/16 -j DROP",
                ]
            )
            # For protecting the machine itself (INPUT/OUTPUT chains)
            commands.extend(
                [
                    f"iptables -I INPUT 1 -s {ip} -j DROP",
                    f"iptables -I OUTPUT 1 -d {ip} -j DROP",
                ]
            )
        elif current_os == "windows":
            # Rules for traffic passing through (less common for typical host IPS)
            commands.extend(
                [
                    f"netsh advfirewall firewall add rule name='IPS Internal Isolate In {ip}' dir=in action=block remoteip={ip} localip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 profile=any enable=yes",
                    f"netsh advfirewall firewall add rule name='IPS Internal Isolate Out {ip}' dir=out action=block localip={ip} remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 profile=any enable=yes",
                ]
            )
            # Rules for protecting the machine itself
            commands.extend(
                [
                    f"netsh advfirewall firewall add rule name='IPS Host Isolate In {ip}' dir=in action=block remoteip={ip} profile=any enable=yes",
                    f"netsh advfirewall firewall add rule name='IPS Host Isolate Out {ip}' dir=out action=block remoteip={ip} profile=any enable=yes",  # Corrected: remoteip={ip} for outgoing to the quarantined IP
                ]
            )
        else:
            logger.warning(
                f"Local firewall isolation not supported on OS: {current_os} for IP {ip}."
            )
            return False

        all_succeeded = True
        for cmd in commands:
            logger.debug(f"Executing firewall command for IP {ip}: {cmd}")
            if not await self._execute_command(cmd):
                all_succeeded = False
                logger.warning(f"Firewall command failed for IP {ip}: {cmd}")
                # Depending on policy, might stop or continue; current logic: try all, succeed if all pass

        if all_succeeded:
            pass
            # logger.info(
            #     f"Successfully applied all local firewall isolation rules for IP {ip}."
            # )
        else:
            logger.warning(
                f"One or more local firewall isolation rules failed for IP {ip}."
            )
        return all_succeeded

    async def _isolate_via_dns(self, ip: str) -> bool:
        """Isolate by redirecting internal DNS queries from this IP to a sinkhole, or blocking its DNS."""
        dns_controller_api = self.config.get("dns_controller_api")
        if not dns_controller_api:
            logger.debug("DNS Controller API not configured. Skipping DNS isolation.")
            return False

        dns_policy_name = f"IPS_Isolation_{ip.replace('.', '_')}"
        sinkhole_ip = self.config.get("dns_sinkhole_ip", "0.0.0.0")

        payload = {
            "policy_name": dns_policy_name,
            "client_ip_address": ip,
            "action": "redirect",
            "redirect_to_ip": sinkhole_ip,
            "domains": ["*"],
            "enabled": True,
            "reason": f"IPS Automated DNS Isolation for IP {ip}",
        }
        headers = {
            "Authorization": f"Bearer {self.config.get('dns_controller_key')}",
            "Content-Type": "application/json",
        }
        url = f"{dns_controller_api}/api/v1/client_policies"

        try:
            # Using session's default timeout
            async with self.session.post(url, json=payload, headers=headers) as resp:
                response_text = await resp.text()
                if resp.status in (200, 201, 202):
                    logger.info(
                        f"Successfully applied DNS isolation for IP {ip} via {url}. Policy: {dns_policy_name}. Status: {resp.status}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Failed to apply DNS isolation for IP {ip} via {url}. Status: {resp.status}. Response: {response_text}"
                    )
                    return False
        except asyncio.TimeoutError:
            logger.error(f"Timeout applying DNS isolation for IP {ip} at {url}.")
            return False
        except aiohttp.ClientError as e:
            logger.error(f"Client error applying DNS isolation for IP {ip}: {e}")
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error applying DNS isolation for IP {ip}: {e}",
                exc_info=True,
            )
            return False

    async def _get_mac_from_ip(self, ip: str) -> Optional[str]:
        """Attempt to resolve MAC address from IP (works on local network)."""
        try:
            if platform.system().lower() == "linux":
                proc = await asyncio.create_subprocess_exec(
                    "arp",
                    "-n",
                    ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode == 0:
                    output = stdout.decode().strip()
                    # Example output: "ip_address (ip_address) at mac_address [ether] on eth0"
                    # Or: "? (ip_address) at <incomplete> on eth0"
                    match_result = re.search(
                        r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output
                    )
                    if match_result:
                        mac = match_result.group(0).lower()
                        logger.debug(f"Resolved MAC for {ip} (Linux): {mac}")
                        return mac
                    else:
                        logger.debug(
                            f"Could not parse MAC from 'arp -n {ip}' output: {output}"
                        )
                else:
                    logger.debug(
                        f"'arp -n {ip}' failed with code {proc.returncode}. Error: {stderr.decode().strip()}"
                    )

            elif platform.system().lower() == "windows":
                proc = await asyncio.create_subprocess_exec(
                    "arp",
                    "-a",
                    ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode == 0:
                    output = stdout.decode()
                    # Example output for Windows:
                    # Interface: 192.168.1.100 --- 0xb
                    #   Internet Address      Physical Address      Type
                    #   192.168.1.1           00-11-22-33-44-55     dynamic
                    #   192.168.1.2           aa-bb-cc-dd-ee-ff     static
                    for line in output.splitlines():
                        # Use regex to find IP and MAC in a line
                        match_result = re.search(
                            r"^\s*("
                            + re.escape(ip)
                            + r")\s+(([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+",
                            line,
                            re.IGNORECASE,
                        )
                        if match_result:
                            mac = match_result.group(2).replace("-", ":").lower()
                            logger.debug(f"Resolved MAC for {ip} (Windows): {mac}")
                            return mac
                    logger.debug(f"MAC for {ip} not found in 'arp -a {ip}' output.")
                else:
                    logger.debug(
                        f"'arp -a {ip}' failed with code {proc.returncode}. Error: {stderr.decode().strip()}"
                    )

            # TODO: Add macOS support: `arp -n {ip}` and parse output similar to Linux
            # Example: "? (ip_address) at mac_address on en0 ifscope [ethernet]"

        except FileNotFoundError:
            logger.warning("'arp' command not found. Cannot resolve MAC address.")
        except Exception as e:
            logger.error(f"MAC resolution for {ip} failed: {e}", exc_info=True)

        return None

    # Methods from the previous diff that need to be implemented/kept:
    # _collect_forensic_data, _notify_incident_response
    # These are not present in the current file from read_files, so they need to be added.
    # I will add them as they were in my previous (failed) diff, as their logic is independent of these other changes.

    async def _collect_forensic_data(self, ip: str) -> bool:
        """
        Triggers forensic data collection for a given IP.
        Initial implementation logs and emits a socket.io event.
        """
        timestamp_iso = datetime.utcnow().isoformat()
        log_message = (
            f"Forensic data collection triggered for IP: {ip} at {timestamp_iso}."
        )
        logger.info(log_message)

        event_payload = {
            "ip_address": ip,
            "timestamp": timestamp_iso,
            "message": "Forensic data collection initiated for this IP.",
        }

        try:
            await self.sio.emit("ips_forensic_trigger", event_payload)
            logger.debug(f"Socket.IO event 'ips_forensic_trigger' emitted for IP: {ip}")
            return True
        except Exception as e:
            logger.error(
                f"Error emitting 'ips_forensic_trigger' for IP {ip}: {e}", exc_info=True
            )
            return False

    async def _notify_incident_response(self, ip: str, match: RuleMatchResult) -> bool:
        """
        Notifies the incident response team about an event.
        Initial implementation logs and emits a socket.io event.
        """
        timestamp_iso = datetime.utcnow().isoformat()
        log_message = (
            f"Incident response notification for IP: {ip} at {timestamp_iso} "
            f"due to Rule ID: {match.rule_id} ({match.description}). Severity: {match.severity}."
        )
        logger.info(log_message)

        event_payload = {
            "ip_address": ip,
            "timestamp": timestamp_iso,
            "rule_id": match.rule_id,
            "description": match.description,
            "severity": match.severity,
            "category": match.category,
            "metadata": match.metadata,
            "message": "Incident response team potentially notified of this event.",  # Message adjusted
        }

        try:
            await self.sio.emit("ips_incident_notification", event_payload)
            logger.debug(
                f"Socket.IO event 'ips_incident_notification' emitted for IP: {ip}, Rule: {match.rule_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Error emitting 'ips_incident_notification' for IP {ip}: {e}",
                exc_info=True,
            )
            return False

    async def _log_to_external_systems(
        self, ip: str, match: RuleMatchResult, action: str
    ) -> None:
        """Placeholder for logging to external systems like ELK, Splunk."""
        logger.info(
            f"Placeholder: Logging event to external system for IP {ip}, action {action}, rule {match.rule_id}"
        )
        # Example: self.external_logger.log({...details...})
        pass


class IPSWorker(multiprocessing.Process):
    def __init__(
        self,
        input_queue: multiprocessing.Queue,
        output_queue: multiprocessing.Queue,
        rule_file: str,
        worker_id: int,
        threat_intel: ThreatIntel,
    ):
        super().__init__()
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.rule_file = rule_file
        self.threat_intel = threat_intel
        self.worker_id = worker_id
        self.shutdown_flag = multiprocessing.Event()
        self.processed_count = 0
        self.rule_manager = RuleManager(rule_file, config={"match_ttl": 60})
        self.packet_processor = PacketProcessor(self.rule_manager, self.threat_intel)

    def run(self):
        """Main worker process loop"""
        logger.info(f"Worker {self.worker_id} started")

        # Set up signal handling
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        while not self.shutdown_flag.is_set():
            try:
                # Get packet from queue with timeout to allow shutdown checks
                packet = self.input_queue.get(timeout=1)
                if packet is None:  # Sentinel value for shutdown
                    break

                # Process packet
                matches = self.packet_processor.process_packet(packet)
                self.processed_count += 1

                # Send results to output queue
                if matches:
                    try:
                        self.output_queue.put(
                            (packet, matches), timeout=1.0
                        )  # Added timeout
                        logger.debug(  # Changed to debug to reduce noise for successful puts
                            f"[Worker-{self.worker_id}] Sent {len(matches)} matches to output_queue for packet from {packet[IP].src}"
                        )
                    except Full:
                        logger.warning(
                            f"[Worker-{self.worker_id}] Output queue full. Dropping {len(matches)} matches for packet from {packet[IP].src}."
                        )
                        # Potentially increment a counter for dropped output items

                # Periodically reload rules
                if self.processed_count % 1000 == 0:
                    self.rule_manager.load_rules()

            except multiprocessing.TimeoutError:
                continue
            except QueueEmpty:
                continue  # Silently skip — normal behavior
            except Exception as e:
                import traceback

                logger.error(f"Worker {self.worker_id} error: {e}")
                logger.error(traceback.format_exc())

        logger.info(f"Worker {self.worker_id} shutting down")

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal"""
        logger.info(f"Worker {self.worker_id} received shutdown signal")
        self.shutdown_flag.set()


class StatsCollector:
    def __init__(self):
        self.start_time = datetime.now()
        self.packet_counts = defaultdict(int)
        self.rule_matches = defaultdict(int)
        self.actions_taken = defaultdict(int)
        self.lock = multiprocessing.Lock()
        self.alert_timestamps = defaultdict(lambda: defaultdict(list))
        self.alert_decay_window = timedelta(minutes=10)
        self.alert_counter = defaultdict(
            lambda: defaultdict(int)
        )  # rule_id -> ip -> count
        self.alert_thresholds = {
            "default": 5,  # Default threshold to escalate
            "SCAN-001": 3,  # Custom thresholds per rule (optional)
            "CLD-901": 10,
        }

    def update_stats(self, packet: Packet, matches: List[RuleMatchResult]):
        """Update statistics with packet and match data"""
        protocol = "unknown"
        if TCP in packet:
            protocol = "tcp"
        elif UDP in packet:
            protocol = "udp"
        elif ICMP in packet:
            protocol = "icmp"

        with self.lock:
            self.packet_counts["total"] += 1
            self.packet_counts[protocol] += 1

            for match in matches:
                self.rule_matches[match.rule_id] += 1
                self.actions_taken[match.action] += 1
                if match.action == "alert":
                    ip = packet[IP].src
                    now = datetime.now()
                    self.alert_timestamps[match.rule_id][ip].append(now)
                    # Remove expired timestamps
                    self.alert_timestamps[match.rule_id][ip] = [
                        t
                        for t in self.alert_timestamps[match.rule_id][ip]
                        if now - t <= self.alert_decay_window
                    ]
                    self.alert_counter[match.rule_id][ip] = len(
                        self.alert_timestamps[match.rule_id][ip]
                    )
                    threshold = self.alert_thresholds.get(
                        match.rule_id, self.alert_thresholds["default"]
                    )

                if self.alert_counter[match.rule_id][ip] >= threshold:
                    # Escalate action
                    logger.warning(
                        f"Escalating rule {match.rule_id} for IP {ip} due to repeated alerts"
                    )
                    match.action = "block"
                    match.severity = "high"

    def get_stats(self) -> Dict:
        """Get current statistics"""
        uptime = datetime.now() - self.start_time
        with self.lock:
            return {
                "uptime": str(uptime),
                "total_packets": self.packet_counts.get("total", 0),
                "packets_by_protocol": dict(self.packet_counts),
                "top_rules": dict(
                    sorted(self.rule_matches.items(), key=lambda x: x[1], reverse=True)[
                        :10
                    ]
                ),
                "actions": dict(self.actions_taken),
                "timestamp": datetime.now().isoformat(),
            }


class MemoryMonitor:
    def __init__(self, max_memory: float = 0.9):
        self.max_memory = max_memory  # 90% of available memory
        self.warning_sent = False

    def check_memory(self) -> bool:
        """Check if memory usage exceeds threshold"""
        mem = psutil.virtual_memory()
        if mem.percent / 100 > self.max_memory:
            if not self.warning_sent:
                logger.warning(f"High memory usage: {mem.percent}%")
                self.warning_sent = True
            return True
        self.warning_sent = False
        return False


class EnterpriseIPS:

    def __init__(
        self,
        rule_file: str,
        sio: socketio.AsyncServer,
        threat_intel: ThreatIntel = None,
        num_workers: int = multiprocessing.cpu_count(),
        input_queue: Queue = None,
        output_queue: Queue = None,
    ):
        self.rule_file = rule_file
        self.sio = sio
        self.num_workers = num_workers
        self.input_queue = input_queue
        self.threat_intel = threat_intel
        self.input_queue.maxsize = MAX_PACKET_QUEUE_SIZE
        self.output_queue = output_queue
        self.workers = []
        self.stats_collector = StatsCollector()
        self.memory_monitor = MemoryMonitor()
        self.mitigation_engine = MitigationEngine(
            sio=sio,
            threat_intel=self.threat_intel,  # Pass ThreatIntel instance
            config={
                "firewall_api": "http://127.0.0.1:8000/firewall",
                "firewall_api_key": "any-key",
                "threat_intel_api": "http://127.0.0.1:8000/intel/update",
                "nac_api": "http://local127.0.0.1/nac/quarantine",
                "dns_controller_api": "http://127.0.0.1:8000/dns",
                "dns_controller_key": "test-key",
                "dashboard_config": {  # Pass dashboard config to MitigationEngine
                    "base_url": "http://localhost:8081",  # Example: Your SIEM/Dashboard URL
                    "api_key": "your_dashboard_api_key",
                    "max_retries": 3,
                    "retry_delay": 5,  # seconds
                    "timeout": 10,  # seconds for request timeout
                },
            },
        )
        self.shutdown_flag = asyncio.Event()
        self.background_tasks = set()

    async def start(self):
        """Start the IPS system"""
        logger.info("Starting Enterprise IPS")

        # Start worker processes
        for i in range(self.num_workers):
            worker = IPSWorker(
                input_queue=self.input_queue,
                output_queue=self.output_queue,
                rule_file=self.rule_file,
                worker_id=i,
                threat_intel=self.threat_intel,
            )
            worker.start()
            self.workers.append(worker)

        # Start background tasks
        self._start_background_task(self._process_results())
        self._start_background_task(self._report_stats())
        self._start_background_task(self._monitor_memory())
        self._start_background_task(self._worker_heartbeat())

    async def stop(self):
        """Stop the IPS system gracefully"""
        logger.info("Stopping Enterprise IPS")
        self.shutdown_flag.set()

        # Send shutdown signal to workers
        for _ in range(self.num_workers):
            self.input_queue.put(None)

        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker.terminate()

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        logger.info("Enterprise IPS stopped")

    async def ingest_packet(self, packet: Packet):
        """Ingest a packet for processing"""
        if self.memory_monitor.check_memory():
            logger.warning("Memory threshold exceeded, dropping packet")
            return

        try:
            self.input_queue.put_nowait(packet)
        except Full:
            logger.warning("Input queue full, dropping packet")
            # In a real implementation, you might want to handle this differently

    def _start_background_task(self, coro):
        """Start a background task and keep reference to it"""
        task = asyncio.create_task(coro)
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

    async def _process_results(self):
        """Process results from worker output queue"""
        while not self.shutdown_flag.is_set():
            try:
                # Get result with timeout to allow shutdown checks
                result = self.output_queue.get_nowait()
                if result is None:
                    continue

                logger.info("[EnterpriseIPS] ✅ Received result from output_queue")

                packet, matches = result
                self.stats_collector.update_stats(packet, matches)

                # Create packet context for mitigation
                processor = PacketProcessor(
                    RuleManager(self.rule_file, config={"match_ttl": 60}), ThreatIntel()
                )

                context = processor.create_packet_context(packet)

                # Execute mitigation for each match
                for match in matches:
                    await self.mitigation_engine.mitigate(match, context)

            except QueueEmpty:
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Error processing results: {e}")
                await asyncio.sleep(1)

    async def _report_stats(self):
        """Periodically report system statistics"""
        while not self.shutdown_flag.is_set():
            try:
                stats = self.stats_collector.get_stats()
                await self.sio.emit("ips_stats", stats)
                # logger.debug(f"System stats: {stats}")
                await asyncio.sleep(STATS_REPORT_INTERVAL)
            except Exception as e:
                logger.error(f"Error reporting stats: {e}")
                await asyncio.sleep(1)

    async def _monitor_memory(self):
        """Monitor system memory usage"""
        while not self.shutdown_flag.is_set():
            self.memory_monitor.check_memory()
            await asyncio.sleep(MEMORY_MONITOR_INTERVAL)

    async def _worker_heartbeat(self):
        """Monitor worker health"""
        while not self.shutdown_flag.is_set():
            dead_workers = [w for w in self.workers if not w.is_alive()]
            for worker in dead_workers:
                logger.error(f"Worker {worker.worker_id} died, restarting")
                self.workers.remove(worker)
                new_worker = IPSWorker(
                    input_queue=self.input_queue,
                    output_queue=self.output_queue,
                    rule_file=self.rule_file,
                    worker_id=worker.worker_id,
                    threat_intel=self.threat_intel,
                )
                new_worker.start()
                self.workers.append(new_worker)
            await asyncio.sleep(HEARTBEAT_INTERVAL)
