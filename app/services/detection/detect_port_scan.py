# Enhanced Port Scan Detection
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
from typing import Dict, Deque, Set, Optional, List
from scapy.all import Packet, IP, TCP, UDP
from dataclasses import dataclass, field

logger = logging.getLogger("portscan")


@dataclass
class ScanTracker:
    """Tracks scanning activity per source IP"""

    syn_count: int = 0
    syn_times: Deque[datetime] = field(default_factory=deque)
    unique_ports: Set[int] = field(default_factory=set)
    last_alert: Optional[datetime] = None


class PortScanDetector:
    def __init__(self):
        self.config = {
            "syn_scan_threshold": 15,
            "port_sweep_threshold": 10,
            "time_window_seconds": 60,
            "alert_cooldown": 300,
            "whitelisted_ips": {
                # Default gateways
                "192.168.1.1",
                "10.0.0.1",
                "172.16.0.1",
                # Network appliances
                "192.168.1.254",
                "10.0.0.254",
                "192.168.100.1",  #
                # Monitoring systems
                "10.0.5.10",
                "10.0.5.11",
                "192.168.2.100",
                # Cloud/metro ranges
                "169.254.0.0/16",
                "100.64.0.0/10",
            },
        }

        self.trackers: Dict[str, ScanTracker] = defaultdict(ScanTracker)
        self.port_counter = defaultdict(set)  # Tracks {port: set(scanning_ips)}
        self.rate_limiter: Dict[str, datetime] = {}

    def _cleanup_old_entries(self):
        """Periodically clean up old tracking data"""
        now = datetime.now()
        stale_ips = [
            ip
            for ip, tracker in self.trackers.items()
            if tracker.syn_times
            and (now - tracker.syn_times[-1]).total_seconds()
            > self.config["time_window_seconds"] * 2
        ]
        for ip in stale_ips:
            del self.trackers[ip]

    def _detect_scan_patterns(self, src_ip: str, tracker: ScanTracker) -> bool:
        """Enhanced detection with temporal analysis"""
        now = datetime.now()

        # Windowed SYN analysis
        while (
            tracker.syn_times
            and (now - tracker.syn_times[0]).total_seconds()
            > self.config["time_window_seconds"]
        ):
            tracker.syn_times.popleft()
            tracker.syn_count = max(0, tracker.syn_count - 1)

        # Dynamic thresholds based on port uniqueness
        unique_ports = len(tracker.unique_ports)
        syn_count = tracker.syn_count

        # Detection conditions
        if (
            syn_count >= self.config["syn_scan_threshold"]
            or unique_ports >= self.config["port_sweep_threshold"]
        ):
            return True

        # Additional check for mixed scanning patterns
        if (
            syn_count > self.config["syn_scan_threshold"] * 0.7
            and unique_ports > self.config["port_sweep_threshold"] * 0.6
        ):
            return True

        return False

    def _is_rate_limited(self, src_ip: str) -> bool:
        """Improved rate limiting with cooldown enforcement"""
        now = datetime.now()
        last_alert = self.trackers[src_ip].last_alert

        if (
            last_alert
            and (now - last_alert).total_seconds() < self.config["alert_cooldown"]
        ):
            return True
        self.trackers[src_ip].last_alert = now
        return False

    def detect(self, packet: Packet) -> Optional[Dict]:
        """Enhanced detection with port set tracking"""
        try:
            if IP not in packet:
                return None

            src_ip = packet[IP].src
            if src_ip in self.config["whitelisted_ips"]:
                return None

            tracker = self.trackers[src_ip]
            now = datetime.now()

            # TCP SYN scan detection
            if TCP in packet:
                tcp = packet[TCP]
                if tcp.flags == 0x02:  # SYN flag
                    tracker.syn_count += 1
                    tracker.syn_times.append(now)

                    if hasattr(tcp, "dport"):
                        port = int(tcp.dport)
                        tracker.unique_ports.add(port)
                        self.port_counter[port].add(src_ip)

            # UDP port sweep detection
            elif UDP in packet:
                udp = packet[UDP]
                if hasattr(udp, "dport"):
                    port = int(udp.dport)
                    tracker.unique_ports.add(port)
                    self.port_counter[port].add(src_ip)

            # Periodic cleanup
            if len(self.trackers) % 100 == 0:
                self._cleanup_old_entries()

            if self._detect_scan_patterns(src_ip, tracker):
                if self._is_rate_limited(src_ip):
                    return None

                alert_data = {
                    "alert_type": self._determine_scan_type(tracker),
                    "severity": "High",
                    "source_ip": src_ip,
                    "destination_ip": packet[IP].dst if IP in packet else None,
                    "ports_scanned": len(tracker.unique_ports),
                    "syn_count": tracker.syn_count,
                    "start_time": (
                        tracker.syn_times[0].isoformat() if tracker.syn_times else None
                    ),
                    "last_seen": now.isoformat(),
                    "packet_summary": packet.summary(),
                    "confidence": self._calculate_confidence(tracker),
                    "top_targeted_ports": self._get_top_ports(5),
                }
                return alert_data

        except Exception as e:
            logger.error(f"Scan detection error: {str(e)}", exc_info=True)
            # PROD_CLEANUP: logger.debug(f"Packet causing error: {packet.summary()}")

        return None

    def _determine_scan_type(self, tracker: ScanTracker) -> str:
        """Improved scan type classification"""
        syn_ratio = tracker.syn_count / self.config["syn_scan_threshold"]
        port_ratio = len(tracker.unique_ports) / self.config["port_sweep_threshold"]

        if syn_ratio >= 1.0 and port_ratio >= 0.8:
            return "Advanced Combination Scan"
        elif syn_ratio >= 1.0:
            return "SYN Scan"
        elif port_ratio >= 1.0:
            return "Port Sweep"
        return "Suspicious Scanning Activity"

    def _calculate_confidence(self, tracker: ScanTracker) -> float:
        """Enhanced confidence scoring"""
        time_window = self.config["time_window_seconds"]
        syn_rate = tracker.syn_count / time_window
        port_diversity = len(tracker.unique_ports) / 1000  # Normalize to 0-1

        # Weighted confidence score
        return min(1.0, 0.6 * syn_rate + 0.4 * port_diversity)

    def _get_top_ports(self, n: int) -> List[Dict[int, int]]:
        """Get top targeted ports with scanning IP count"""
        return sorted(
            [
                {"port": port, "count": len(ips)}
                for port, ips in self.port_counter.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:n]

    def reset_port_counter(self):
        """Reset port tracking"""
        self.port_counter.clear()

    def reset_tracker(self, src_ip: str):
        """Clear tracking for specific IP"""
        if src_ip in self.trackers:
            del self.trackers[src_ip]
        if src_ip in self.rate_limiter:
            del self.rate_limiter[src_ip]
