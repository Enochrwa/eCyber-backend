import re
import math
import json
import uuid # Added import

import gzip, joblib, json
import time
import logging
import platform
from operator import itemgetter
import asyncio 
import traceback
from functools import lru_cache
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Callable, Dict, Optional, List, Tuple,Any
from multiprocessing import Process,Manager, Value,Queue, Event, Lock as ProcessLock
from pathlib import Path
import pickle 
import socket
import multiprocessing as mp
from multiprocessing.managers import DictProxy
from queue import Full, Empty
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms

import numpy as np
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
    AsyncSniffer,
    wrpcap
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet
import scapy.layers.http as HTTP
from scapy.layers.inet6 import IPv6ExtHdrFragment
import ipaddress
from sqlalchemy.inspection import inspect
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from .feature_processor import AdvancedFeatureExtractor, ThreatDetector, EnhancedPacketProcessor
from ...models.network import NetworkEvent
from ...models.threat import ThreatLog
from ...database import get_db
from ...models.packet import Packets
from ...core.security import get_current_user
from ..detection.rate_limiter import RateLimiter
from ..prevention.firewall import FirewallManager
# from ...database import get_sync_db
from ..detection.signature import SignatureEngine
from ..detection.detect_port_scan import PortScanDetector
# from ..detection.phishing_blocker import PhishingBlocker
from .reporter_helper import _reporter_loop, default_asn, default_geo
from ml.feature_extraction import analyze_and_flatten,map_to_cicids2017_features
from ...utils.format_http_data import transform_http_activity
from ...utils.save_to_json import save_http_data_to_json, save_packet_data_to_json, save_features_to_json, save_feature_vectors_to_json
# from ..ips.engine import IPSEngine

# Configure logging
logger = logging.getLogger("packet_sniffer")
logger.setLevel(logging.INFO)

from .utils.constants import BASE64_CHARS, cipher_name,SCORING_WEIGHTS,WEAK_CIPHERS,RECOMMENDED_CIPHERS,KNOWN_SERVICES  


def default_recent_packet():
    return {
        "packets": deque(maxlen=100),
        "syn_times": deque(maxlen=1000),
        "rst_count": 0,
        "auth_failures": 0,
        "network_flows": deque(maxlen=1000),
    }


class PacketSniffer:
    def __init__(self, sio_queue: Queue):
        """
        Initializes the PacketSniffer.

        Args:
            sio_queue (Queue): A multiprocessing queue for sending events to a Socket.IO server.
            phishing_blocker (Optional[PhishingBlocker]): An instance of PhishingBlocker
                                                          for analyzing HTTP traffic for phishing attempts.
                                                          If None, phishing analysis will be skipped.
        """
        self.sio_queue = sio_queue
        # self.phishing_blocker = phishing_blocker # Store the PhishingBlocker instance
        self._http_listeners: list[Callable[[Dict], bool]] = []
        self.manager = Manager()
        self.packet_counter = mp.Value("i", 0)
        self._setup_logging()
        self.stop_event = mp.Event()
        # self.recorder = PacketRecorder()
        self._running = False
        self.firewall_lock = mp.Lock()
        self.start_time = time.time()
        self.end_time = time.time()
        self._state_checked = False
        self._stop_event = Event()
        self.sniffer_process: Optional[Process] = None
        self.stop_sniffing_event = mp.Event()
        self.total_bytes = 0
        

        ##Machine learning part
        # Load all ML artifacts once at startup:
        self.models = {}   # attack → (scaler, model, threshold)
        bundle_dir = Path(__file__).parent / "ml" / "cicids_models_bundle"
        for meta_path in bundle_dir.glob("*_meta.json"):
            attack = meta_path.stem.replace("_meta","").replace("_"," ")
            mdir = meta_path.parent
            meta = json.loads(meta_path.read_text())
            algo = meta["algorithm"]
            thresh = meta["threshold"]
            # Paths:
            scaler_p = mdir / f"{meta_path.stem.replace('_meta','')}_scaler.pkl.gz"
            model_p  = mdir / f"{meta_path.stem.replace('_meta','')}_{algo}_model.pkl.gz"
            # Load:
            with gzip.open(scaler_p,"rb") as f: scaler = joblib.load(f)
            with gzip.open(model_p ,"rb") as f: model  = joblib.load(f)
            self.models[attack] = (scaler, model, thresh)
        
        

        self.feature_extractor = AdvancedFeatureExtractor(
            cleanup_interval=300, flow_timeout=120
        )
        self.packet_processor = EnhancedPacketProcessor()
        self.threat_detector = ThreatDetector(self.feature_extractor, self.sio_queue)
        # If you’ll do ML inference:
        # self.enhanced_processor = EnhancedPacketProcessor()
        # self.enhanced_processor.load_model("path/to/your/model.pkl")

        # Initialize queues and locks
        self.event_queue = Queue(maxsize=10000)
        self.data_lock = mp.Lock()
        # self.processing_lock has been removed as per optimization task
        self.worker_process = Process(target=self._process_queue, args=(), daemon=True)

        self.sniffer_process: Optional[Process] = None
        self._queue_monitor_active = False
        self._queue_stats = {"processed": 0, "dropped": 0, "errors": 0}

        self.last_request_time = {}

        self._async_sniffer: AsyncSniffer | None = None

        # Initialize shared data structures
        self.byte_distribution = [0] * 256  # For payload byte analysis
        self.service_map = defaultdict(int)
        self.rate_limiter = RateLimiter(
            max_requests=500, time_window=timedelta(seconds=60)
        )

        self.signature_engine = SignatureEngine(sio_queue)
        self.firewall = FirewallManager(sio_queue)

        # Initialize statistics
        self.stats = self.manager.dict(
            {
                "start_time": datetime.utcnow(),  # datetime is immutable, so it's okay as-is
                "total_packets": 0,  # primitives like int are fine
                "protocols": defaultdict(
                    int
                ),  # use manager.dict in place of defaultdict
                "flows": self.manager.dict(),
                "top_talkers": self.manager.dict(),
                "alerts": self.manager.list(),  # no maxlen, you'll need to manage length manually
                "throughput": self.manager.dict(
                    {
                        "1min": deque(maxlen=60),  # again, no maxlen—handle it in logic
                        "5min": deque(maxlen=360),
                    }
                ),
                "geo_data": self.manager.dict(),
                "threat_types": self.manager.dict(),
            }
        )
        self._last_seen_times = defaultdict(float)
        self._dns_counter = self.manager.dict()
        self._endpoint_tracker = defaultdict(lambda: defaultdict(set))
        self._protocol_counter = self.manager.dict()

        self.recent_packets = defaultdict(default_recent_packet)
        self.current_packet_source = None
        self.port_scan_detector = PortScanDetector()

        self._init_ip_databases()

        # RFC compliance patterns
        self.rfc7230_methods = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'}
        self.http_version_pattern = re.compile(r'HTTP/\d\.\d$')
        self.pseudo_headers = {':method', ':path', ':authority', ':scheme', ':status'}
        self.h2c_cleartext_ports = {80, 8080}  # HTTP/2 over TCP ports

        # Network path analysis cache
        self.network_path_cache = defaultdict(deque)

        # Start worker processes

        self._reporter_stop = Event()
        self.reporter_process = Process(
            target=_reporter_loop,
            args=(self.sio_queue, self.stats, self._reporter_stop,5.0),
            daemon=True,
        )

        # self.worker_process.start()
        # self.reporter_process.start()

    def _run_sniffer_process(self, interface: str, sio_queue: Queue):
        """Runs the AsyncSniffer in a separate process."""
        logger.info("Sniffer process started on interface %s", interface)
        self.sio_queue = sio_queue  # Crucial for the new process

        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=interface,
                filter="not (dst net 127.0.0.1 or multicast)",
                prn=self._packet_handler,
                store=False,
                promisc=True
            )
            sniffer.start()
            # logger.info("AsyncSniffer started sniffing in dedicated process on %s", interface)
            self.stop_sniffing_event.wait()  # Wait until stop event is set
        except Exception as e:
            logger.error(f"Error in sniffer process on interface {interface}: {e}", exc_info=True)
        finally:
            if sniffer and hasattr(sniffer, 'stop') and callable(sniffer.stop):
                try:
                    sniffer.stop()
                    logger.info("AsyncSniffer stopped in dedicated process on %s", interface)
                except Exception as e: # pylint: disable=broad-except
                    logger.error(f"Error stopping AsyncSniffer in dedicated process: {e}", exc_info=True)
            # logger.info("Sniffer process on interface %s stopped.", interface)

    def __getstate__(self):
        # 1) Copy everything
        state = self.__dict__.copy()

        # 2) Strip known un-picklables by name
        for bad in (
            "manager",
            "worker_process",
            "sniffer_process",
            "reporter_process",
            "signature_engine",
            "firewall",
            "ids_signature_engine",
            "ips_engine",
            "blocker",
            "monitor",
            "_dns_counter",
            "_endpoint_tracker",
            "recent_packets",
        ):
            state.pop(bad, None)

        # 3) Strip any leftover Process objects by type
        for k, v in list(state.items()):
            if isinstance(v, mp.process.BaseProcess):
                state.pop(k)

        # 4) If already scanned, short‑circuit
        if self._state_checked:
            return state

        # 5) One‑time pickle test for anything else
        for k, v in list(state.items()):
            try:
                pickle.dumps(v)
            except Exception as e:
                print(f"❌ Cannot pickle attribute: {k} ({type(v)}) – {e}")
                state.pop(k)

        # 6) Mark done so we don’t repeat
        self._state_checked = True
        return state
    
    def __setstate__(self, state):
        # 1) Restore attributes
        self.__dict__.update(state)
        
        # 2) Reinitialize non-pickleable attributes
        from collections import defaultdict
        self.recent_packets = defaultdict(default_recent_packet)
        self._endpoint_tracker = defaultdict(lambda: defaultdict(set))
        self._dns_counter = {}
        self._protocol_counter = {}
        self.stop_sniffing_event = mp.Event()


    def _init_ip_databases(self):
        """Initialize local IP information databases"""
        self.asn_db = defaultdict(default_asn)
        self.geo_db = defaultdict(default_geo)

        # Load local IP data (example - extend with actual data)
        self._load_sample_data()
        
    def _count_packet(self,packet):
        # Increment total bytes and packet count
        self.total_bytes += len(packet)
        # Optional: Emit the current stats to the frontend
        self.sio_queue.put(("packet_bytes", self.total_bytes))

        
        
    def _load_sample_data(self):
        """Load sample IP data (replace with real data import)"""
        self.asn_db['8.8.8.8'] = {'asn': 15169, 'org': 'Google LLC'}
        self.geo_db['8.8.8.8'] = {'country': 'United States', 'city': 'Mountain View'}

    def get_queue_stats(self):
        """Return current queue statistics"""
        return {
            **self._queue_stats,
            "qsize": self.sio_queue.qsize(),
            "active": self._queue_monitor_active}

    def _update_traffic_baseline(self, http_data: Dict) -> None:
        """Update traffic baselines with rolling window statistics"""
        try:
            with self.data_lock:
                # Initialize if not exists
                if '1min' not in self.stats['throughput']:
                    self.stats['throughput']['1min'] = deque(maxlen=300)

                entry = {
                    'timestamp': time.time(),
                    'bytes': http_data['network_metrics']['packet_size'],
                    'packets': 1,
                    'source_ip': http_data['source_ip'],
                    'destination_ip': http_data['destination_ip']
                }

                self.stats['throughput']['1min'].append(entry)
                self._update_derived_metrics(entry)

        except Exception as e:
            logger.error(f"Traffic baseline update failed: {str(e)}", exc_info=True)
            try:
                self.sio_queue.put_nowait(('system_error', {
                    'error': 'traffic_baseline_failure',
                    'message': str(e)
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: system_error (traffic_baseline_failure)")
    def _update_derived_metrics(self, entry: Dict) -> None:
        """Update derived network metrics in a thread-safe manner"""
        with self.data_lock:
            # Update top talkers
            self.stats['top_talkers'][entry['source_ip']] += entry['packets']
            self.stats['top_talkers'][entry['destination_ip']] += entry['packets']

            # Update protocol distribution
            protocol = entry.get('protocol', 'unknown')
            self.stats['protocols'][protocol] += 1

    def _check_rfc_compliance(self, http_layer) -> Dict:
        """Verify HTTP protocol compliance with RFC standards"""
        compliance = {
            'rfc7230': {'valid': True, 'violations': []},
            'rfc7540': {'valid': False, 'violations': []}
        }

        try:
            # RFC 7230 (HTTP/1.1) checks
            if hasattr(http_layer, 'Method'):
                method = http_layer.Method.decode('ascii', errors='replace').strip()
                if method not in self.rfc7230_methods:
                    compliance['rfc7230']['violations'].append(f'Invalid method {method}')

            if hasattr(http_layer, 'Http_Version'):
                version = http_layer.Http_Version.decode('ascii', errors='replace').strip()
                if not self.http_version_pattern.match(version):
                    compliance['rfc7230']['violations'].append(f'Invalid version {version}')

            # RFC 7540 (HTTP/2) checks
            if hasattr(http_layer, 'Headers'):
                headers = http_layer.headers
                h2_indicators = sum(1 for h in headers if h.startswith(':'))
                if h2_indicators > 0:
                    compliance['rfc7540']['valid'] = True
                    for header in headers:
                        if header.startswith(':') and header not in self.pseudo_headers:
                            compliance['rfc7540']['violations'].append(f'Invalid pseudo-header {header}')

            # Check for HTTP/2 over TCP (h2c) compliance
            if compliance['rfc7540']['valid']:
                port = http_layer.get('Destination-Port', 80)
                if port not in self.h2c_cleartext_ports:
                    compliance['rfc7540']['violations'].append('Invalid port for h2c')

            # Update validity status
            compliance['rfc7230']['valid'] = len(compliance['rfc7230']['violations']) == 0
            compliance['rfc7540']['valid'] = len(compliance['rfc7540']['violations']) == 0

        except Exception as e:
            logger.warning(f"RFC compliance check failed: {str(e)}")
            try:
                self.sio_queue.put_nowait(('detection_error', {
                    'error': 'rfc_check_failure',
                    'message': str(e)
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: detection_error (rfc_check_failure)")

        return compliance

    def _analyze_network_path(self, source_ip: str) -> Dict:
        """Perform network path analysis using local data"""
        result = {
            'hops': [],
            'geo_path': [],
            'asn': self.asn_db[source_ip]['asn'],
            'org': self.asn_db[source_ip]['org'],
            'country': self.geo_db[source_ip]['country'],
            'city': self.geo_db[source_ip]['city']
        }

        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(source_ip)[0]
            result['hostname'] = hostname
        except (socket.herror, socket.gaierror):
            result['hostname'] = 'unknown'

        # Add cached traceroute information
        result['hops'] = list(self.network_path_cache.get(source_ip, deque(maxlen=10)))

        return result

    def _get_asn_info(self, ip_address: str) -> Dict:
        """Retrieve ASN information from local database"""
        return self.asn_db[ip_address]

    def _store_network_path(self, source_ip: str, hops: list):
        """Store network path information in cache"""
        self.network_path_cache[source_ip].extend(hops)
        if len(self.network_path_cache[source_ip]) > 10:
            self.network_path_cache[source_ip].popleft()

    def _setup_logging(self):
        """Configure packet-level logging"""
        self.packet_logger = logging.getLogger("packet_traffic")
        self.packet_logger.setLevel(logging.INFO)

    def _periodic_reporter(self):
        """Periodically report system stats with interrupt handling"""
        while not self.stop_event.is_set():
            try:
                time.sleep(60)
                stats = self._report_system_stats()
                try:
                    self.sio_queue.put_nowait(("system_stats", stats))
                except Full:
                    logger.warning("sio_queue is full. Dropping event: system_stats")
            except KeyboardInterrupt:
                logger.debug("Reporter received KeyboardInterrupt")
                break
            except Exception as e:
                logger.error("Reporter error: %s", str(e))

    def _report_system_stats(self):
        """Send periodic system statistics"""
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "packets_per_minute": sum(self.stats["throughput"]["1min"]),
            "top_talkers" : dict(
                sorted(
                    self.stats["top_talkers"].items(),
                    key=itemgetter(1),
                    reverse=True
                )[:10]
            ),
            "threat_distribution": dict(self.stats["threat_types"]),
            "queue_stats": self.get_queue_stats(),
            "memory_usage": self._get_memory_usage(),
            "cpu_usage": self._get_cpu_usage(),
        }
        try:
            self.sio_queue.put_nowait(("system_stats", stats))
        except Full:
            logger.warning("sio_queue is full. Dropping event: system_stats (periodic)")
        return stats

    def _get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        try:
            import psutil

            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            import psutil

            return psutil.cpu_percent()
        except ImportError:
            return 0.0

    def _queue_event(self, event_type: str, data: dict):
        if not self._running:
            return

        event = ("packet_sniffer", event_type, data)
        try:
            self.sio_queue.put_nowait(event)
        except Full:
            logger.warning("Dropped event due to full queue: %s", event_type)
            with self.data_lock:
                self._queue_stats["dropped"] += 1

    def _process_queue(self):
        """Process events from the queue in a dedicated process"""
        while not self.stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1)

                if callable(event):
                    event()
                elif isinstance(event, tuple) and len(event) == 2:
                    try:
                        self.sio_queue.put_nowait(event)
                    except Full:
                        logger.warning("sio_queue is full. Dropping event: %s", event[0] if event else "unknown_event_from_queue")
                else:
                    logger.error("Malformed event: %s", str(event))

            except Empty:
                continue
            except KeyboardInterrupt:
                logger.debug("Queue processor received KeyboardInterrupt")
                break  # Exit loop on interrupt
            except Exception as e:
                logger.error("Queue processing error: %s", str(e))
                continue

    def _get_flow_key(self, packet: Packet) -> tuple:
        """Create bidirectional flow key"""
        src_ip = dst_ip = proto = sport = dport = None
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto = packet[IPv6].nh

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        return tuple(sorted([src_ip, dst_ip]) + [proto, sport, dport])

    def _get_protocol_name(self, packet: Packet) -> str:
        """Safe and accurate protocol detection based on layers and ports"""
        try:
            TCP_PROTOCOLS = {
                80: "HTTP",
                8080: "HTTP",
                8008: "HTTP",
                8000: "HTTP",
                8888: "HTTP",
                443: "HTTPS",
                8443: "HTTPS",
                22: "SSH",
                21: "FTP",
                25: "SMTP",
                587: "SMTP",
                465: "SMTPS",
                23: "Telnet",
                53: "DNS-TCP",
            }

            UDP_PROTOCOLS = {
                53: "DNS",
                67: "DHCP",
                68: "DHCP",
                123: "NTP",
                161: "SNMP",
                162: "SNMPTRAP",
                500: "ISAKMP",
            }

            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                return "HTTP"

            if packet.haslayer(DNS):
                return "DNS"

            if packet.haslayer(ICMP):
                return "ICMP"

            if packet.haslayer(ARP):
                return "ARP"

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                # Avoid guessing HTTP just from ports
                return "TCP"

            if packet.haslayer(UDP):
                return "UDP"

            return "Other"

        except Exception as e:
            logger.debug(f"Protocol detection error: {str(e)}")
            return "Unknown"

    def _analyze_tcp_metadata(self, packet: Packet) -> dict:
        """Enhanced TCP metadata analysis"""
        if not packet.haslayer(TCP):
            return {}

        tcp = packet[TCP]
        return {
            "flags": {
                "syn": tcp.flags.S,
                "ack": tcp.flags.A,
                "fin": tcp.flags.F,
                "rst": tcp.flags.R,
                "psh": tcp.flags.P,
                "urg": tcp.flags.U,
                "ece": tcp.flags.E,
                "cwr": tcp.flags.C,
            },
            "window_size": tcp.window,
            "options": str(tcp.options),
            "seq_analysis": {
                "relative_seq": tcp.seq,
                "ack_diff": tcp.ack - tcp.seq,
                "window_ratio": tcp.window / (len(packet) if len(packet) > 0 else 1),
            },
        }
    def _packet_handler(self, packet: Packet):
        """Main packet processing method with enhanced analysis"""
        
        self.start_time = time.perf_counter()
        features = {}

        with self.packet_counter.get_lock():
            self.packet_counter.value += 1
            self._count_packet(packet)

        try:
            # self.processing_lock has been removed.
            # Extract IP-level metadata first
            src_ip = dst_ip = None
            ip_version = None
            is_arp = False
            try:
                if packet.haslayer(ARP):
                    self._analyze_arp(packet)
                    arp = packet[ARP]
                    src_ip = arp.psrc
                    dst_ip = arp.pdst
                    is_arp = True
                    # logger.info(f"ARP Packet: {arp.op} {src_ip} -> {dst_ip}")
                elif packet.haslayer(IP):
                    ip_version = 4
                    src_ip = str(packet[IP].src)
                    dst_ip = str(packet[IP].dst)
                    logger.debug(f"IPv4 Packet: {src_ip} -> {dst_ip}")
                elif packet.haslayer(IPv6):
                    ip_version = 6
                    src_ip = str(packet[IPv6].src)
                    dst_ip = str(packet[IPv6].dst)
                    logger.debug(f"IPv6 Packet: {src_ip} -> {dst_ip}")
            except Exception as e:
                logger.debug("Layer 2/3 extraction error: %s", str(e))
                return

            # Create base packet info
            packet_info = self._create_packet_info(packet, src_ip, dst_ip, ip_version, is_arp)
            if not self._validate_packet(packet_info):
                return

            # Transport Layer Analysis
            try:
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    
                    packet_info.update({
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "flags": str(tcp.flags)
                    })
                    self.service_map[tcp.dport] += 1
                    logger.debug("TCP Packet: %s -> %s flags=%s",
                                f"{src_ip}:{tcp.sport}", f"{dst_ip}:{tcp.dport}", tcp.flags)
                    self._analyze_tcp(packet)
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info.update({
                        "src_port": udp.sport,
                        "dst_port": udp.dport
                    })
                    self.service_map[udp.dport] += 1
                    logger.debug("UDP Packet: %s -> %s length=%d",
                                f"{src_ip}:{udp.sport}", f"{dst_ip}:{udp.dport}", udp.len)
                    self._analyze_udp(packet)
            except Exception as e:
                logger.debug("Transport layer processing error: %s", str(e))
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    packet_info["protocol"] = "HTTP"
                else:
                    packet_info["protocol"] = self._get_protocol_name(packet)
            # Assign protocol name AFTER ports are known
            try:
                packet_info["protocol"] = self._get_protocol_name(packet)
            except Exception as e:
                logger.debug("Protocol name resolution failed: %s", str(e))
                packet_info["protocol"] = "Unknown"

            # Log the packet now with accurate data
            # logger.info(
            #     "Packet Received: proto=%(protocol)s src=%(src_ip)s:%(src_port)s "
            #     "dst=%(dst_ip)s:%(dst_port)s size=%(size)d flags=%(flags)s",
            #     {
            #         "protocol": packet_info["protocol"],
            #         "src_ip": src_ip,
            #         "src_port": packet_info.get("src_port", "N/A"),
            #         "dst_ip": dst_ip,
            #         "dst_port": packet_info.get("dst_port", "N/A"),
            #         "size": packet_info["size"],
            #         "flags": packet_info.get("flags", "N/A")
            #     }
            # )
            
            # --- Populate _endpoint_tracker (Task 4) ---
            if src_ip and dst_ip and packet_info.get("protocol") and packet_info.get("dst_port") is not None:
                protocol_name = packet_info["protocol"]
                destination_port = packet_info["dst_port"]
                with self.data_lock:
                    self._endpoint_tracker[src_ip][protocol_name].add((dst_ip, destination_port))
            # --- End Populate _endpoint_tracker ---

            # Layer 3+ Analysis
            try:
                if packet.haslayer(IP):
                    self._analyze_ip_packet(packet[IP])
                    self.current_packet_source = packet[IP].src
                elif packet.haslayer(IPv6):
                    self._analyze_ipv6_packet(packet[IPv6])
                    self.current_packet_source = packet[IPv6].src
            except Exception as e:
                logger.debug("Layer 3+ analysis error: %s", str(e))

            # Application Layer Analysis
            try:
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    self._analyze_http(packet)
                    # logger.info(
                    #     "HTTP %s %s%s",
                    #     (
                    #         packet[HTTPRequest].Method.decode(errors="replace")
                    #         if packet.haslayer(HTTPRequest) else "Response"
                    #     ),
                    #     (
                    #         packet[HTTPRequest].Host.decode(errors="replace")
                    #         if packet.haslayer(HTTPRequest) else ""
                    #     ),
                    #     (
                    #         packet[HTTPRequest].Path.decode(errors="replace")
                    #         if packet.haslayer(HTTPRequest) else ""
                    #     ),
                    # )

                elif packet.haslayer(DNS):
                    self._analyze_dns(packet)
                    # logger.debug("DNS Query: %s", packet[DNS].summary())

            except Exception as e:
                logger.debug("Application layer error: %s", str(e))

            # Special Protocol Handlers
            try:
                if packet.haslayer(ICMP):
                    logger.debug("ICMP Packet: type=%d code=%d",
                                packet[ICMP].type, packet[ICMP].code)
                    self._analyze_icmp(packet)
                if packet.haslayer(Raw):
                    logger.debug("Raw payload: %d bytes", len(packet[Raw]))
                    self._analyze_payload(packet)
            except Exception as e:
                logger.debug("Special protocol analysis error: %s", str(e))

            # Behavioral Analysis
            try:
                logger.debug("Behavior analysis for %s", src_ip)
                self._analyze_behavior(packet)
            except Exception as e:
                logger.debug("Behavior analysis error: %s", str(e))

            # Final Processing
            try:
                self._process_payload_data(packet)
                self._update_packet_stats(packet_info)
                self._detect_common_threats(packet)
                logger.debug("Processed packet from %s", src_ip)
            except Exception as e:
                logger.error("Final processing error: %s", str(e))
                logger.error("Traceback:\n%s", traceback.format_exc())
            # ── Feature Extraction ──
            
            try:
                # Step 1: Extract CICIDS features
                features = self.feature_extractor.extract_features(packet)

                # Step 2: Prepare ML-ready vector
                feature_vector = self.packet_processor.prepare_feature_vector(features)

                # Optional: Save for offline debugging
                # if len(features) > 1:
                #     save_feature_vectors_to_json(feature_vector)
                #     save_features_to_json(features)

                # ── ML SCORING ──
                # For each attack-specific model, scale & predict
                for attack, (scaler, model, thresh) in self.models.items():
                    Xs = scaler.transform(feature_vector)            # shape (1,40)
                    prob = float(model.predict_proba(Xs)[0,1])       # P(attack)
                    if prob >= thresh:
                        alert_id = f"ml_{attack.replace(' ', '_')}_{str(uuid.uuid4())[:8]}"

                        # Determine severity (example heuristic)
                        severity = "High" if prob > 0.9 else "Medium" if prob > 0.75 else "Low"
                        if "DDoS" in attack or "Brute_Force" in attack: # Example: elevate severity for certain attack types
                            severity = "Critical" if prob > 0.8 else "High"
                        
                        description = f"Machine learning model detected {attack.replace('_', ' ')} with {prob*100:.2f}% confidence."
                        
                        source_ip_val = features.get('Src IP', packet_info.get('src_ip', 'N/A'))
                        destination_ip_val = features.get('Dst IP', packet_info.get('dst_ip', 'N/A'))
                        destination_port_val = features.get('Dst Port', packet_info.get('dst_port', 0))
                        
                        protocol_val_numeric = features.get('Protocol', packet_info.get('protocol_num')) # Assuming protocol_num if direct from packet_info
                        
                        # Ensure protocol_for_alert is a string name
                        protocol_map_for_alert = {6: "TCP", 17: "UDP", 1: "ICMP"}
                        protocol_str = protocol_map_for_alert.get(protocol_val_numeric)
                        if not protocol_str: # If not found in map, try to get from packet_info['protocol'] (string name) or default
                            protocol_str = packet_info.get('protocol', str(protocol_val_numeric))


                        alert = {
                            "id": alert_id,
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "severity": severity,
                            "source_ip": source_ip_val,
                            "destination_ip": destination_ip_val,
                            "destination_port": int(destination_port_val) if isinstance(destination_port_val, (str, float)) and str(destination_port_val).isdigit() else destination_port_val if isinstance(destination_port_val, int) else 0,
                            "protocol": protocol_str,
                            "description": description,
                            "threat_type": attack.replace('_', ' '), 
                            "rule_id": f"ml_model_{attack.replace(' ', '_')}", 
                            "metadata": {
                                "probability": round(prob, 4),
                                "model_name": attack, # Original attack name from model iteration
                                "features_contributing": {k: v for k, v in features.items() if v != 0}, # Send non-zero features
                                # "model_algorithm": self.models[attack][1].__class__.__name__ # Example if model object has algo info
                            }
                        }
                        try:
                            self.sio_queue.put_nowait(("ml_alert", alert))
                        except Full:
                            logger.warning("ML alert queue full, dropping: %s", alert_id)
                
                # Step 3: Update flow state & export on flow end
                self.packet_processor.process_packet(packet)

                # Periodic cleanup/backup of long‐lived flows
                if self.packet_counter.value % 300 == 0:
                    self.feature_extractor.cleanup_old_flows(timeout=60.0)

            except Exception as e:
                logger.debug("Feature extraction or ML scoring failed: %s", e)

            # ── Rule-Based Threat Detection ──
            try:
                threats = self.threat_detector.detect_threats(packet)
                for threat in threats:
                    try:
                        self.sio_queue.put_nowait(("threat_detected", threat))
                    except Full:
                        logger.warning("sio_queue is full. Dropping event: threat_detected")
            except Exception as e:
                logger.debug("Threat detection failed: %s", e)

            # ── ML-Based Threat Prediction (optional) ──
            # Uncomment if ML model is enabled
            # try:
            #     if self.enhanced_processor.prediction_model:
            #         ml_out = self.enhanced_processor.process_packet(packet)
            #         ml_result = ml_out.get("ml_prediction")
            #         if ml_result is not None:
            #             try:
            #                 self.sio_queue.put_nowait(("ml_alert", ml_out))
            #             except Full:
            #                 logger.warning("sio_queue is full. Dropping event: ml_alert")
            # except Exception as e:
            #     logger.debug("ML prediction failed: %s", e)
        except Exception as e:
            logger.error("Packet processing error: %s [Summary: %s]",
                        str(e), packet.summary()[:100])
            try:
                self.sio_queue.put_nowait(("system_error", {
                    "component": "packet_handler",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: system_error (packet_handler)")
        finally:
            self.current_packet_source = None
            logger.debug("Packet processing completed in %.4f seconds",
                        time.perf_counter() - self.start_time)

    def _create_packet_info(self, packet, src_ip, dst_ip, ip_version, is_arp):
        """DRY method for creating packet info structure"""
        return {
            "timestamp": datetime.utcnow(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_version": ip_version,
            "protocol": self._get_protocol_name(packet) if not is_arp else "ARP",
            "size": len(packet),
            "flags": None,
            "payload": self._extract_payload(packet),
            "src_port": None,
            "dst_port": None
        }

    def _process_payload_data(self, packet):
        """Centralized payload processing"""
        if packet.haslayer(Raw):
            try:
                raw = packet[Raw].load
                arr = np.frombuffer(raw, dtype=np.uint8)
                counts = np.bincount(arr, minlength=256)
                with self.data_lock:
                    for i, c in enumerate(counts):
                        self.byte_distribution[i] += int(c)
            except Exception as e:
                logger.debug("Payload processing error: %s", str(e))

    def _update_packet_stats(self, packet_info):
        """Thread-safe stats updating"""
        src_ip = packet_info["src_ip"]
        with self.data_lock:
            self.stats["total_packets"] += 1
            self.stats["protocols"][packet_info["protocol"]] += 1

            # Store in network_flows deque
            rp = self.recent_packets[src_ip]
            if 'network_flows' not in rp:
                rp['network_flows'] = deque(maxlen=1000)
            rp['network_flows'].append({
                "timestamp": time.time(),
                "protocol": packet_info["protocol"],
                "dst_ip": packet_info["dst_ip"],
                "dst_port": packet_info["dst_port"],
                "length": packet_info["size"]
            })

    def _is_binary(self, data: bytes) -> bool:
        """Check if data appears to be binary"""
        if not data:
            return False
        return bool(re.search(rb'[\x00-\x08\x0b-\x0c\x0e-\x1f]', data))

    def _smart_truncate(self, text: str, max_length: int) -> str:
        """Truncate text while trying to preserve domain structure"""
        if '.' in text:
            parts = text.split('.')
            while len('.'.join(parts)) > max_length and len(parts) > 1:
                parts.pop(0)
            truncated = '.'.join(parts)
            if len(truncated) > max_length:
                return '...' + truncated[-(max_length-3):]
            return truncated
        return text[:max_length-3] + '...'

    def _sanitize_dns_query(self, query, max_length: int = 255) -> str:
        """Sanitize DNS query with length trimming and binary detection"""
        try:
            if isinstance(query, str):
                decoded = query.strip()
                query_bytes = query.encode('utf-8', errors='replace')
            else:
                query_bytes = query
                decoded = query.decode('utf-8', errors='replace').strip()
        except Exception:
            decoded = query.decode('latin-1', errors='replace').strip()
            query_bytes = query

        # Detect binary-looking payloads
        if self._is_binary(query_bytes):
            hex_repr = query_bytes.hex()[:max_length]
            return f"[BINARY:{hex_repr}]..."

        if len(decoded) > max_length:
            return self._smart_truncate(decoded, max_length)

        return decoded

    def _validate_packet(self, packet_info: dict) -> bool:
        """Perform comprehensive packet validation"""
        validation_checks = [
            (packet_info["src_ip"], "src_ip"),
            (packet_info["dst_ip"], "dst_ip"),
            (packet_info["protocol"], "protocol"),
            (packet_info["size"] >= 0, "size"),
        ]

        for value, field in validation_checks:
            if not value:
                logger.debug(f"Invalid {field} in packet: {value}")
                return False

        try:
            if packet_info["src_ip"]:
                ipaddress.ip_address(packet_info["src_ip"])
            if packet_info["dst_ip"]:
                ipaddress.ip_address(packet_info["dst_ip"])
        except ValueError as e:
            logger.warning("Invalid IP format: %s", str(e))
            return False

        return True

    def _final_validation(self, packet_info: dict) -> bool:
        """Validate against known columns"""
        valid_fields = Packets.get_column_names()
        return all(k in valid_fields for k in packet_info.keys())

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate entropy of payload data"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def _analyze_ip_packet(self, ip_packet):
        """Analyze IPv4 packets"""
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst

        # Update top talkers
        with self.data_lock:
            self.stats["top_talkers"][src_ip] += 1
            self.stats["top_talkers"][dst_ip] += 1

        # Rate limiting
        if self.rate_limiter.check_rate_limit(src_ip):
            with self.firewall_lock:
                self.firewall.block_ip(
                src_ip, "Rate limit exceeded", duration=3600
            )
                self.firewall.block_ip(
                src_ip, "Rate limit exceeded", duration=3600 # Standardized duration
            )
            # Create standardized firewall block event
            firewall_event_data = self._create_firewall_block_event_data(
                ip_address=src_ip,
                reason="Rate limit exceeded",
                duration=3600, # Standardized duration
                packet_info={"dst_ip": dst_ip, "protocol": self._get_protocol_name(ip_packet)} # Provide some packet context
            )
            try:
                self.sio_queue.put_nowait(("firewall_blocked", firewall_event_data)) # Emitting standardized event
            except Full:
                logger.warning("sio_queue is full. Dropping event: firewall_blocked (rate_limit)")

    def _analyze_ipv6_packet(self, ipv6_packet):
        """Enhanced IPv6 threat analysis with tunneling detection"""
        src_ip = ipv6_packet.src
        dst_ip = ipv6_packet.dst

        # Update statistics
        with self.data_lock:
            self.stats["top_talkers"][src_ip] = (
                self.stats["top_talkers"].get(src_ip, 0) + 1
            )

        # IPv6-specific threat detection
        threats = {
            "tunneling_suspected": False,
            "unusual_extension_headers": False,
            "flood_attempt": False,
        }

        # Detect 6to4 tunneling
        if ipv6_packet.haslayer(IPv6ExtHdrFragment):
            fragment_header = ipv6_packet[IPv6ExtHdrFragment]
            threats["tunneling_suspected"] = fragment_header.offset > 0

        # Check for unusual extension headers
        extension_headers = [h.name for h in ipv6_packet.payload.layers()]
        threats["unusual_extension_headers"] = any(
            h in extension_headers for h in ["HopByHop", "Routing", "Destination"]
        )

        # Emit IPv6-specific events
        ipv6_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "next_header": ipv6_packet.nh,
            "threat_indicators": threats,
            "flow_label": ipv6_packet.fl,
            "payload_length": ipv6_packet.plen,
            # --- Refine ipv6_activity payload (Task 5) ---
            "id": f"ipv6_{datetime.utcnow().timestamp()}_{src_ip}_{dst_ip}",
            "traffic_class": ipv6_packet.tc,
            "hop_limit": ipv6_packet.hlim,
            # --- End Refine ipv6_activity payload ---
        }
        try:
            self.sio_queue.put_nowait(("ipv6_activity", ipv6_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: ipv6_activity")

        # Critical threat response
        if threats["tunneling_suspected"]:
            alert =  {
                        "type": "IPv6 Tunneling Attempt",
                        "severity": "high",
                        "source_ip": src_ip,
                        "description": f"Potential IPv6 tunneling detected from {src_ip}",
                    }
            self._queue_event("security_alert", alert)
            self.sio_queue.put_nowait(("security_alert", alert))

    def _calculate_threat_score(self, http_data: dict) -> dict:
        """Calculate threat score based on detected indicators"""
        score = 0
        indicators = []

        # Header Analysis Scoring
        headers = http_data.get("header_analysis", {})
        if headers.get("security_headers", {}).get("missing_csp"):
            score += SCORING_WEIGHTS["missing_security_headers"]
            indicators.append("missing_csp")

        if headers.get("header_injections"):
            score += SCORING_WEIGHTS["header_injections"]
            indicators.append("header_injections")

        # Content Analysis Scoring
        content = http_data.get("content_analysis", {})
        if content.get("injection_patterns"):
            score += SCORING_WEIGHTS["injection_patterns"]
            indicators.append("injection_patterns")

        if content.get("data_exfiltration"):
            score += SCORING_WEIGHTS["data_exfiltration"]
            indicators.append("data_exfiltration")

        # Behavioral Scoring
        behavior = http_data.get("behavioral_indicators", {})
        if behavior.get("unusual_timing", {}).get("rapid_requests"):
            score += SCORING_WEIGHTS["rapid_requests"]
            indicators.append("rapid_requests")

        if behavior.get("beaconing"):
            score += SCORING_WEIGHTS["beaconing"]
            indicators.append("beaconing")

        # Normalize score to 0-100
        score = min(100, score)

        return {
            "threat_score": score,
            "risk_level": self._get_risk_level(score),
            "contributing_indicators": indicators,
        }

    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 30:
            return "medium"
        if score >= 10:
            return "low"
        return "info"

    def _get_nxdomain_ratio(self, queries: list) -> float:
        """Calculate ratio of NXDOMAIN responses with validation"""
        # self.processing_lock has been removed. Access to shared _dns_counter needs to be thread-safe if used by multiple processes.
        # Assuming _dns_counter is a manager.dict() which is process-safe.
        if not self.current_packet_source: # This check might need re-evaluation if current_packet_source is not reliably set.
            logger.debug("Missing source context for NXDOMAIN ratio")
            return 0.0

        # manager.dict operations are inherently process-safe.
        counter = self._dns_counter.get(
            self.current_packet_source, {"total": 0, "nxdomain": 0}
        )
        total = counter["total"]
        return round(counter["nxdomain"] / total, 4) if total > 0 else 0.0

    def _calculate_inter_arrival(self, packet: Packet) -> float:
        """Calculate time between consecutive packets from same source"""

        if not packet.haslayer(IP):
            return 0.0

        src_ip = packet[IP].src
        current_time = time.time()

        with self.data_lock:
            last_time = self._last_seen_times.get(src_ip, current_time)
            interval = current_time - last_time
            self._last_seen_times[src_ip] = current_time

        return round(interval, 6)

    def _get_protocol_ratio(self, src_ip: str) -> dict:
        """Get protocol distribution ratios for a source IP"""
        with self.data_lock:
            counter = self._protocol_counter.get(src_ip, Counter())
            total = sum(counter.values())

            if total == 0:
                return {}

            return {proto: count / total for proto, count in counter.most_common()}

    def _get_unique_endpoints(self, src_ip: str) -> dict:
        """Get unique destination endpoints for a source IP"""
        with self.data_lock:
            endpoints = self._endpoint_tracker.get(src_ip, {})

            # Debug: print the actual data
            logger.debug("endpoints for %s: %s", src_ip, endpoints)

            # If there is data, check port types
            if endpoints:
                for proto, ports in endpoints.items():
                    logger.debug(
                        "Protocol: %s, Ports: %s, Port types: %s", proto, ports, [type(p) for p in ports]
                    )

            return {
                "total": sum(len(ports) for ports in endpoints.values()),
                "per_protocol": {
                    proto: len(ports) for proto, ports in endpoints.items()
                },
            }

    def _analyze_http(self, packet: Packet):
        """Comprehensive HTTP analysis with advanced threat detection"""
        try:
            # Layer extraction with safety checks
            http_layer = None
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]

            if not http_layer:
                return

            # Payload extraction with error handling
            try:
                payload = self._extract_http_payload(packet)
            except Exception as e:
                logger.error(f"Payload extraction failed: {str(e)}", exc_info=True)
                payload = b''

            # Base HTTP data structure
            http_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": packet[IP].src if packet.haslayer(IP) else None,
                "destination_ip": packet[IP].dst if packet.haslayer(IP) else None,
                "host": self._safe_extract(http_layer, "Host"),
                "path": self._safe_extract(http_layer, "Path"),
                "method": self._safe_extract(http_layer, "Method"),
                "user_agent": self._safe_extract(http_layer, "User_Agent"),
                "status_code": (
                            int(self._safe_extract(http_layer, "Status_Code"))
                            if packet.haslayer(HTTPResponse)
                            else None
                    ),
                "version": self._safe_extract(http_layer, "Http_Version"),
                "referer": self._safe_extract(http_layer, "Referer"),
                "content_type": self._safe_extract(http_layer, "Content_Type"),
                "threat_indicators": {},
                "header_analysis": {},
                "content_analysis": {},
                "behavioral_indicators": {},
                "observability_metrics": {},
            }

            # Flow tracking with multiprocessing-safe locks
            flow_info = {}
            try:
                with self.data_lock:
                    current_time = time.time()
                    tcp_layer = packet[TCP] if packet.haslayer(TCP) else None
                    flow_key = (
                        http_data["source_ip"],
                        http_data["destination_ip"],
                        tcp_layer.sport if tcp_layer else None,
                        tcp_layer.dport if tcp_layer else None,
                    )

                    if flow_key not in self.stats["flows"]:
                        self.stats["flows"][flow_key] = {
                            "first_seen": current_time,
                            "last_seen": current_time,
                            "packet_count": 1,
                            "byte_count": len(packet),
                            "direction": "outbound" if http_data["source_ip"] == self.current_packet_source else "inbound",
                        }
                    else:
                        self.stats["flows"][flow_key].update({
                            "last_seen": current_time,
                            "packet_count": self.stats["flows"][flow_key]["packet_count"] + 1,
                            "byte_count": self.stats["flows"][flow_key]["byte_count"] + len(packet),
                        })

                    flow_info = self.stats["flows"][flow_key]
                    flow_duration = max(flow_info["last_seen"] - flow_info["first_seen"], 0.001)
                    bytes_per_second = flow_info["byte_count"] / flow_duration if flow_duration > 0 else 0
                    packets_per_second = flow_info["packet_count"] / flow_duration if flow_duration > 0 else 0
            except Exception as e:
                logger.error(f"Flow tracking failed: {str(e)}", exc_info=True)
                try:
                    self.sio_queue.put_nowait(('system_error', {
                        'error': 'flow_tracking_failed',
                        'message': str(e),
                        'source_ip': http_data.get("source_ip")
                    }))
                except Full:
                    logger.warning("sio_queue is full. Dropping event: system_error (flow_tracking_failed)")
                flow_duration = 0
                bytes_per_second = 0
                packets_per_second = 0

            # Network layer extraction with safety
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

            # Header analysis
            header_fields = http_layer.fields if http_layer else {}
            try:
                header_length = sum(len(str(k)) + len(str(v)) for k, v in header_fields.items())
            except:
                header_length = 0

            # Main data structure population
            http_data.update({
                "network_metrics": {
                    "packet_size": len(packet),
                    "inter_arrival_time": self._calculate_inter_arrival(packet),
                    "protocol_ratio": self._get_protocol_ratio(packet[IP].src) if packet.haslayer(IP) else 0,
                    "protocol": ip_layer.proto if ip_layer else None,
                    "source_port": tcp_layer.sport if tcp_layer else None,
                    "destination_port": tcp_layer.dport if tcp_layer else None,
                    "ttl": ip_layer.ttl if ip_layer else None,
                    "packets_sent": self.stats["top_talkers"].get(http_data["source_ip"], 0),
                    "packets_received": self.stats["top_talkers"].get(http_data["destination_ip"], 0),
                    "bytes_per_second": round(bytes_per_second, 2),
                    "packets_per_second": round(packets_per_second, 2),
                    "unique_endpoints": self._get_unique_endpoints(packet[IP].src) if packet.haslayer(IP) else 0,
                    "tcp_metrics": self._analyze_tcp_metadata(packet),
                },
                "payload_characteristics": {
                    "entropy": self._calculate_entropy(payload),
                    "hex_patterns": self._find_hex_patterns(payload),
                    "header_length": header_length,
                    "compression_ratio": len(payload) / (header_length + 1) if payload else 0,
                    "header_field_count": len(header_fields),
                    "printable_ratio": sum(32 <= c < 127 for c in payload) / len(payload) if payload else 0,
                },
                "session_context": {
                    "request_count": self._get_session_count(packet[IP].src) if packet.haslayer(IP) else 0,
                    "unique_endpoints": self._get_unique_endpoints(packet[IP].src) if packet.haslayer(IP) else 0,
                    "flow_duration": round(flow_duration, 4),
                    "flow_id": hash(flow_key) if flow_key else None,
                    "direction": flow_info.get("direction", "unknown"),
                    "session_state": "new" if flow_info.get("packet_count", 0) == 1 else "established"
                }
            })

            # Advanced analyses with error handling
            try:
                http_data["header_analysis"] = {
                    "spoofed_headers": self._check_header_spoofing(http_layer),
                    "injection_vectors": self._detect_header_injections(http_layer),
                    "security_headers": self._check_security_headers(http_layer),
                    "header_manipulation": self._detect_header_tampering(http_layer),
                }

                http_data["content_analysis"] = {
                    "injection_patterns": self._detect_content_injections(payload),
                    "malicious_payloads": self._scan_malicious_patterns(payload),
                    "data_exfiltration": self._detect_payload_exfiltration(payload),
                    "path_exfiltration": self._detect_path_exfiltration(http_data["path"]),
                    "encoding_analysis": self._analyze_encodings(payload),
                }

                http_data["behavioral_indicators"] = {
                    "unusual_timing": self._check_request_timing(packet),
                    "beaconing": self._detect_beaconing(http_data),
                    "protocol_violations": self._check_protocol_anomalies(http_layer),
                }

                http_data["threat_analysis"] = self._calculate_threat_score(http_data)
            except Exception as e:
                logger.error(f"Advanced analysis failed: {str(e)}", exc_info=True)
                try:
                    self.sio_queue.put_nowait(('system_error', {
                        'error': 'analysis_failed',
                        'message': str(e),
                        'source_ip': http_data.get("source_ip")
                    }))
                except Full:
                    logger.warning("sio_queue is full. Dropping event: system_error (analysis_failed)")

            # Threat detection and notification
            try:
                critical_threats = self._detect_critical_threats(http_data, payload)
                if critical_threats:
                    # Standardize critical_alert by using _create_alert (Task 6)
                    description = f"Critical HTTP Threat: {critical_threats.get('type', 'Unknown Type')} for host {http_data.get('host', '')}{http_data.get('path', '')}. Indicators: {critical_threats.get('indicators')}"
                    
                    # Prepare metadata for _create_alert, ensuring specific fields are passed if available
                    alert_metadata = {
                        "destination_ip": http_data.get("destination_ip"),
                        "destination_port": http_data.get("network_metrics", {}).get("destination_port"),
                        "protocol": "HTTP", # Protocol is known here
                        "http_details": http_data, 
                        "critical_indicators": critical_threats.get('indicators', {}),
                        "raw_packet_summary": packet.summary(),
                        "rule_id": f"http_critical_{critical_threats.get('type', 'generic').lower().replace(' ', '_')}"
                    }
                    
                    self._create_alert(
                        alert_type="Critical HTTP Threat", 
                        severity="Critical", 
                        source_ip=http_data.get("source_ip"),
                        description=description,
                        metadata=alert_metadata
                    )
                    # Removed direct emission of "critical_alert"

                if payload:
                    sig_results = self.signature_engine.scan_packet(payload)
                    if sig_results:
                        try:
                            self.sio_queue.put_nowait(
                                ("signature_match", {**sig_results, "context": http_data})
                            )
                        except Full:
                             logger.warning("sio_queue is full. Dropping event: signature_match")
                # try:
                #      save_to_json([http_data]) # This saves the original extensive http_data
                # except Exception as e:
                #     logger.warning(f"Failed to process and save data: {e}")
                
                # --- Refine http_activity payload (Task 5) ---
                frontend_http_payload = {
                    "id": f"http_{datetime.utcnow().timestamp()}_{http_data.get('source_ip', 'unknownip')}_{http_data.get('destination_ip', 'unknownip')}",
                    "timestamp": http_data.get("timestamp", datetime.utcnow().isoformat()),
                    "source_ip": http_data.get("source_ip"),
                    "source_port": http_data.get("network_metrics", {}).get("source_port"),
                    "destination_ip": http_data.get("destination_ip"),
                    "destination_port": http_data.get("network_metrics", {}).get("destination_port"),
                    "method": http_data.get("method"),
                    "host": http_data.get("host"),
                    "path": http_data.get("path"),
                    "status_code": http_data.get("status_code"),
                    "user_agent": http_data.get("user_agent"),
                    "content_type": http_data.get("content_type"),
                    "protocol": http_data.get("version"), # HTTP version (e.g., "HTTP/1.1")
                    "payload_size": len(payload), # Size of the extracted payload from _extract_http_payload
                    "threat_score": http_data.get("threat_analysis", {}).get("threat_score"),
                    "risk_level": http_data.get("threat_analysis", {}).get("risk_level"),
                    "contributing_indicators": http_data.get("threat_analysis", {}).get("contributing_indicators", [])
                    # response_time_ms is complex to capture accurately at sniffer level and is omitted.
                }
                # save_http_data_to_json(frontend_http_payload) # Optionally save the emitted payload for debugging

                try:
                    self.sio_queue.put_nowait(("http_activity", frontend_http_payload))
                except Full:
                    logger.warning("sio_queue is full. Dropping event: http_activity")
                # --- End Refine http_activity payload ---

                # # <<< Integration with PhishingBlocker >>>
                # if self.phishing_blocker:
                #     try:
                #         # Prepare data for PhishingBlocker. This should include essential HTTP details.
                #         # PhishingBlocker.submit_http_for_analysis is a synchronous method that
                #         # schedules the asynchronous PhishingBlocker.process_http_activity,
                #         # ensuring the sniffer's packet processing loop is not blocked.
                #         blocker_data = {
                #             "host": http_data.get("host"), # Target host/domain
                #             "path": http_data.get("path"), # Request path
                #             "source_ip": http_data.get("source_ip"), # Source IP of the request
                #             "headers": header_fields, # Extracted HTTP headers
                #             # Additional fields like 'method', 'user_agent' can be added if PhishingBlocker uses them.
                #         }
                #         if blocker_data["host"]: # Only submit if a host is present.
                #             # logger.info(f"Submitting HTTP data for host '{blocker_data['host']}' to PhishingBlocker for analysis.")
                #             self.phishing_blocker.submit_http_for_analysis(blocker_data)
                #         else:
                #             logger.debug("Skipping PhishingBlocker submission: Host information is missing in http_data.")
                #     except Exception as pb_e: # Catch any errors during the submission process.
                #         logger.error(f"Error submitting HTTP data to PhishingBlocker: {pb_e}", exc_info=True)

            except Exception as e:
                logger.critical(f"Notification or PhishingBlocker submission failed: {str(e)}", exc_info=True)

        except Exception as e:
            logger.critical(f"HTTP analysis failed completely: {str(e)}", exc_info=True)
            try:
                self.sio_queue.put_nowait(('system_error', {
                    'error': 'http_analysis_failed',
                    'message': str(e),
                    'packet_summary': packet.summary() if 'packet' in locals() else None
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: system_error (http_analysis_failed)")

    def __analyze_chunked_encoding(self, payload: bytes) -> dict:
        """
        Internal method to validate chunked transfer encoding

        Args:
            payload: HTTP payload bytes

        Returns:
            dict: Chunked encoding validation results
        """
        results = {
            "invalid_chunks": 0,
            "incomplete_final_chunk": False,
            "chunk_size_errors": 0,
        }

        try:
            chunks = payload.split(b"\r\n\r\n", 1)[-1].split(b"\r\n")
            total_size = 0

            for i in range(0, len(chunks), 2):
                if i + 1 >= len(chunks):
                    results["incomplete_final_chunk"] = True
                    break

                size_line = chunks[i].strip()
                try:
                    chunk_size = int(size_line, 16)
                except ValueError:
                    results["chunk_size_errors"] += 1
                    continue

                if chunk_size == 0:
                    break

                total_size += chunk_size
                expected_length = len(chunks[i + 1])
                if expected_length != chunk_size:
                    results["invalid_chunks"] += 1

        except Exception as e:
            logger.debug(f"Chunked encoding analysis failed: {str(e)}")
            results["analysis_failed"] = True

        return results

    def _analyze_ciphersuites(self, packet: Packet) -> dict:
        """
        Analyze TLS cipher suites by manually parsing TCP payload
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Cipher suite information with security assessments
        """
        ciphers = {
            'supported_ciphers': [],
            'weak_ciphers': [],
            'recommended_ciphers': [],
            'tls_version': None,
            'analysis_error': False
        }

        try:
            if not packet.haslayer(TCP):
                return ciphers

            tcp = packet[TCP]
            if not tcp.payload:
                return ciphers

            # Get raw payload bytes
            raw = bytes(tcp.payload)
            if len(raw) < 5:
                return ciphers

            # Check TLS handshake (Content Type 0x16)
            if raw[0] != 0x16:
                return ciphers

            # Parse TLS version (bytes 1-3)
            version_bytes = raw[1:3]
            ciphers['tls_version'] = self.__parse_tls_version_from_bytes(version_bytes)

            # Look for Client Hello (Handshake Type 0x01)
            handshake_type = raw[5]
            if handshake_type != 0x01:  # Not ClientHello
                return ciphers

            # Parse cipher suites from ClientHello
            cipher_suites = self.__extract_cipher_suites(raw)
            ciphers['supported_ciphers'] = [self.__parse_cipher_suite(c) for c in cipher_suites]

            # Evaluate cipher strength
            ciphers['weak_ciphers'] = [c for c in ciphers['supported_ciphers'] 
                                    if c in WEAK_CIPHERS]
            ciphers['recommended_ciphers'] = [c for c in ciphers['supported_ciphers']
                                            if c in RECOMMENDED_CIPHERS]

        except Exception as e:
            logger.error(f"Cipher suite analysis failed: {str(e)}", exc_info=True)
            ciphers['analysis_error'] = True

        return ciphers

    def __extract_cipher_suites(self, raw: bytes) -> list:
        """Extract cipher suites from ClientHello message"""
        try:
            # ClientHello structure offsets
            pos = 5  # Start after TLS record header
            pos += 4  # Skip handshake message length
            pos += 2  # Skip client version
            pos += 32  # Skip random bytes
            session_id_length = raw[pos]
            pos += 1 + session_id_length

            # Skip cipher suites length (2 bytes)
            cipher_suites_length = int.from_bytes(raw[pos:pos+2], 'big')
            pos += 2

            # Extract cipher suite codes (2 bytes each)
            cipher_suites = []
            for _ in range(cipher_suites_length // 2):
                suite = raw[pos:pos+2]
                cipher_suites.append(suite)
                pos += 2

            return cipher_suites

        except IndexError:
            return []

    def __parse_cipher_suite(self, suite_bytes: bytes) -> str:
        """Convert cipher suite bytes to IANA name"""
        cipher_map = {
            b'\x00\x2f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
            b'\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
            b'\xc0\x14': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            b'\xc0\x2b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            b'\x13\x01': 'TLS_AES_128_GCM_SHA256',
            b'\x13\x02': 'TLS_AES_256_GCM_SHA384',
            b'\x00\x04': 'TLS_RSA_WITH_RC4_128_SHA',
            b'\x00\x0a': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        }
        return cipher_map.get(suite_bytes, f'UNKNOWN_{suite_bytes.hex().upper()}')

    def __parse_tls_version_from_bytes(self, version_bytes: bytes) -> str:
        """Parse TLS version from 2-byte version field"""
        version_map = {
            b'\x03\x04': 'TLS 1.3',
            b'\x03\x03': 'TLS 1.2',
            b'\x03\x02': 'TLS 1.1',
            b'\x03\x01': 'TLS 1.0',
            b'\x03\x00': 'SSL 3.0'
        }
        return version_map.get(version_bytes, f'Unknown ({version_bytes.hex()})')

    def _analyze_content_gaps(self, payload: bytes) -> dict:
        """
        Analyze payload for content inconsistencies and structural anomalies.

        Args:
            payload: Raw HTTP payload bytes

        Returns:
            dict: Structural integrity findings with severity scores
        """
        findings = {
            "header_body_mismatch": False,
            "chunked_errors": 0,
            "compression_anomalies": 0,
            "severity": 0.0,
        }

        try:
            if not payload:
                return findings

            # Check for chunked encoding inconsistencies
            if b"Transfer-Encoding: chunked" in payload:
                chunked_analysis = self.__analyze_chunked_encoding(payload)
                findings.update(chunked_analysis)

            # Check for Content-Length header mismatches
            content_length = self.__extract_content_length(payload)
            if content_length is not None:
                body_length = len(payload.split(b"\r\n\r\n", 1)[-1])
                if body_length != content_length:
                    findings["header_body_mismatch"] = True
                    findings["severity"] = max(findings["severity"], 0.7)

            # Check for suspicious compression patterns
            if b"Content-Encoding" in payload:
                findings["compression_anomalies"] = self.__check_compression_anomalies(
                    payload
                )

        except Exception as e:
            logger.error(f"Content gap analysis failed: {str(e)}", exc_info=True)
            findings["analysis_error"] = True

        return findings

    def __extract_content_length(self, payload: bytes) -> Optional[int]:
        """
        Safely extract and validate Content-Length header from HTTP payload
        
        Args:
            payload: Raw HTTP payload bytes
            
        Returns:
            int: Valid content length if found and valid, None otherwise
        """
        try:
            # Split headers from body
            headers_part = payload.split(b'\r\n\r\n', 1)[0]

            # Find Content-Length header
            for line in headers_part.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    try:
                        # Split header key/value
                        _, value = line.split(b':', 1)
                        content_length = value.strip().decode('ascii')

                        # Validate numeric value
                        if not content_length.isdigit():
                            logger.warning(f"Invalid Content-Length value: {content_length}")
                            return None

                        # Convert to integer
                        length = int(content_length)

                        # Check for multiple Content-Length headers
                        if b'content-length:' in line.lower().replace(line.lower(), b'', 1):
                            logger.warning("Multiple Content-Length headers detected")
                            return None

                        # Validate against maximum realistic value
                        if length > 10**9:  # 1GB
                            logger.warning(f"Excessive Content-Length: {length}")
                            return None

                        return length

                    except (ValueError, UnicodeDecodeError) as e:
                        logger.debug(f"Content-Length parsing failed: {str(e)}")
                        return None

            return None

        except Exception as e:
            logger.error(f"Content-Length extraction error: {str(e)}", exc_info=True)
            return None

    def __check_compression_anomalies(self, payload: bytes) -> dict:
        """
        Detect suspicious compression patterns in HTTP/TLS traffic
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            dict: Compression findings with severity assessment
        """
        findings = {
            'tls_compression': [],
            'http_compression': None,
            'insecure_methods': [],
            'severity': 0.0
        }

        try:
            # ==================== TLS Compression Analysis ====================
            if len(payload) > 5 and payload[0] == 0x16:  # TLS handshake
                handshake_type = payload[5]
                pos = 5  # Start after TLS record header

                # Skip record header length
                record_length = int.from_bytes(payload[3:5], 'big')
                pos += 4 if record_length > 0x4000 else 3

                if handshake_type == 0x01:  # ClientHello
                    pos += 38  # Skip client version + random bytes
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length

                    # Skip cipher suites length
                    cipher_suites_length = int.from_bytes(payload[pos:pos+2], 'big')
                    pos += 2 + cipher_suites_length

                    # Get compression methods
                    compression_methods_length = payload[pos]
                    pos += 1
                    findings['tls_compression'] = [
                        self.__parse_compression_method(m) 
                        for m in payload[pos:pos+compression_methods_length]]

                elif handshake_type == 0x02:  # ServerHello
                    pos += 38  # Skip server version + random bytes
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length

                    # Get selected compression method
                    if len(payload) > pos:
                        findings['tls_compression'] = [
                            self.__parse_compression_method(payload[pos])]

                # Check insecure TLS compression
                insecure_tls_methods = {'DEFLATE', 'LZS'}
                for method in findings['tls_compression']:
                    if method in insecure_tls_methods:
                        findings['insecure_methods'].append(f'TLS_{method}')
                        findings['severity'] = max(findings['severity'], 0.8)

            # ==================== HTTP Compression Analysis ====================
            # Parse HTTP headers from payload
            http_headers = self.__parse_http_headers(payload)

            http_compression = {
                'content_encoding': http_headers.get('Content-Encoding', ''),
                'accept_encoding': http_headers.get('Accept-Encoding', ''),
                'transfer_encoding': http_headers.get('Transfer-Encoding', '')
            }
            findings['http_compression'] = http_compression

            # Detect compression mismatch
            if (http_compression['content_encoding'] and 
                not http_compression['accept_encoding']):
                findings['severity'] = max(findings['severity'], 0.6)
                findings['insecure_methods'].append('Forced-Compression')

            # Detect deprecated methods
            deprecated_methods = {'compress', 'deflate', 'gzip'}
            used_methods = {m.strip().lower() 
                            for m in http_compression['content_encoding'].split(',') + 
                                    http_compression['accept_encoding'].split(',')}

            findings['insecure_methods'].extend(
                m for m in used_methods if m in deprecated_methods
            )

            if findings['insecure_methods']:
                findings['severity'] = max(findings['severity'], 0.7)

        except Exception as e:
            logger.error(f"Compression analysis failed: {str(e)}", exc_info=True)
            findings['analysis_error'] = True

        return findings

    def __parse_compression_method(self, method_byte: int) -> str:
        """Convert TLS compression method byte to name"""
        methods = {
            0x00: 'NULL',
            0x01: 'DEFLATE',
            0x40: 'LZS',
            0xFF: 'reserved'
        }
        return methods.get(method_byte, f'UNKNOWN_0x{method_byte:02x}')

    def __parse_http_headers(self, payload: bytes) -> dict:
        """Extract HTTP headers from raw payload"""
        headers = {}
        try:
            header_block = payload.split(b'\r\n\r\n', 1)[0]
            for line in header_block.split(b'\r\n'):
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.strip().decode('ascii', 'ignore')] = value.strip().decode('ascii', 'ignore')
        except Exception:
            pass
        return headers

    def _calculate_entropy(self, payload: bytes) -> float:
        """Calculate payload entropy for encrypted traffic detection"""
        if not payload:
            return 0.0
        counts = Counter(payload)
        probs = [c / len(payload) for c in counts.values()]
        return round(-sum(p * math.log2(p) for p in probs), 6)

    def _find_hex_patterns(self, payload: bytes) -> dict:
        """Identify suspicious hex patterns"""
        return {
            "magic_bytes": payload[:4].hex() if len(payload) >= 4 else None,
            "repeated_hex": bool(re.search(rb"(\x00{4,}|\xCC{4,})", payload)),
            "non_printable_ratio": (
                sum(c < 32 or c >= 127 for c in payload) / len(payload)
                if payload
                else 0
            ),
        }

    def _get_session_count(self, src_ip: str) -> dict:
        """Get session statistics for source IP"""
        flows = self.recent_packets.get(src_ip, {}).get('network_flows', [])
        return {
            "total_requests": len(flows),
            "unique_ports": len({f["dst_port"] for f in flows if f["dst_port"]}),
            "protocol_distribution": dict(
                Counter([f["protocol"] for f in flows])
            )
        }

    def _check_security_headers(self, http_layer) -> dict:
        """Analyze HTTP headers for security best practices"""
        security_checks = {
            "missing_csp": False,
            "insecure_csp": False,
            "missing_hsts": False,
            "hsts_short_max_age": False,
            "missing_xcto": False,
            "missing_xfo": False,
            "missing_xxp": False,
            "missing_rp": False,
            "insecure_cookies": False,
        }

        headers = {}
        # Convert all headers to lowercase for case-insensitive checks
        if hasattr(http_layer, "fields"):
            headers = {k.lower(): v for k, v in http_layer.fields.items()}
        elif hasattr(http_layer, "headers"):
            headers = {k.lower(): v for k, v in http_layer.headers.items()}

        # Content Security Policy Check
        if "content-security-policy" not in headers:
            security_checks["missing_csp"] = True
        else:
            csp = headers["content-security-policy"].lower()
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                security_checks["insecure_csp"] = True

        # Strict Transport Security Check
        if "strict-transport-security" not in headers:
            security_checks["missing_hsts"] = True
        else:
            hsts = headers["strict-transport-security"]
            if "max-age=" in hsts:
                try:
                    max_age = int(hsts.split("max-age=")[1].split(";")[0])
                    if max_age < 31536000:  # 1 year minimum recommended
                        security_checks["hsts_short_max_age"] = True
                except (ValueError, IndexError):
                    pass

        # X-Content-Type-Options Check
        if "x-content-type-options" not in headers:
            security_checks["missing_xcto"] = True
        elif headers["x-content-type-options"].lower() != "nosniff":
            security_checks["missing_xcto"] = True

        # X-Frame-Options Check
        if "x-frame-options" not in headers:
            security_checks["missing_xfo"] = True
        else:
            xfo = headers["x-frame-options"].lower()
            if xfo not in ["deny", "sameorigin"]:
                security_checks["missing_xfo"] = True

        # X-XSS-Protection Check (legacy but still useful)
        if "x-xss-protection" not in headers:
            security_checks["missing_xxp"] = True
        else:
            xxp = headers["x-xss-protection"].lower()
            if "0" in xxp:  # Disabled protection
                security_checks["missing_xxp"] = True

        # Referrer-Policy Check
        if "referrer-policy" not in headers:
            security_checks["missing_rp"] = True
        else:
            rp = headers["referrer-policy"].lower()
            if rp in ["unsafe-url", ""]:
                security_checks["missing_rp"] = True

        # Cookie Security Checks
        if "set-cookie" in headers:
            cookies = (
                headers["set-cookie"]
                if isinstance(headers["set-cookie"], list)
                else [headers["set-cookie"]]
            )
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if "secure" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                if "httponly" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                if "samesite=" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                    security_checks["insecure_cookies"] = True

        return security_checks

    def _detect_header_tampering(self, http_layer) -> dict:
        """Detect suspicious header modifications and inconsistencies"""
        tampering_indicators = {
            "header_injection": False,
            "duplicate_headers": False,
            "obfuscated_headers": False,
            "invalid_format": False,
            "unusual_casing": False,
            "malformed_values": False,
        }

        headers = {}
        if hasattr(http_layer, "fields"):
            headers = http_layer.fields
        elif hasattr(http_layer, "headers"):
            headers = http_layer.headers

        # Regex normalization rules
        HEADER_NORMALIZATION_RULES = [
            (r"(?i)^(X-)?", ""),  # Remove X- prefixes for common headers
            (r"[^a-zA-Z0-9-]", ""),  # Remove special characters
            (r"\s+", " "),  # Collapse whitespace
        ]

        VALUE_NORMALIZATION_RULES = [
            (r"\s+", " "),  # Collapse whitespace
            (r"^ *(.*?) *$", r"\1"),  # Trim whitespace
            (r";.*", ""),  # Remove parameter comments
            (r"(?i)\\x[0-9a-f]{2}", "?"),  # Replace hex escapes
            (r"(?i)%[0-9a-f]{2}", "?"),  # Replace URL encoding
            (r"(?i)(true|false)", lambda m: m.group().title()),  # Normalize booleans
        ]

        def normalize_header(header: str) -> str:
            """Normalize header name with regex rules"""
            normalized = header.strip()
            for pattern, repl in HEADER_NORMALIZATION_RULES:
                normalized = re.sub(pattern, repl, normalized)
            return normalized.title()  # Convert to Title-Case

        def normalize_value(value: str) -> str:
            """Normalize header value with regex rules"""
            if not isinstance(value, str):
                return str(value)
            normalized = value.strip()
            for pattern, repl in VALUE_NORMALIZATION_RULES:
                normalized = re.sub(pattern, repl, normalized)
            return normalized

        normalized_headers = {}
        original_headers = {}

        # First pass: Normalize and collect headers
        for header, value in headers.items():
            # Preserve original values
            orig_header = header
            orig_value = value

            # Normalize versions
            norm_header = normalize_header(str(header))
            norm_value = normalize_value(str(value))

            # Store for comparison
            original_headers[orig_header] = orig_value
            normalized_headers[norm_header] = norm_value

            # Original injection checks (preserved)
            if isinstance(orig_value, str):
                if any(c in orig_value for c in ["\r", "\n", "\0"]):
                    tampering_indicators["header_injection"] = True

                # Original obfuscation check
                if any(ord(c) > 127 for c in orig_value):
                    tampering_indicators["obfuscated_headers"] = True

                # Original casing check
                if orig_header != orig_header.title():
                    tampering_indicators["unusual_casing"] = True

                # Original malformed value check
                if ";" in orig_value and "=" not in orig_value:
                    tampering_indicators["malformed_values"] = True

            # Additional checks using normalized values
            if any(c in norm_value for c in ["\r", "\n", "\0"]):
                tampering_indicators["header_injection"] = True

            if norm_header != header.title():
                tampering_indicators["unusual_casing"] = True

            if ";" in norm_value and "=" not in norm_value:
                tampering_indicators["malformed_values"] = True

        # Duplicate header check using normalized names
        unique_headers = set(normalized_headers.keys())
        if len(normalized_headers) != len(unique_headers):
            tampering_indicators["duplicate_headers"] = True

        # Special checks using normalized values
        for norm_header, norm_value in normalized_headers.items():
            if norm_header == "Content-Length":
                if not norm_value.isdigit() or int(norm_value) < 0:
                    tampering_indicators["invalid_format"] = True

            elif norm_header == "Host":
                if ":" in norm_value:
                    port_part = norm_value.split(":")[-1].split("]")[-1]  # Handle IPv6
                    if not port_part.isdigit():
                        tampering_indicators["invalid_format"] = True

            elif norm_header == "User-Agent":
                if re.search(r"(?:[^\w\-\.]|^)\d{10,}(?:[^\w\-\.]|$)", norm_value):
                    tampering_indicators["malformed_values"] = True

        return tampering_indicators

    def _safe_extract(self, layer: Packet, attribute: str) -> Optional[str]:
        """
        Safely extract attributes from HTTP layers with comprehensive error handling
        """
        try:
            # Direct field access
            if hasattr(layer, attribute):
                value = getattr(layer, attribute)
            # Try lower-case fallback
            elif hasattr(layer, attribute.lower()):
                value = getattr(layer, attribute.lower())
            # Try fields dict
            elif attribute in layer.fields:
                value = layer.fields[attribute]
            else:
                return None

            if value is None:
                return None

            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        except Exception as e:
            logger.debug(f"Failed to extract {attribute}: {str(e)}")
            return None

    def _detect_content_injections(self, payload: bytes) -> dict:
        """Detect various code injection patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore").lower()

        return {
            "sql_injection": any(
                re.search(pattern, content)
                for pattern in [
                    r"union\s+select",
                    r"\d+=\d+",
                    r"waitfor\s+delay",
                    r"sleep\(\d+\)",
                ]
            ),
            "xss": any(
                pattern in content
                for pattern in ["<script>", "javascript:", "onerror=", "alert("]
            ),
            "command_injection": any(
                re.search(pattern, content)
                for pattern in [
                    r"(?:;|\||&&)\s*(?:sh|bash|cmd|powershell)\b",
                    r"\$(?:\{|\().*?(?:\}|\))",
                    r"`.*?`",
                ]
            ),
            "template_injection": any(
                pattern in content for pattern in ["{{", "}}", "<%", "%>"]
            ),
        }

    def _scan_malicious_patterns(self, payload: bytes) -> dict:
        """Detect known malicious payload patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore")

        # Indicators for common attack patterns
        return {
            "web_shells": any(
                re.search(pattern, content, re.I)
                for pattern in [
                    r"eval\(base64_decode\(",
                    r"system\(\$_GET\[",
                    r"passthru\(\$_POST\[",
                    r"shell_exec\(",
                ]
            ),
            "c2_indicators": any(
                re.search(pattern, content, re.I)
                for pattern in [
                    r"(?:https?://)[^\s/]+\.(?:php|asp|jsp)\?[a-z0-9]+=",
                    r"(?:[a-z0-9]{16,}\.(?:php|asp|jsp))",
                    r"cmd\.exe\s+/c",
                ]
            ),
            "obfuscation": any(
                re.search(pattern, content)
                for pattern in [
                    r"\w{30,}",  # Long random strings
                    r"[0-9a-f]{20,}",  # Long hex strings
                    r"(?:[A-Za-z0-9+/]{4}){10,}",  # Base64 patterns
                    r"\$(?:\w+\$)+\w+",  # PHP variable variables
                ]
            ),
        }

    def _analyze_encodings(self, payload: bytes) -> dict:
        """Detect suspicious encoding patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore")

        return {
            "double_encoded": any(
                pattern in content
                for pattern in [
                    "%2520",  # Double URL encoding
                    "&#x",  # Hex HTML entities
                    "\\u00",  # Unicode escapes
                ]
            ),
            "non_standard": any(
                re.search(pattern, content)
                for pattern in [
                    r"%[0-9a-f]{2}%[0-9a-f]{2}",  # Repeated URL encoding
                    r"&#\d+;",  # HTML entities
                    r"\\x[0-9a-f]{2}",  # Hex escapes
                ]
            ),
            "compression": any(
                content.startswith(magic)
                for magic in [
                    b"\x1f\x8b",  # Gzip
                    b"\x78\x01",  # Zlib
                    b"\x42\x5a\x68",  # Bzip2
                ]
                if payload.startswith(magic)
            ),
        }

    def _check_request_timing(self, packet: Packet) -> dict:
        """Detect timing-based anomalies"""
        current_time = time.time()

        if not hasattr(self, "last_request_time"):
            self.last_request_time = {}

        src_ip = packet[IP].src if packet.haslayer(IP) else None
        if not src_ip:
            return {}

        # Calculate time delta
        time_delta = current_time - self.last_request_time.get(src_ip, current_time)
        self.last_request_time[src_ip] = current_time

        return {
            "rapid_requests": time_delta < 0.1,  # >10 requests/sec
            "slowloris_indicator": time_delta > 5
            and packet.haslayer(TCP)
            and packet[TCP].flags == "S",  # Slow connection setup
            "beaconing_pattern": 0.9 < time_delta % 60 < 1.1,  # ~60s intervals
        }

    def _scan_content(self, payload: bytes) -> dict:
        """Analyze HTTP payload for suspicious content patterns"""
        content_str = payload.decode(errors="ignore").lower()

        return {
            "base64_encoded": any(
                len(chunk) > 50 and all(c in BASE64_CHARS for c in chunk)
                for chunk in content_str.split()
            ),
            "executable_patterns": any(
                pattern in content_str
                for pattern in ["<script>", "eval(", "fromcharcode", "cmd.exe"]
            ),
            "long_hex_strings": bool(re.search(r"(?:[0-9a-f]{20,})", content_str)),
        }

    def _check_protocol_anomalies(self, http_layer) -> dict:
        """Detect HTTP protocol violations"""
        anomalies = {}

        if hasattr(http_layer, "Method"):
            method = http_layer.Method.decode(errors="ignore")
            anomalies["invalid_method"] = method not in [
                "GET",
                "POST",
                "HEAD",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PATCH",
            ]

        if hasattr(http_layer, "Http_Version"):
            version = http_layer.Http_Version.decode(errors="ignore")
            anomalies["version_spoofing"] = not version.startswith("HTTP/1.")

        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)
            anomalies["header_overflow"] = len(headers) > 8192  # 8KB header limit
            anomalies["crlf_injection"] = any(
                marker in headers for marker in ["\r\n\r\n", "\n\n"]
            )

        return anomalies

    def _decode_chunked(self, payload: bytes) -> bytes:
        """Decode HTTP chunked transfer encoding"""
        try:
            decoded = bytearray()
            while payload:
                # Find chunk size
                chunk_end = payload.find(b"\r\n")
                if chunk_end == -1:
                    break

                chunk_size = int(payload[:chunk_end], 16)
                if chunk_size == 0:
                    break  # End of chunks

                # Extract chunk data
                chunk_start = chunk_end + 2
                chunk_data = payload[chunk_start : chunk_start + chunk_size]
                decoded.extend(chunk_data)

                # Move to next chunk
                payload = payload[chunk_start + chunk_size + 2 :]

            return bytes(decoded)
        except Exception as e:
            logger.warning("Chunked decode failed: %s", str(e))
            return payload  # Return original if decoding fails

    def _decompress_gzip(self, payload: bytes) -> bytes:
        """Decompress GZIP-encoded HTTP payload"""
        try:
            import zlib

            # Skip header if present
            if payload.startswith(b"\x1f\x8b"):
                return zlib.decompress(payload, 16 + zlib.MAX_WBITS)
            return payload
        except Exception as e:
            logger.warning("GZIP decompress failed: %s", str(e))
            return payload

    def _detect_payload_exfiltration(self, payload: bytes) -> bool:
        """Check payload for sensitive data patterns"""
        if not payload:
            return False
        return any(
            p in payload.decode(errors="ignore").lower()
            for p in ["ccnum=", "password=", "secret="]
        )

    def _detect_path_exfiltration(self, path: str) -> bool:
        """Check URL path for exfiltration signs"""
        if not path:
            return False
        return len(path) > 200 and any(c in path for c in ["=", "/", "+"])

    def _extract_http_payload(self, packet: Packet) -> bytes:
        """Handle chunked encoding and compressed payloads"""
        payload = bytes(packet[Raw].payload) if packet.haslayer(Raw) else b""

        if packet.haslayer(HTTP) and hasattr(packet[HTTP], "Transfer_Encoding"):
            if "chunked" in packet[HTTP].Transfer_Encoding:
                payload = self._decode_chunked(payload)

        if packet.haslayer(HTTP) and hasattr(packet[HTTP], "Content_Encoding"):
            if "gzip" in packet[HTTP].Content_Encoding:
                payload = self._decompress_gzip(payload)

        return payload

    def _detect_critical_threats(
        self, http_data: dict, payload: bytes
    ) -> Optional[dict]:
        """Check for immediately actionable threats"""
        threats = {}

        # Web shell detection
        if http_data["path"] and any(
            p in http_data["path"].lower() for p in ["/cmd.php", "/shell", "/backdoor"]
        ):
            threats["web_shell"] = True

        # RCE patterns
        rce_patterns = [
            r"system\(",
            r"exec\(",
            r"passthru\(",
            r"popen\(",
            r"proc_open\(",
            r"`.*`",
        ]
        if any(re.search(p, payload.decode(errors="ignore")) for p in rce_patterns):
            threats["rce_attempt"] = True

        # SQL injection patterns
        sql_patterns = [
            r"union\s+select",
            r"1=1--",
            r"waitfor\s+delay",
            r"sleep\(\d+\)",
            r"benchmark\(",
        ]
        if any(re.search(p, payload.decode(errors="ignore")) for p in sql_patterns):
            threats["sql_injection"] = True

        if threats:
            return {
                "type": "Critical HTTP Threat",
                "severity": "critical",
                "source_ip": http_data["source_ip"],
                "indicators": threats,
                "timestamp": http_data["timestamp"],
            }
        return None

    def _detect_beaconing(self, http_data: dict) -> bool:
        """Detect potential C2 beaconing behavior"""
        if not http_data["host"]:
            return False

        # Check against known beaconing patterns
        beacon_domains = ["azure-api.net", "aws.amazon.com", "googleapis.com"]

        return (
            http_data["host"] in beacon_domains
            and http_data["method"] == "GET"
            and len(http_data.get("path", "")) < 30  # Short paths common in beacons
        )

    def _check_header_spoofing(self, http_layer) -> list:
        """Detect header spoofing attempts"""
        suspicious = []
        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)

            # Common spoofing indicators
            if "X-Forwarded-For: 127.0.0.1" in headers:
                suspicious.append("localhost_spoofing")
            if "Via:" in headers and "Proxy-Authorization" not in headers:
                suspicious.append("proxy_spoofing")

        return suspicious

    def _detect_header_injections(self, http_layer) -> list:
        """Detect HTTP header injection attempts"""
        injections = []
        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)

            # CRLF injection patterns
            if any(pattern in headers for pattern in ["\r\n", "%0d%0a", "\\r\\n"]):
                injections.append("crlf_injection")

            # HTTP response splitting
            if "Set-Cookie:" in headers and ("\n" in headers or "\r" in headers):
                injections.append("response_splitting")

        return injections

    def _detect_c2_patterns(self, http_data: dict) -> bool:
        """Check for Command & Control patterns"""
        c2_indicators = [
            r"(?:[a-z0-9]{16,}\.php)",  # Long random PHP files
            r"(?:cmd|whoami|ipconfig)\=",  # Common commands
            r"(?:sleep\(\d+\))",  # Time delay patterns
        ]
        return any(
            re.search(pattern, http_data["path"] or "", re.I)
            for pattern in c2_indicators
        )

    def _analyze_dns(self, packet: Packet):
        """Enhanced DNS analysis with TTL monitoring"""
        try:
            dns = packet[DNS]
            ip = packet[IP]

            queries = []
            responses = []

            # Query processing
            if dns.qr == 0 and dns.qd:  # Query
                queries.append({
                    "name": dns.qd.qname.decode(errors="replace").strip('.') if dns.qd.qname else "",
                    "type": int(dns.qd.qtype),
                })

            # Response processing
            elif dns.qr == 1 and dns.an:  # Response
                for answer in dns.an:
                    responses.append({
                        "name": answer.rrname.decode(errors="replace").strip('.') if answer.rrname else "",
                        "type": int(answer.type),
                        "ttl": int(answer.ttl),
                        "data": str(answer.rdata) if hasattr(answer, "rdata") else None,
                    })

            # --- Refine dns_activity payload (Task 5) ---
            dns_payload = {
                "id": f"dns_{datetime.utcnow().timestamp()}_{ip.src}",
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": ip.src,
                "queries": [{"query_name": q.get("name"), "query_type": q.get("type")} for q in queries],
                "responses": [{"name": r.get("name"), "type": r.get("type"), "ttl": r.get("ttl"), "response_data": r.get("data")} for r in responses],
                "is_suspicious": any(q.get("type", 0) in {12, 16, 255} for q in queries), # Common suspicious query types (TXT, NULL, ANY)
                "tunnel_detected": bool(self._detect_dns_tunneling(queries, responses)),
                "dga_score": float(self._calculate_dga_score(queries)),
                "nxdomain_ratio": float(self._get_nxdomain_ratio(queries)), 
                "unique_domains_queried": int(len({q.get("name") for q in queries if q.get("name")})),
                "query_chain_depth": len([rr for rr in responses if rr.get("type") == 5]), 
                "ttl_variation": float(np.std([r["ttl"] for r in responses if r.get("ttl") is not None])) if responses and any(r.get("ttl") is not None for r in responses) else 0.0,
                "subdomain_entropy": float(self._calculate_subdomain_entropy(queries)),
                "ttl_anomaly": False # Default, updated below
            }
            
            # TTL Anomaly Check
            if dns_payload["responses"] and any(r.get("ttl") is not None for r in dns_payload["responses"]):
                valid_ttls = [r["ttl"] for r in dns_payload["responses"] if r.get("ttl") is not None]
                if valid_ttls: # Ensure valid_ttls is not empty before division
                    avg_ttl = sum(valid_ttls) / len(valid_ttls)
                    dns_payload["ttl_anomaly"] = bool(avg_ttl < 30) 
            
            self.sio_queue.put_nowait(("dns_activity", dns_payload))
            # --- End Refine dns_activity payload ---

        except Exception as e:
            logger.error(f"DNS analysis failed: {str(e)}", exc_info=True)

    def _calculate_subdomain_entropy(self, queries: list) -> float:
        """Calculate entropy of subdomain labels"""
        labels = [q["name"].split(".")[-2] for q in queries if "." in q["name"]]
        counter = Counter(labels)
        probs = [c / len(labels) for c in counter.values()]
        return -sum(p * math.log2(p) for p in probs) if labels else 0

    def _calculate_dga_score(self, queries: list) -> float:
        """
        Calculate likelihood of DGA (Domain Generation Algorithm) usage based on:
        - N-gram frequency analysis
        - Domain length and entropy
        - Subdomain patterns
        - TLD distribution

        Returns: Score between 0 (benign) and 1 (highly likely DGA)
        """
        if not queries:
            return 0.0

        total_score = 0.0
        analyzed_domains = 0

        # English language n-gram frequencies (pre-computed)
        COMMON_BIGRAMS = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"}
        COMMON_TRIGRAMS = {
            "the",
            "and",
            "ing",
            "her",
            "hat",
            "his",
            "tha",
            "ere",
            "for",
            "ent",
        }

        for query in queries:
            if not query.get("name"):
                continue

            domain = query["name"].lower().rstrip(".")
            if not domain or len(domain) < 4:
                continue

            domain_parts = domain.split(".")
            main_domain = domain_parts[-2] if len(domain_parts) > 1 else domain_parts[0]
            subdomain = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

            # Initialize metrics
            metrics = {
                "length_score": 0,
                "entropy_score": 0,
                "ngram_score": 0,
                "subdomain_score": 0,
                "tld_score": 0,
            }

            # 1. Length analysis (long domains are suspicious)
            metrics["length_score"] = min(1, len(main_domain) / 30)  # Normalize 0-1

            # 2. Entropy calculation (high entropy = random-looking)
            char_counts = Counter(main_domain)
            entropy = -sum(
                (count / len(main_domain)) * math.log2(count / len(main_domain))
                for count in char_counts.values()
            )
            metrics["entropy_score"] = min(
                1, entropy / 4
            )  # Max entropy for a-z is ~4.7

            # 3. N-gram analysis (matches against known language patterns)
            bigrams = {main_domain[i : i + 2] for i in range(len(main_domain) - 1)}
            trigrams = {main_domain[i : i + 3] for i in range(len(main_domain) - 2)}

            metrics["ngram_score"] = 1 - (
                (len(bigrams & COMMON_BIGRAMS) + len(trigrams & COMMON_TRIGRAMS))
                / (len(bigrams) + len(trigrams) + 1e-6)
            )

            # 4. Subdomain analysis (random subdomains are suspicious)
            if subdomain:
                sub_entropy = -sum(
                    (count / len(subdomain)) * math.log2(count / len(subdomain))
                    for count in Counter(subdomain).values()
                )
                metrics["subdomain_score"] = min(1, sub_entropy / 4) * 0.7  # Weighted

            # 5. TLD analysis (uncommon TLDs increase suspicion)
            uncommon_tlds = {"xyz", "top", "gq", "cf", "pw"}
            tld = domain_parts[-1]
            metrics["tld_score"] = 0.8 if tld in uncommon_tlds else 0.1

            # Weighted combined score
            weights = {
                "length_score": 0.15,
                "entropy_score": 0.30,
                "ngram_score": 0.25,
                "subdomain_score": 0.15,
                "tld_score": 0.15,
            }

            domain_score = sum(
                metrics[metric] * weight for metric, weight in weights.items()
            )

            total_score += min(1, domain_score * 1.2)  # Cap at 1.0
            analyzed_domains += 1

        if analyzed_domains == 0:
            return 0.0

        # Average score across all queries with nonlinear scaling
        avg_score = total_score / analyzed_domains
        return round(avg_score**1.5, 2)  # Make scores >0.7 rarer

    def _detect_dns_tunneling(self, queries: list, responses: list) -> bool:
        """Detect DNS tunneling attempts"""
        suspicious = False
        for q in queries:
            # Check for long subdomains or encoded data
            if len(q["name"]) > 60 or any(c in q["name"] for c in ["_", "=", "/"]):
                suspicious = True
        return suspicious

    def _analyze_ssh(self, packet: Packet):
        """Enhanced SSH analysis with version detection"""
        ssh_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
            "destination_ip": packet[IP].dst if packet.haslayer(IP) else None,
            "is_encrypted": False,
        }

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                banner = payload.decode("utf-8", errors="replace")
                ssh_data["banner"] = banner[:100]  # Truncate long banners

                # Detect brute force patterns
                if "Failed password" in banner or "Invalid user" in banner:
                    ssh_data["is_bruteforce"] = True
                    with self.data_lock:
                        self.stats["threat_types"]["ssh_bruteforce"] += 1
            except UnicodeDecodeError:
                ssh_data["is_encrypted"] = True
        try:
            self.sio_queue.put_nowait(("ssh_activity", ssh_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: ssh_activity")
    def _detect_common_threats(self, packet: Packet):
        """Comprehensive threat detection"""
        # Port scan detection
        if packet.haslayer(TCP) and packet[TCP].flags == 0x29:  # SYN scan
            self._create_alert(
                alert_type="Port Scan",
                severity="High",
                source_ip=packet[IP].src if packet.haslayer(IP) else None,
                description="SYN scan detected",
                metadata={
                    "destination_port": packet[TCP].dport,
                    "flags": str(packet[TCP].flags),
                },
            )

        # ARP spoofing detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            if packet[Ether].src != packet[ARP].hwsrc:
                self._create_alert(
                    alert_type="ARP Spoofing",
                    severity="Critical",
                    source_ip=packet[ARP].psrc,
                    description="ARP cache poisoning attempt",
                    metadata={
                        "claimed_mac": packet[ARP].hwsrc,
                        "actual_mac": packet[Ether].src,
                    },
                )

        # DNS tunneling detection
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNSQR]
            if len(dns.qname) > 50:  # Long domain names
                self._create_alert(
                    alert_type="DNS Tunneling",
                    severity="Medium",
                    source_ip=packet[IP].src if packet.haslayer(IP) else None,
                    description="Possible DNS tunneling",
                    metadata={
                        "query": dns.qname.decode(errors="replace"),
                        "length": len(dns.qname),
                    },
                )

    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        description: str,
        metadata: Dict = None,
    ):
        """Create and emit security alert with database logging"""
        alert_id = f"alert_{datetime.utcnow().timestamp()}_{hash(source_ip or '')}"
        alert = {
            "id": alert_id,
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "timestamp": datetime.utcnow().isoformat(),
            "description": description,
            "metadata": metadata or {},
        }

        # Update stats
        with self.data_lock:
            self.stats["alerts"].append(alert)
            self.stats["threat_types"][alert_type] += 1

        # Emit via Socket.IO
        try:
            self.sio_queue.put_nowait(( "security_alert", alert))
        except Full:
            logger.warning("sio_queue is full. Dropping event: security_alert (%s)", alert_type)

        # Log to database
        self._log_threat_to_db(alert)

    def _log_threat_to_db(self, alert: Dict):
        """Log threat to database"""
        try:
            db = get_db()
            db.add(
                ThreatLog(
                    id=alert["id"],
                    rule_id=alert.get("rule_id", "heuristic"),
                    source_ip=alert["source_ip"],
                    threat_type=alert["type"],
                    severity=alert["severity"],
                    description=alert["description"],
                    raw_data=str(alert["metadata"]),
                    timestamp=datetime.fromisoformat(alert["timestamp"]),
                )
            )
            db.commit()
        except Exception as e:
            logger.error("Failed to log threat: %s", str(e))
            try:
                self.sio_queue.put_nowait(( "database_error", {
                            "operation": "threat_logging",
                            "error": str(e),
                            "timestamp": datetime.utcnow().isoformat(),
                        }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: database_error (threat_logging)")

    async def _log_packet_to_db(self, packet_data: dict):
        try:
            valid_fields = [c.key for c in inspect(Packets).mapper.column_attrs]
            filtered_data = {k: v for k, v in packet_data.items() if k in valid_fields}
            if not filtered_data:
                logger.warning("No valid fields found for packet")
                return

            async with get_db() as db:
                db.add(Packets(**filtered_data))

        except Exception as e:
            logger.error("Logging failed: %s", str(e))

    # def start(self, interface: str = "Wi-Fi"):
    #     """Start sniffing with enhanced error handling"""
    #     if (
    #         getattr(self, "sniffer_process", None) is not None
    #         and self.sniffer_process.is_alive()
    #     ):
    #         logger.warning("Sniffer already running")

    #         return

    #     # Initialize interface
    #     interface = interface or conf.iface

    #     if not interface:
    #         interface = conf.iface
    #     self.worker_process = Process(target=self._process_queue, daemon=True)
    #     self.sniffer_process = Process(
    #         target=self._start_sniffing,
    #         args=(interface,),
    #         daemon=True,
    #     )
    #     self.stop_event.clear()
    #     self.worker_process.start()
    #     self.sniffer_process.start()
    #     self.reporter_process.start()

    #     logger.info("Started packet sniffing on interface %s" , interface)

    #     # Send system alert
    #     self.sio_queue.put(
    #         (
    #             "system_status",
    #             {
    #                 "component": "packet_sniffer",
    #                 "status": "running",
    #                 "interface": interface,
    #                 "timestamp": datetime.utcnow().isoformat(),
    #             },
    #         )
    #     )

    async def start(self, interface: str = None):
        """Start the packet sniffer in a separate process and other auxiliary processes."""
        interface = interface or conf.iface
        if not interface:
            logger.error("No network interface specified for sniffing.")
            raise RuntimeError("No interface specified for packet sniffing.")

        if self.sniffer_process and self.sniffer_process.is_alive():
            logger.warning("Sniffer process is already running on interface %s.", interface)
            return

        # 1) Start queue-processor (if not already running)
        if not self.worker_process or not self.worker_process.is_alive():
            self.worker_process = Process(target=self._process_queue, daemon=True)
            self.worker_process.start()
            # logger.info("Queue processing worker started.")

        # 2) Start the new sniffer process for AsyncSniffer
        self.stop_sniffing_event.clear()
        self.sniffer_process = Process(
            target=self._run_sniffer_process,
            args=(interface, self.sio_queue), # Pass the queue
            daemon=True
        )
        self.sniffer_process.start()
        # logger.info("Packet sniffer process started on interface %s.", interface)
        
        # The original `await self._stop_event.wait()` was likely for keeping the main thread alive
        # or for a different kind of sniffer lifecycle. In a multiprocessing setup,
        # the main process continues, and the sniffer runs in the background.
        # If `start` is expected to block, this needs reconsideration. Assuming it's not.

        # 3) Start reporter (if not already running)
        if not self.reporter_process or not self.reporter_process.is_alive():
            self.reporter_process = Process(
            target=_reporter_loop,
            args=(self.sio_queue, self.stats, self._reporter_stop,5.0),
            daemon=True,
        )
            self.reporter_process.start()

        # 4) send system status
        try:
            self.sio_queue.put_nowait((
                "system_status",
                {
                    "component": "packet_sniffer",
                    "status": "running",
                    "interface": interface,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ))
        except Full:
            logger.warning("sio_queue is full. Dropping event: system_status (running)")
            # Depending on importance, you might want to retry or handle this differently

    def stop(self):
        """Stop packet capture and cleanup."""
        # logger.info("Stopping packet sniffer and associated processes...")

        # 1) Stop the new sniffer process
        if self.sniffer_process and self.sniffer_process.is_alive():
            # logger.info("Signaling sniffer process to stop...")
            self.stop_sniffing_event.set()
            self.sniffer_process.join(timeout=10) # Increased timeout for sniffer to stop gracefully
            if self.sniffer_process.is_alive():
                logger.warning("Sniffer process did not stop gracefully, terminating.")
                self.sniffer_process.terminate()
                self.sniffer_process.join(timeout=5) # Wait for termination
            if not self.sniffer_process.is_alive():
                 logger.info("Sniffer process stopped.")
            else:
                logger.error("Failed to stop sniffer process even after termination attempt.")
            self.sniffer_process = None
        else:
            logger.info("Sniffer process was not running or already stopped.")
            
            # self.recorder.flush_remaining_on_exit() # If recorder is used

        # 2) Stop worker and reporter as before
        if self.worker_process and self.worker_process.is_alive():
            # logger.info("Stopping queue processing worker...")
            self.worker_process.terminate() # Consider a more graceful shutdown if possible
            self.worker_process.join(timeout=5)
            if not self.worker_process.is_alive():
                logger.info("Queue processing worker stopped.")
            else:
                logger.warning("Queue processing worker did not stop gracefully.")
            self.worker_process = None # Clear the process reference

        if self.reporter_process and self.reporter_process.is_alive():
            logger.info("Stopping reporter process...")
            self._reporter_stop.set()
            self.reporter_process.join(timeout=5) # Reporter has an event, so join should be effective
            if self.reporter_process.is_alive():
                logger.warning("Reporter process did not stop gracefully, terminating.")
                self.reporter_process.terminate()
                self.reporter_process.join(timeout=5)
            if not self.reporter_process.is_alive():
                pass
                # logger.info("Reporter process stopped.")
            else:
                logger.warning("Reporter process did not stop gracefully after termination.")
            self.reporter_process = None # Clear the process reference

        self.end_time = time.perf_counter()
        
        # This event was for the old AsyncSniffer direct control, may not be needed or used the same way
        if self._stop_event and not self._stop_event.is_set(): # Ensure it's set if other parts rely on it
             self._stop_event.set()

        logger.info("Processed %d packets in %.2f seconds", self.packet_counter.value, (self.end_time - self.start_time))
        
        # Send stopping status
        try:
            self.sio_queue.put_nowait((
                "system_status",
                {
                    "component": "packet_sniffer",
                    "status": "stopped",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ))
        except Full:
            logger.warning("sio_queue is full. Dropping event: system_status (stopped)")

    def get_stats(self) -> Dict:
        """Get comprehensive statistics"""
        uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            **self.stats,
            "uptime_seconds": uptime,
            "avg_packets_per_second": (
                self.stats["total_packets"] / uptime if uptime > 0 else 0
            ),
            "current_time": datetime.utcnow().isoformat(),
        }

    def clear_stats(self):
        """Reset statistics while preserving runtime"""
        with self.data_lock:
            self.stats.update(
                {
                    "total_packets": 0,
                    "protocols": defaultdict(int),
                    "top_talkers": defaultdict(int),
                    "alerts": deque(maxlen=1000),
                    "throughput": {"1min": deque(maxlen=60), "5min": deque(maxlen=300)},
                    "threat_types": defaultdict(int),
                }
            )

    def _analyze_tcp(self, packet: Packet):
        """Advanced TCP traffic analysis with threat detection"""
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        ip = packet[IP] if packet.haslayer(IP) else None

        # Base TCP data structure
        tcp_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip.src if ip else None,
            "destination_ip": ip.dst if ip else None,
            "source_port": tcp.sport,
            "destination_port": tcp.dport,
            "flags": {
                "syn": tcp.flags.S,
                "ack": tcp.flags.A,
                "fin": tcp.flags.F,
                "rst": tcp.flags.R,
                "psh": tcp.flags.P,
                "urg": tcp.flags.U,
                "ece": tcp.flags.E,
                "cwr": tcp.flags.C,
            },
            "window_size": tcp.window,
            "seq_num": tcp.seq,
            "ack_num": tcp.ack,
            "payload_size": len(tcp.payload) if tcp.payload else 0,
            # Threat indicators will be flattened below
        }

        # TCP Flag Analysis and other indicators
        threat_indicators = {
            "syn_flood_detected": self._detect_syn_flood(packet) if tcp.flags.S and not tcp.flags.A else False,
            "fin_scan_detected": self._detect_fin_scan(packet) if tcp.flags.F and not tcp.flags.A else False,
            "rst_attack_detected": self._detect_rst_attack(packet) if tcp.flags.R else False,
            "syn_ack_anomaly_detected": self._detect_syn_ack_anomaly(packet) if tcp.flags.S and tcp.flags.A else False,
            "suspicious_port_detected": self._check_suspicious_port(tcp.dport),
            # seq_anomaly and window_anomaly return dicts, so they are not simple booleans to flatten directly
            # behavior_anomaly also returns a dict
        }
        
        # Add more complex analysis results that are dictionaries
        seq_analysis_result = self._analyze_sequence(packet)
        window_analysis_result = self._analyze_window(packet)
        behavior_analysis_result = self._analyze_tcp_behavior(packet)

        # Refined TCP data payload (Task 7)
        refined_tcp_data = {
            "id": f"tcp_{datetime.utcnow().timestamp()}_{ip.src if ip else 'unknown'}_{tcp.sport}_{ip.dst if ip else 'unknown'}_{tcp.dport}",
            "timestamp": tcp_data["timestamp"],
            "source_ip": tcp_data["source_ip"],
            "destination_ip": tcp_data["destination_ip"],
            "source_port": tcp_data["source_port"],
            "destination_port": tcp_data["destination_port"],
            "protocol": "TCP",
            "length": len(packet), # Overall packet length
            "flags": tcp_data["flags"], # Dictionary of flags
            "window_size": tcp_data["window_size"],
            "seq_num": tcp_data["seq_num"],
            "ack_num": tcp_data["ack_num"],
            "tcp_payload_size": tcp_data["payload_size"], # Renamed for clarity vs overall packet length
            "payload_preview": (bytes(tcp.payload)[:16].hex() if tcp.payload else None),
            "payload_entropy": self._calculate_entropy(bytes(tcp.payload) if tcp.payload else b""),
            **threat_indicators, # Flatten simple boolean indicators
            "sequence_analysis": seq_analysis_result, # Nested dict for complex analysis
            "window_analysis": window_analysis_result,   # Nested dict
            "behavioral_analysis_tcp": behavior_analysis_result # Nested dict
        }

        # Protocol Specific Checks
        if tcp.dport == 22 or tcp.sport == 22:
            self._analyze_ssh(packet)
        elif tcp.dport == 3389 or tcp.sport == 3389:
            self._analyze_rdp(packet)

        # Emit TCP event
        try:
            self.sio_queue.put_nowait(("tcp_activity", refined_tcp_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: tcp_activity")
        except Exception as e: 
            logger.error(f"Error sending tcp activity: { e}")

    def _analyze_udp(self, packet: Packet):
        """Comprehensive UDP traffic analysis"""
        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]
        ip = packet[IP] if packet.haslayer(IP) else None

        udp_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip.src if ip else None,
            "destination_ip": ip.dst if ip else None,
            "source_port": udp.sport,
            "destination_port": udp.dport,
            "length": udp.len, # This is UDP header + payload length
            "udp_payload_size": len(udp.payload) if udp.payload else 0, # Renamed for clarity
            # threat_indicators will be flattened
        }

        # DNS Analysis is handled by _analyze_dns which is called if port is 53
        if udp.dport == 53 or udp.sport == 53:
            # _analyze_dns already sends its own specific "dns_activity" event
            return

        # Threat indicators for non-DNS UDP
        threat_indicators = {
            "ntp_amplification_detected": self._detect_ntp_amplification(packet) if udp.dport == 123 else False,
            "udp_flood_detected": self._detect_udp_flood(packet),
            "suspicious_port_detected": self._check_suspicious_port(udp.dport),
        }
        # _analyze_udp_payload returns a dict, keep it nested or flatten parts of it
        payload_analysis_results = self._analyze_udp_payload(packet)

        refined_udp_data = {
            "id": f"udp_{datetime.utcnow().timestamp()}_{ip.src if ip else 'unknown'}_{udp.sport}_{ip.dst if ip else 'unknown'}_{udp.dport}",
            "timestamp": udp_data["timestamp"],
            "source_ip": udp_data["source_ip"],
            "destination_ip": udp_data["destination_ip"],
            "source_port": udp_data["source_port"],
            "destination_port": udp_data["destination_port"],
            "protocol": "UDP",
            "length": udp_data["length"], # UDP header + payload length
            "udp_payload_size": udp_data["udp_payload_size"],
            "payload_preview": (bytes(udp.payload)[:16].hex() if udp.payload else None),
            "payload_entropy": self._calculate_entropy(bytes(udp.payload) if udp.payload else b""),
            **threat_indicators, # Flatten simple boolean indicators
            "udp_payload_analysis_details": payload_analysis_results # Nested dict for payload specifics
        }

        try:
            self.sio_queue.put_nowait(("udp_activity", refined_udp_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: udp_activity")

    def _analyze_icmp(self, packet: Packet):
        """ICMP traffic analysis with attack detection"""
        if not packet.haslayer(ICMP):
            return

        icmp = packet[ICMP]
        ip = packet[IP] if packet.haslayer(IP) else None

        icmp_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip.src if ip else None,
            "destination_ip": ip.dst if ip else None,
            "type": icmp.type,
            "code": icmp.code,
            "icmp_payload_size": len(icmp.payload) if icmp.payload else 0, # Renamed for clarity
            # threat_indicators will be flattened
        }

        threat_indicators = {
            "ping_flood_detected": self._detect_ping_flood(packet) if icmp.type == 8 else False,
            "ping_of_death_detected": self._detect_ping_of_death(packet) if icmp.type == 8 else False,
            "icmp_redirect_detected": True if icmp.type == 5 else False,
            "timestamp_probe_detected": True if icmp.type == 13 or icmp.type == 14 else False,
        }
        
        refined_icmp_data = {
            "id": f"icmp_{datetime.utcnow().timestamp()}_{ip.src if ip else 'unknown'}_{ip.dst if ip else 'unknown'}_{icmp.type}_{icmp.code}",
            "timestamp": icmp_data["timestamp"],
            "source_ip": icmp_data["source_ip"],
            "destination_ip": icmp_data["destination_ip"],
            "protocol": "ICMP",
            "icmp_type": icmp_data["type"],
            "icmp_code": icmp_data["code"],
            "icmp_payload_size": icmp_data["icmp_payload_size"],
            "payload_preview": (bytes(icmp.payload)[:16].hex() if icmp.payload else None),
            "payload_entropy": self._calculate_entropy(bytes(icmp.payload) if icmp.payload else b""),
            **threat_indicators
        }
        try:
            self.sio_queue.put_nowait(("icmp_activity", refined_icmp_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: icmp_activity")

    def _analyze_arp(self, packet: Packet):
        """ARP traffic analysis for spoofing detection"""
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        ether = packet[Ether] if packet.haslayer(Ether) else None

        arp_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": "reply" if arp.op == 2 else "request",
            "sender_ip": arp.psrc,
            "sender_mac": arp.hwsrc,
            "target_ip": arp.pdst,
            "target_mac": arp.hwdst,
            # threat_indicators will be flattened
        }

        threat_indicators = {
            "arp_spoofing_detected": self._detect_arp_spoofing(packet) if arp.op == 2 else False,
            "gratuitous_arp_detected": (arp.psrc == arp.pdst and arp.op == 2),
            "mac_spoofing_detected": (ether and arp.hwsrc != ether.src) if ether else False,
        }

        refined_arp_data = {
            "id": f"arp_{datetime.utcnow().timestamp()}_{arp.psrc}_{arp.pdst}_{arp.op}",
            "timestamp": arp_data["timestamp"],
            "protocol": "ARP",
            "operation": arp_data["operation"],
            "sender_ip": arp_data["sender_ip"],
            "sender_mac": arp_data["sender_mac"],
            "target_ip": arp_data["target_ip"],
            "target_mac": arp_data["target_mac"],
            **threat_indicators
        }
        try:
            self.sio_queue.put_nowait(("arp_activity", refined_arp_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: arp_activity")

    def _analyze_payload(self, packet: Packet):
        """Advanced payload analysis for exploit detection"""
        payload_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
            "destination_ip": packet[IP].dst if packet.haslayer(IP) else None,
            "protocol": self._get_protocol_name(packet), # This helps identify context
            "payload_size": len(packet.payload) if packet.payload else 0, # Size of the specific layer's payload being analyzed
            # threat_indicators will be flattened
        }
        
        raw_payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b"" # Prefer Raw layer for general payload

        threat_indicators = {
            "shellcode_detected": self._detect_shellcode(raw_payload),
            "sql_injection_detected": self._detect_sql_injection(raw_payload),
            "xss_detected": self._detect_xss(raw_payload),
            "exploit_kit_pattern_detected": self._detect_exploit_kit_patterns(raw_payload),
            "obfuscation_detected": self._detect_obfuscation(raw_payload),
            "high_entropy_detected": (self._calculate_entropy(raw_payload) > 7.0) if raw_payload else False,
        }

        refined_payload_data = {
            "id": f"payload_{datetime.utcnow().timestamp()}_{payload_data.get('source_ip', 'unknown')}_{payload_data.get('protocol', 'unknown')}",
            "timestamp": payload_data["timestamp"],
            "source_ip": payload_data["source_ip"],
            "destination_ip": payload_data["destination_ip"],
            "protocol": payload_data["protocol"],
            "actual_payload_size": len(raw_payload), # More specific naming
            "payload_preview": raw_payload[:16].hex() if raw_payload else None,
            "entropy": self._calculate_entropy(raw_payload),
            **threat_indicators
        }

        try:
            self.sio_queue.put_nowait(("payload_analysis", refined_payload_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: payload_analysis")

    def _analyze_behavior(self, packet: Packet):
        """Behavioral analysis across protocols"""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        # Update flow tracking
        flow_key = self._get_flow_key(packet)
        current_time = time.time()

        with self.data_lock:
            if flow_key not in self.stats["flows"]:
                self.stats["flows"][flow_key] = {
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "packet_count": 1,
                    "byte_count": len(packet),
                    "direction": (
                        "outbound" if ip.src == self.current_packet_source else "inbound"
                    ),
                }
            else:
                self.stats["flows"][flow_key].update(
                    {
                        "last_seen": current_time,
                        "packet_count": self.stats["flows"][flow_key]["packet_count"] + 1,
                        "byte_count": self.stats["flows"][flow_key]["byte_count"]
                        + len(packet),
                    }
                )

        # Behavioral Analysis Data
        behavior_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "flow_id": hash(flow_key),
            "duration": current_time - self.stats["flows"][flow_key]["first_seen"],
            "packet_count": self.stats["flows"][flow_key]["packet_count"],
            "byte_count": self.stats["flows"][flow_key]["byte_count"],
            # threat_indicators will be flattened
        }

        threat_indicators = {
            "port_scan_detected": self._detect_port_scan_behavior(ip.src),
            "dos_attempt_detected": self._detect_dos_behavior(ip.src),
            # "beaconing_detected": self._detect_beaconing(ip.src), # Removed: _detect_beaconing expects http_data. Add if a generic IP-based version is created.
            "data_exfiltration_detected": self._detect_exfiltration_behavior(ip.src),
        }
        # Beaconing detection is complex and usually context-specific (e.g., HTTP).
        # If a generic IP-based beaconing is needed, a separate, simpler helper would be appropriate.

        refined_behavior_data = {
            "id": f"behavior_{datetime.utcnow().timestamp()}_{ip.src}_{ip.dst}_{behavior_data.get('flow_id', 'unknown_flow')}",
            "timestamp": behavior_data["timestamp"],
            "source_ip": behavior_data["source_ip"],
            "destination_ip": behavior_data["destination_ip"],
            "flow_id": behavior_data["flow_id"],
            "duration_seconds": behavior_data["duration"],
            "packet_count_in_flow": behavior_data["packet_count"],
            "byte_count_in_flow": behavior_data["byte_count"],
            **threat_indicators
        }
        try:
            self.sio_queue.put_nowait(("behavior_analysis", refined_behavior_data))
        except Full:
            logger.warning("sio_queue is full. Dropping event: behavior_analysis")

    def register_http_listener(self, fn: Callable[[Dict], bool]):
        """
        Register a callback that returns False if it wants to block the packet,
        or True to let it through / continue processing.
        """
        self._http_listeners.append(fn)

    @staticmethod
    def get_model_fields(model):
        """Safely get column names from SQLAlchemy model"""
        try:
            return [c.key for c in inspect(model).mapper.column_attrs]
        except Exception as e:
            logger.error("Model inspection failed: %s", str(e))
            return []

    def _detect_syn_flood(self, packet: Packet) -> bool:
        """Detect SYN flood attacks using adaptive rate limiting."""
        if not packet.haslayer(TCP) or not packet[TCP].flags.S:
            return False

        src_ip = packet[IP].src
        now = time.time()

        # Track SYN packets with sliding window
        with self.data_lock:
            syn_tracker = self.recent_packets.setdefault(src_ip, {
                'syn_times': deque(maxlen=1000),
                'syn_ack_count': 0
            })

            syn_tracker['syn_times'].append(now)

        # Calculate SYN rate (packets/second)
        window = 2  # Second window
        syn_count = sum(1 for t in syn_tracker['syn_times'] if now - t <= window)

        # Dynamic threshold based on network baseline
        threshold = self.rate_limiter.get_threshold('syn', default=500)
        return syn_count > threshold

    def _detect_fin_scan(self, packet: Packet) -> bool:
        """Detect FIN scans (stealth scanning techniques)."""
        if packet.haslayer(TCP) and packet[TCP].flags.F and not packet[TCP].flags.A:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            with self.data_lock:
                fin_targets = self.recent_packets.setdefault(src_ip, {
                    'fin_ports': set(),
                    'fin_times': deque(maxlen=100)
                })

                fin_targets['fin_ports'].add(dst_port)
                fin_targets['fin_times'].append(time.time())

                # Detect if scanning multiple ports
                return len(fin_targets['fin_ports']) > 10 and \
                    (fin_targets['fin_times'][-1] - fin_targets['fin_times'][0]) < 5
        return False

    def _detect_rst_attack(self, packet: Packet) -> bool:
        """Detect TCP RST injection attacks."""
        if packet.haslayer(TCP) and packet[TCP].flags.R:
            src_ip = packet[IP].src
            with self.data_lock:
                self.recent_packets.setdefault(src_ip, {'rst_count': 0})['rst_count'] += 1
                return self.recent_packets[src_ip]['rst_count'] > 50  # Threshold
        return False

    def _detect_syn_ack_anomaly(self, packet: Packet) -> bool:
        """Detect unexpected SYN-ACK responses."""
        if packet.haslayer(TCP) and packet[TCP].flags.SA:
            src_ip = packet[IP].src
            with self.data_lock:
                syn_cache = self.recent_packets.setdefault(src_ip, {'syn_sent': set()})
                dst_port = packet[TCP].sport
                # Check if we saw SYN to this port first
                return dst_port not in syn_cache['syn_sent']
        return False

    def _check_suspicious_port(self, port: int) -> bool:
        """Identify high-risk ports with threat intelligence feed."""
        suspicious_ports = {
            # Hidden Tor ports
            9001, 9030, 9150,  
            # Cryptominer ports
            3333, 4444, 5555, 6666,
            # Malware ports
            7626, 2745, 3127, 6129,
            # Database exploits
            1433, 1434, 3306, 5432
        }
        return port in suspicious_ports or port in KNOWN_SERVICES.get('malicious', [])

    def _analyze_sequence(self, packet: Packet) -> dict:
        """Detect TCP sequence prediction attacks."""
        tcp = packet[TCP]
        seq_analysis = {
            'predictable': False,
            'delta': 0,
            'anomaly_score': 0.0
        }

        src_ip = packet[IP].src
        with self.data_lock:
            seq_history = self.recent_packets.setdefault(src_ip, {
                'last_seq': None,
                'sequence_deltas': []
            })

            if seq_history['last_seq']:
                delta = abs(tcp.seq - seq_history['last_seq'])
                seq_history['sequence_deltas'].append(delta)

                # Check for predictable increments
                if len(seq_history['sequence_deltas']) > 10:
                    std_dev = np.std(seq_history['sequence_deltas'][-10:])
                    seq_analysis['anomaly_score'] = 1 - min(std_dev / 10000, 1.0)
                    seq_analysis['predictable'] = std_dev < 1000  # Static increment threshold

            seq_history['last_seq'] = tcp.seq

        return seq_analysis

    def _analyze_window(self, packet: Packet) -> dict:
        """Detect window size manipulation attempts."""
        tcp = packet[TCP]
        window_analysis = {
            'zero_window': tcp.window == 0,
            'small_window': tcp.window < 64,
            'unusual_scaling': False
        }

        # Check for window scaling anomalies
        if packet.haslayer(TCP):
            options = dict(packet[TCP].options)  # Convert to dict for easier lookup
            if 'WScale' in options:
                window_analysis['unusual_scaling'] = options['WScale'] > 10
        return window_analysis

    def _analyze_tcp_behavior(self, packet: Packet) -> dict:
        """Detect advanced TCP behavior anomalies."""
        behavior = {
            'retransmission_ratio': 0.0,
            'persist_probes': 0,
            'half_open': False
        }

        src_ip = packet[IP].src
        with self.data_lock:
            tcp_stats = self.recent_packets.setdefault(src_ip, {
                'retransmits': 0,
                'total_packets': 0,
                'syn_count': 0
            })

            tcp_stats['total_packets'] += 1
            if packet[TCP].flags.R:
                tcp_stats['retransmits'] += 1

            behavior['retransmission_ratio'] = tcp_stats['retransmits'] / tcp_stats['total_packets']
            behavior['half_open'] = tcp_stats['syn_count'] > 10 and \
                                tcp_stats['syn_count'] / tcp_stats['total_packets'] > 0.8

        return behavior

    def _detect_ntp_amplification(self, packet: Packet) -> bool:
        """Detect NTP amplification attack attempts."""
        if packet.haslayer(UDP) and packet[UDP].dport == 123:
            payload = bytes(packet[UDP].payload)
            # Check for monlist request (NTP mode 7)
            return len(payload) >= 4 and payload[0] & 0x07 == 0x07 and \
                len(payload) == 48  # Typical monlist request size
        return False

    def _detect_udp_flood(self, packet: Packet) -> bool:
        """Detect UDP flood attacks with adaptive thresholds."""
        if not packet.haslayer(UDP):
            return False

        src_ip = packet[IP].src
        now = time.time()

        with self.data_lock:
            flood_tracker = self.recent_packets.setdefault(src_ip, {
                'udp_times': deque(maxlen=5000),
                'udp_sizes': deque(maxlen=5000)
            })

            flood_tracker['udp_times'].append(now)
            flood_tracker['udp_sizes'].append(len(packet))

        # Calculate bandwidth and PPS
        window = 1  # Second
        recent = [t for t in flood_tracker['udp_times'] if now - t <= window]
        total_bytes = sum(flood_tracker['udp_sizes'][-len(recent):])

        return len(recent) > 1000 or total_bytes > 1000000  # 1Mbps or 1000pps

    def _analyze_udp_payload(self, packet: Packet) -> dict:
        """Analyze UDP payload for tunneling and exploits."""
        payload = bytes(packet[UDP].payload) if packet.haslayer(UDP) else b''
        analysis = {
            'dns_tunneling': False,
            'entropy': self._calculate_entropy(payload),
            'hex_pattern': False
        }

        # Detect DNS tunneling (hex-encoded subdomains)
        if packet.haslayer(DNS) and len(payload) > 512:
            analysis['dns_tunneling'] = any(
                re.match(r'^[0-9a-f]{16,}\.', q.qname.decode(errors='ignore'))
                for q in packet[DNS].qd
            )

        # Detect hex-encoded payload patterns
        analysis['hex_pattern'] = bool(re.search(rb'[0-9a-fA-F]{32,}', payload))

        return analysis

    def _detect_ping_flood(self, packet: Packet) -> bool:
        """Detect ICMP echo request floods."""
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            src_ip = packet[IP].src
            with self.data_lock:
                self.recent_packets.setdefault(src_ip, {'icmp_count': 0})['icmp_count'] += 1
                return self.recent_packets[src_ip]['icmp_count'] > 100  # 100 pps
        return False

    def _detect_ping_of_death(self, packet: Packet) -> bool:
        """Detect oversized ICMP packets."""
        if packet.haslayer(ICMP) and len(packet) > 65535:
            return True
        return False

    def _detect_arp_spoofing(self, packet: Packet) -> bool:
        """Detect ARP poisoning attacks."""
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            with self.data_lock:
                arp_table = self.recent_packets.setdefault('arp_table', {})
                if src_ip in arp_table:
                    return arp_table[src_ip] != src_mac  # MAC changed
                arp_table[src_ip] = src_mac

            # Check for multiple IPs mapping to same MAC
            mac_count = sum(1 for ip, mac in arp_table.items() if mac == src_mac)
            return mac_count > 3

    def _detect_shellcode(self, payload: bytes) -> bool:
        """Detect common shellcode patterns."""
        shellcode_patterns = [
            rb'\x90{16}',  # NOP sled
            rb'\xcc{4}',    # INT3 breakpoints
            rb'\x68....\x68',  # PUSH sequences
            rb'\xeb\xff....\x0f'  # JMP-CALL-POP
        ]
        return any(re.search(p, payload) for p in shellcode_patterns)

    def _detect_sql_injection(self, payload: bytes) -> bool:
        """Detect SQL injection patterns with improved accuracy."""
        patterns = [
            rb"'\s+OR\s+'\d'='d",
            rb"UNION\s+ALL\s+SELECT",
            rb"WAITFOR\s+DELAY\s+'0:0:\d+",
            rb"EXEC\(0x[0-9a-f]+\)",
            rb"information_schema\.tables"
        ]
        normalized = payload.lower().replace(b' ', b'').replace(b'\t', b'')
        return any(re.search(p, normalized) for p in patterns)

    def _detect_xss(self, payload: bytes) -> bool:
        """Detect cross-site scripting attempts."""
        xss_patterns = [
            rb"<script>[^<]*</script>",
            rb"javascript:\w+\([^)]*\)",
            rb"on\w+=\s*[\"']?[^\"'>]+",
            rb"alert\([^)]*\)"
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in xss_patterns)

    def _detect_exploit_kit_patterns(self, payload: bytes) -> bool:
        """Detect known exploit kit signatures."""
        ek_patterns = [
            rb"\/CWS[\x09-\x0d]",  # Angler EK
            rb"\/[a-z0-9]{8}\/",    # Rig EK
            rb"\/[a-z]{4}\.php\?[a-z]="  # Neutrino EK
        ]
        return any(re.search(p, payload) for p in ek_patterns)

    def _detect_obfuscation(self, payload: bytes) -> bool:
        """Detect obfuscated code patterns."""
        return (
            self._calculate_entropy(payload) > 7.5 or
            bool(re.search(rb'\\x[0-9a-f]{2}', payload)) or
            bool(re.search(rb'%[0-9a-f]{2}', payload)) or
            bool(re.search(rb'(?:[A-Za-z0-9+/]{4}){10,}', payload))  # Base64
        )

    def _detect_port_scan_behavior(self, src_ip: str) -> bool:
        """Detect horizontal port scanning patterns."""
        with self.data_lock:
            targets = self.recent_packets.get(src_ip, {}).get('dst_ports', set())
            return len(targets) > 50 and len(targets) / len(self.recent_packets[src_ip].get('packets', 1)) > 0.8

    def _detect_dos_behavior(self, src_ip: str) -> bool:
        """Detect DoS behavior through multiple vectors."""
        with self.data_lock:
            stats = self.recent_packets.get(src_ip, {})
            return (
                stats.get('packet_rate', 0) > 1000 or  # Packets/second
                stats.get('error_rate', 0) > 0.5 or     # Error ratio
                stats.get('unique_ports', 0) > 100      # Port randomization
            )

    def _detect_exfiltration_behavior(self, src_ip: str) -> bool:
        """Detect data exfiltration patterns."""
        with self.data_lock:
            stats = self.recent_packets.get(src_ip, {})
            return (
                stats.get('outbound_bytes', 0) > 100e6 or  # 100MB
                stats.get('dns_queries', 0) > 1000 or
                stats.get('uncommon_protocol_ratio', 0) > 0.8
            )

    def _analyze_rdp(self, packet: Packet):
        """Advanced RDP protocol analysis with exploit detection"""
        if not packet.haslayer(TCP) or packet[TCP].dport != 3389:
            return

        ip = packet[IP]
        tcp = packet[TCP]
        rdp_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "threat_indicators": {
                "bruteforce": False,
                "bluekeep_exploit": False,
                "credential_stuffing": False,
                "weak_encryption": False
            },
            "protocol_state": {
                "ssl_negotiation": False,
                "connection_sequence": 0,
                "auth_attempts": 0
            }
        }

        try:
            # Track RDP connection attempts
            with self.data_lock:
                rdp_tracker = self.recent_packets.setdefault(ip.src, {
                    'rdp_attempts': deque(maxlen=20),
                    'auth_failures': 0,
                    'last_attempt': 0
                })

                rdp_tracker['rdp_attempts'].append(time.time())
                current_window = [t for t in rdp_tracker['rdp_attempts'] 
                                if time.time() - t < 60]

            # Bruteforce detection
            if len(current_window) > 15:
                rdp_data["threat_indicators"]["bruteforce"] = True
                self._create_alert(
                    "RDP Bruteforce Attempt",
                    "critical",
                    ip.src,
                    f"Excessive RDP attempts ({len(current_window)}/min)"
                )

            # Analyze payload for known exploits
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                # Detect BlueKeep (CVE-2019-0708) vulnerability scan
                if len(payload) > 50 and payload[0] == 0x03 and payload[1] == 0x00:
                    if b"\x00\x08\x00\x03\x00\x00\x00" in payload[:20]:
                        rdp_data["threat_indicators"]["bluekeep_exploit"] = True
                        self._create_alert(
                            "BlueKeep Exploit Attempt",
                            "critical",
                            ip.src,
                            "CVE-2019-0708 exploitation detected"
                        )

                # Detect credential stuffing patterns
                if b"\x02\x00\x08\x00" in payload and b"\x04\x00\x08\x00" in payload:
                    rdp_data["threat_indicators"]["credential_stuffing"] = True
                    rdp_data["protocol_state"]["auth_attempts"] += 1

                # Check encryption negotiation
                if b"\x00\x03\x00\x0b" in payload[:10]:
                    rdp_data["protocol_state"]["ssl_negotiation"] = True
                    if b"\x00\x01\x00" in payload[10:20]:
                        rdp_data["threat_indicators"]["weak_encryption"] = True

            # Behavioral analysis
            if rdp_data["protocol_state"]["auth_attempts"] > 5:
                with self.data_lock:
                    rdp_tracker['auth_failures'] += 1
                    if rdp_tracker['auth_failures'] > 10:
                        self.firewall.block_ip(ip.src, "RDP brute force", 3600)
                        try:
                            self.sio_queue.put_nowait(("firewall_block", {
                                "ip": ip.src,
                                "reason": "RDP brute force",
                                "duration": 3600
                            }))
                        except Full:
                            logger.warning("sio_queue is full. Dropping event: firewall_block (RDP brute force)")
            try:
                self.sio_queue.put_nowait(("rdp_activity", rdp_data))
            except Full:
                logger.warning("sio_queue is full. Dropping event: rdp_activity")

        except Exception as e:
            logger.error(f"RDP analysis failed: {str(e)}", exc_info=True)
            try:
                self.sio_queue.put_nowait(('system_error', {
                    'component': 'rdp_analysis',
                    'error': str(e),
                    'packet_summary': packet.summary()
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: system_error (rdp_analysis)")

    def _extract_payload(self, packet: Packet) -> dict:
        """Safely extract and analyze payload from multiple layers with protocol awareness"""
        payload_info = {
            "raw": b"",
            "hex": "",
            "entropy": 0.0,
            "printable_ratio": 0.0,
            "mime_type": "unknown",
            "obfuscated": False,
            "layers": []
        }

        try:
            # Extract payload from all possible layers
            payload_layers = [Raw, TCP, UDP, ICMP]
            for layer in payload_layers:
                if packet.haslayer(layer):
                    layer_payload = bytes(packet[layer].payload)
                    if layer_payload:
                        payload_info["raw"] += layer_payload
                        payload_info["layers"].append(layer.__name__)

            if not payload_info["raw"]:
                return payload_info

            # Calculate metrics
            payload_info["hex"] = payload_info["raw"].hex()
            payload_info["entropy"] = self._calculate_entropy(payload_info["raw"])

            # Detect printable characters
            printable_chars = sum(32 <= c < 127 for c in payload_info["raw"])
            payload_info["printable_ratio"] = printable_chars / len(payload_info["raw"])

            # Detect obfuscation
            payload_info["obfuscated"] = self._detect_obfuscation(payload_info["raw"])

            # MIME type detection
            payload_info["mime_type"] = self._detect_mime_type(payload_info["raw"])

            # Update byte distribution (thread-safe)
            if payload_info["raw"]:
                with self.data_lock:
                    arr = np.frombuffer(payload_info["raw"], dtype=np.uint8)
                    counts = np.bincount(arr, minlength=256)
                    for i, c in enumerate(counts):
                        self.byte_distribution[i] += int(c)

        except Exception as e:
            logger.debug(f"Payload extraction error: {str(e)}")
            try:
                self.sio_queue.put_nowait(('system_error', {
                    'component': 'payload_extractor',
                    'error': str(e),
                    'packet_summary': packet.summary()[:100] if packet else None
                }))
            except Full:
                logger.warning("sio_queue is full. Dropping event: system_error (payload_extractor)")

        return payload_info

    def _detect_mime_type(self, payload: bytes) -> str:
        """Detect MIME type using magic numbers and heuristics"""
        if len(payload) < 4:
            return "unknown"

        magic_numbers = {
            b"\x25PDF": "application/pdf",
            b"\x50\x4B\x03\x04": "application/zip",
            b"\x89PNG": "image/png",
            b"\xFF\xD8\xFF": "image/jpeg",
            b"\x47\x49\x46": "image/gif",
        }

        for magic, mime in magic_numbers.items():
            if payload.startswith(magic):
                return mime

        # Fallback to text detection
        try:
            payload.decode('utf-8')
            return "text/plain" if self._is_human_readable(payload) else "text/encoded"
        except UnicodeDecodeError:
            return "application/octet-stream"

    def _is_human_readable(self, payload: bytes) -> bool:
        """Determine if payload contains mostly readable text"""
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x7F)) | {0x09, 0x0A})
        return all(c in text_chars for c in payload[:1024])