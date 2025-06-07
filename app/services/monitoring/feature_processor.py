import time
import hashlib
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
import logging
from dataclasses import dataclass, field
import statistics
from collections import OrderedDict
import csv
import json
import os
import traceback
import threading
from multiprocessing import Queue
import multiprocessing
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
    wrpcap,
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import IPv6ExtHdrFragment
from scapy.packet import Packet
from statistics import mean, stdev

logger = logging.getLogger(__name__)
# Top 40 selected features (in training)


# -----------------------------------------------------------------------------
# Module-level Feature Definition (shared by all processors)
# -----------------------------------------------------------------------------
EXPECTED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Length of Fwd Packets',
    'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Bwd Segment Size', 'Subflow Fwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]


def new_deque():
    return deque()


def default_int():
    return defaultdict(int)

ACTIVE_IDLE_THRESHOLD = 1.0 

@dataclass
class FlowKey:
    """Unique identifier for network flows"""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __hash__(self):
        return hash(
            (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        )


@dataclass
class PacketMetrics:
    """Individual packet metrics"""

    size: int
    payload_size: int
    pkt: Packet
    header_size: int
    timestamp: float = field(default_factory=time.time)
    flags: str = ""
    tcp_window_size: int = 0
    tcp_urgent_ptr: int = 0
    tcp_options_len: int = 0
    ip_ttl: int = 0
    ip_flags: int = 0
    ip_fragment_offset: int = 0
    icmp_type: int = -1
    icmp_code: int = -1


@dataclass
class FlowStatistics:
    """Comprehensive flow statistics"""

    # Basic flow info
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    duration: float = 0.0
    unique_dest_ips: Set[str] = field(default_factory=set)
    protocols_seen: Set[int] = field(default_factory=set)
    last_forward_time: Optional[float] = None
    last_backward_time: Optional[float] = None
    # Packet counts
    total_packets: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    payload_lengths: List[int] = field(default_factory=list)
    # Size statistics
    total_length_forward: int = 0
    total_length_backward: int = 0
    forward_packet_lengths: List[int] = field(default_factory=list)
    backward_packet_lengths: List[int] = field(default_factory=list)

    # Header lengths
    forward_header_lengths: List[int] = field(default_factory=list)
    backward_header_lengths: List[int] = field(default_factory=list)
    backward_psh_flags: int = 0
    backward_urg_flags: int = 0
    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int = 0
    init_win_forward: Optional[int] = None
    init_win_backward: Optional[int] = None

    # Timing statistics
    forward_iat: List[float] = field(default_factory=list)  # Inter-arrival times
    backward_iat: List[float] = field(default_factory=list)
    flow_iat: List[float] = field(default_factory=list)

    # TCP-specific
    tcp_flags_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    syn_flag_count: int = 0
    cwe_flag_count: int = 0  # CWR, ECE, URG flags
    tcp_window_size: int = 0
    tcp_urgent_pointer: int = 0
    tcp_sequence_number: int = 0
    tcp_acknowledgment_number: int = 0
    tcp_reserved_bits: int = 0
    tcp_checksum: int = 0
    tcp_options_count: int = 0
    packets: List[Any] = field(default_factory=list)  # List[scapy.Packet]
    # Active/Idle time tracking
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)
    last_activity: float = field(default_factory=time.time)

    # Advanced metrics
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # CICFlowMeter Feature Set Additions
    packet_length_min: float = 0.0
    packet_length_max: float = 0.0
    packet_length_mean: float = 0.0
    packet_length_std: float = 0.0
    packet_length_variance: float = 0.0
    ece_flag_count: int = 0  # Distinct from cwe_flag_count for ECE flag

    # Bulk transfer characteristics
    bulk_duration_forward: float = 0.0
    bulk_duration_backward: float = 0.0
    bulk_packet_count_forward: int = 0
    bulk_packet_count_backward: int = 0
    bulk_size_avg_forward: float = 0.0  # Corresponds to Fwd_Byts_Blk_Avg
    bulk_size_avg_backward: float = 0.0  # Corresponds to Bwd_Byts_Blk_Avg
    fwd_bytes_bulk_avg: float = 0.0  # Explicitly adding based on FlowFeature.java
    fwd_pkt_bulk_avg: float = 0.0
    fwd_bulk_rate_avg: float = 0.0
    bwd_bytes_bulk_avg: float = 0.0
    bwd_pkt_bulk_avg: float = 0.0
    bwd_bulk_rate_avg: float = 0.0

    fwd_seg_size_min: float = 0.0  # Corresponds to Fwd Seg Size Min

    # Subflow characteristics
    subflow_forward_packets: int = 0
    subflow_forward_bytes: int = 0
    subflow_backward_packets: int = 0
    subflow_backward_bytes: int = 0
    forward_payload_lengths: List[int] = field(default_factory=list)
    backward_payload_lengths: List[int] = field(default_factory=list)
    last_flow_time: Optional[float] = None
    all_packet_lengths_temp: List[int] = field(
        default_factory=list
    )  # For overall packet length stats


class AdvancedFeatureExtractor:
    """Advanced feature extraction for network packets aligned with CICIDS datasets"""

    def __init__(self, cleanup_interval: int = 300, flow_timeout: int = 120):
        self.flows: Dict[FlowKey, FlowStatistics] = {}
        self.flow_packets: Dict[FlowKey, List[PacketMetrics]] = {}
        self.cleanup_interval = cleanup_interval
        self.flow_timeout = flow_timeout
        self.host_windows = defaultdict(new_deque)
        self.last_cleanup = time.time()

        self.lock = multiprocessing.Lock()

        # Behavioral tracking
        self.ip_behavior = defaultdict(self.default_ip_behavior)
        # Protocol detection patterns
        self.protocol_signatures = {
            "HTTP": [80, 8080, 8000, 3128],
            "HTTPS": [443, 8443, 9443],
            "FTP": [21, 20],
            "SSH": [22],
            "TELNET": [23],
            "SMTP": [25, 587, 465],
            "DNS": [53],
            "DHCP": [67, 68],
            "POP3": [110, 995],
            "IMAP": [143, 993],
            "SNMP": [161, 162],
            "LDAP": [389, 636],
            "SMB": [445, 139],
            "RDP": [3389],
            "VNC": [5900, 5901, 5902],
        }

    def _sanitize_value(self, value: Any, precision: int = 6) -> Any:
        if isinstance(value, (int, float)):
            if (
                np.isnan(value) or np.isinf(value) or not np.isfinite(value)
            ):  # Added isfinite check
                return 0.0
            if isinstance(value, float):
                return round(value, precision)
        elif isinstance(
            value,
            (
                np.int_,
                np.intc,
                np.intp,
                np.int8,
                np.int16,
                np.int32,
                np.int64,
                np.uint8,
                np.uint16,
                np.uint32,
                np.uint64,
            ),
        ):
            return int(value)
        elif isinstance(value, (np.float64, np.float16, np.float32, np.float64)):
            if np.isnan(value) or np.isinf(value) or not np.isfinite(value):
                return 0.0
            return round(float(value), precision)
        return value

    def compute_features(self, flow_key: FlowKey) -> Dict[str, Any]:
        if flow_key not in self.flows:
            logger.warning(
                f"Flow key {flow_key} not found in self.flows for feature computation."
            )
            return {}
        st = self.flows[flow_key]
        f = OrderedDict()
        micro_converter = 1_000_000.0  # Ensure float for division

        # --- Flow Identifiers (7 features) ---
        flow_id_str = f"{flow_key.src_ip}-{flow_key.src_port}-{flow_key.dst_ip}-{flow_key.dst_port}-{flow_key.protocol}"
        f["Flow ID"] = flow_id_str
        f["Src IP"] = flow_key.src_ip
        f["Source Port"] = flow_key.src_port  # Already int
        f["Dst IP"] = flow_key.dst_ip
        f["Destination Port"] = flow_key.dst_port  # Already int
        protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        f["Protocol"] = protocol_map.get(
            str(flow_key.protocol).upper(), 0
        )  # Already int
        f["Timestamp"] = datetime.fromtimestamp(st.start_time).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )

        # --- Basic Flow Features ---
        f["Flow Duration"] = (
            st.duration * micro_converter
        )  # CICFlowMeter expects microseconds
        f["Total Fwd Packet"] = st.forward_packets
        f["Total Backward Packets"] = st.backward_packets
        f["Total Length of Fwd Packets"] = float(st.total_length_forward)
        f["Total Length of Bwd Packet"] = float(st.total_length_backward)

        # --- Packet Length Statistics (Fwd & Bwd) ---
        f["Fwd Packet Length Max"] = float(
            max(st.forward_packet_lengths) if st.forward_packet_lengths else 0.0
        )
        f["Fwd Packet Length Min"] = float(
            min(st.forward_packet_lengths) if st.forward_packet_lengths else 0.0
        )
        f["Fwd Packet Length Mean"] = float(
            mean(st.forward_packet_lengths) if st.forward_packet_lengths else 0.0
        )
        f["Fwd Packet Length Std"] = float(
            stdev(st.forward_packet_lengths)
            if len(st.forward_packet_lengths) > 1
            else 0.0
        )

        f["Bwd Packet Length Max"] = float(
            max(st.backward_packet_lengths) if st.backward_packet_lengths else 0.0
        )
        f["Bwd Packet Length Min"] = float(
            min(st.backward_packet_lengths) if st.backward_packet_lengths else 0.0
        )
        f["Bwd Packet Length Mean"] = float(
            mean(st.backward_packet_lengths) if st.backward_packet_lengths else 0.0
        )
        f["Bwd Packet Length Std"] = float(
            stdev(st.backward_packet_lengths)
            if len(st.backward_packet_lengths) > 1
            else 0.0
        )

        # --- Flow Bytes/Packets per Second ---
        flow_duration_sec = st.duration  # This is in seconds
        total_bytes = float(st.total_length_forward + st.total_length_backward)
        total_flow_packets = float(st.forward_packets + st.backward_packets)

        f["Flow Bytes/s"] = (
            total_bytes / flow_duration_sec if flow_duration_sec > 0 else 0.0
        )
        f["Flow Packets/s"] = (
            total_flow_packets / flow_duration_sec if flow_duration_sec > 0 else 0.0
        )

        # --- IAT Statistics (Flow, Fwd, Bwd) - CICFlowMeter expects microseconds ---
        f["Flow IAT Mean"] = mean(st.flow_iat) * micro_converter if st.flow_iat else 0.0
        f["Flow IAT Std"] = (
            stdev(st.flow_iat) * micro_converter if len(st.flow_iat) > 1 else 0.0
        )
        f["Flow IAT Max"] = max(st.flow_iat) * micro_converter if st.flow_iat else 0.0
        f["Flow IAT Min"] = min(st.flow_iat) * micro_converter if st.flow_iat else 0.0

        f["Fwd IAT Total"]   = sum(st.forward_iat)
        f["Fwd IAT Mean"] = (
            mean(st.forward_iat) * micro_converter if st.forward_iat else 0.0
        )
        f["Fwd IAT Std"] = (
            stdev(st.forward_iat) * micro_converter if len(st.forward_iat) > 1 else 0.0
        )
        f["Fwd IAT Max"] = (
            max(st.forward_iat) * micro_converter if st.forward_iat else 0.0
        )
        f["Fwd IAT Min"] = (
            min(st.forward_iat) * micro_converter if st.forward_iat else 0.0
        )

        f["Bwd IAT Total"]   = sum(st.backward_iat)
        f["Flow IAT Total"]  = sum(st.flow_iat)
        f["Bwd IAT Mean"] = (
            mean(st.backward_iat) * micro_converter if st.backward_iat else 0.0
        )
        f["Bwd IAT Std"] = (
            stdev(st.backward_iat) * micro_converter
            if len(st.backward_iat) > 1
            else 0.0
        )
        f["Bwd IAT Max"] = (
            max(st.backward_iat) * micro_converter if st.backward_iat else 0.0
        )
        f["Bwd IAT Min"] = (
            min(st.backward_iat) * micro_converter if st.backward_iat else 0.0
        )

        # --- TCP Flags (Directional PSH/URG and Overall Counts) ---
        total_psh_flags = st.tcp_flags_counts.get("PSH", 0)
        total_urg_flags = st.tcp_flags_counts.get("URG", 0)
        f["Fwd PSH Flags"] = total_psh_flags - st.backward_psh_flags
        f["Bwd PSH Flags"] = st.backward_psh_flags
        f["Fwd URG Flags"] = total_urg_flags - st.backward_urg_flags
        f["Bwd URG Flags"] = st.backward_urg_flags

        # --- Header Lengths (Total bytes) ---
        f["Fwd Header Length"] = float(sum(st.forward_header_lengths))
        f["Bwd Header Length"] = float(sum(st.backward_header_lengths))

        # --- Packets per Second (Directional) ---
        f["Fwd Packets/s"] = (
            float(st.forward_packets) / flow_duration_sec
            if flow_duration_sec > 0
            else 0.0
        )
        f["Bwd Packets/s"] = (
            float(st.backward_packets) / flow_duration_sec
            if flow_duration_sec > 0
            else 0.0
        )

        # --- Overall Packet Length Statistics (from st object, already calculated) ---
        f["Min Packet Length"] = st.packet_length_min
        f["Max Packet Length"] = st.packet_length_max
        f["Packet Length Mean"] = st.packet_length_mean
        f["Packet Length Std"] = st.packet_length_std
        f["Packet Length Variance"] = st.packet_length_variance

        # --- TCP Flag Counts (Overall) ---
        f["FIN Flag Count"] = st.tcp_flags_counts.get("FIN", 0)
        f["SYN Flag Count"] = st.tcp_flags_counts.get(
            "SYN", 0
        )  # st.syn_flag_count is also available
        f["RST Flag Count"] = st.tcp_flags_counts.get("RST", 0)
        f["PSH Flag Count"] = total_psh_flags
        f["ACK Flag Count"] = st.tcp_flags_counts.get("ACK", 0)
        f["URG Flag Count"] = total_urg_flags
        f["CWE Flag Count"] = st.cwe_flag_count
        f["ECE Flag Count"] = st.ece_flag_count

        # --- Ratios and Segment Sizes ---
        f["Down/Up Ratio"] = (
            float(st.backward_packets) / float(st.forward_packets)
            if st.forward_packets > 0
            else 0.0
        )
        f["Average Packet Size"] = (
            total_bytes / total_flow_packets if total_flow_packets > 0 else 0.0
        )
        f["Avg Fwd Segment Size"] = (
            float(st.total_length_forward) / float(st.forward_packets)
            if st.forward_packets > 0
            else 0.0
        )
        f["Avg Bwd Segment Size"] = (
            float(st.total_length_backward) / float(st.backward_packets)
            if st.backward_packets > 0
            else 0.0
        )

        # Note: "Fwd Header Length" is listed twice in the prompt's feature list. We've included it once as sum.
        # If a duplicate is needed (e.g. "Fwd Header Length1"), it would be:
        # f["Fwd Header Length1"] = f["Fwd Header Length"]

        # --- Bulk Transfer Averages ---
        f["Fwd Avg Bytes/Bulk"] = st.fwd_bytes_bulk_avg
        f["Fwd Avg Packets/Bulk"] = st.fwd_pkt_bulk_avg
        f["Fwd Avg Bulk Rate"] = st.fwd_bulk_rate_avg
        f["Bwd Avg Bytes/Bulk"] = st.bwd_bytes_bulk_avg
        f["Bwd Avg Packets/Bulk"] = st.bwd_pkt_bulk_avg
        f["Bwd Avg Bulk Rate"] = st.bwd_bulk_rate_avg

        # --- Subflow Statistics ---
        N = 10
        f["Subflow Fwd Packets"] = min(N, len(st.forward_packet_lengths))
        f["Subflow Fwd Bytes"]   = float(sum(st.forward_packet_lengths[:N]))
        f["Subflow Bwd Packets"] = min(N, len(st.backward_packet_lengths))
        f["Subflow Bwd Bytes"]   = float(sum(st.backward_packet_lengths[:N]))

        # --- Initial Window Bytes ---
        f["Init_Win_bytes_forward"] = float(
            st.init_win_forward if st.init_win_forward is not None else 0
        )
        f["Init_Win_bytes_backward"] = float(
            st.init_win_backward if st.init_win_backward is not None else 0
        )

        f["Fwd Act Data Pkts"] = st.act_data_pkt_fwd
        f["Fwd Seg Size Min"] = (
            st.fwd_seg_size_min
        )  # This is already float from FlowStatistics

        # --- Active/Idle Time Statistics (convert to microseconds) ---
        # f["Active Mean"] = (
        #     mean(st.active_times) * micro_converter if st.active_times else 0.0
        # )
        # f["Active Std"] = (
        #     stdev(st.active_times) * micro_converter
        #     if len(st.active_times) > 1
        #     else 0.0
        # )
        # f["Active Max"] = (
        #     max(st.active_times) * micro_converter if st.active_times else 0.0
        # )
        # f["Active Min"] = (
        #     min(st.active_times) * micro_converter if st.active_times else 0.0
        # )

        # f["Idle Mean"] = mean(st.idle_times) * micro_converter if st.idle_times else 0.0
        # f["Idle Std"] = (
        #     stdev(st.idle_times) * micro_converter if len(st.idle_times) > 1 else 0.0
        # )
        # f["Idle Max"] = max(st.idle_times) * micro_converter if st.idle_times else 0.0
        # f["Idle Min"] = min(st.idle_times) * micro_converter if st.idle_times else 0.0

        # Active / Idle summaries
        if st.active_times:
            f["Active Mean"] = statistics.mean(st.active_times)
            f["Active Std"]  = statistics.stdev(st.active_times) if len(st.active_times)>1 else 0.0
            f["Active Max"]  = max(st.active_times)
            f["Active Min"]  = min(st.active_times)
        else:
            f["Active Mean"] = f["Active Std"] = f["Active Max"] = f["Active Min"] = 0.0

        if st.idle_times:
            f["Idle Mean"]   = statistics.mean(st.idle_times)
            f["Idle Std"]    = statistics.stdev(st.idle_times) if len(st.idle_times)>1 else 0.0
            f["Idle Max"]    = max(st.idle_times)
            f["Idle Min"]    = min(st.idle_times)
        else:
            f["Idle Mean"] = f["Idle Std"] = f["Idle Max"] = f["Idle Min"] = 0.0

        f["Label"] = "BENIGN"

        # Final sanitization pass for all feature values
        for key_f in f:
            f[key_f] = self._sanitize_value(f[key_f])

        # Forward bulk
        f_avg_pkts, f_avg_bytes, f_avg_dur = self._compute_bulk_metrics(
            st.forward_iat,
            st.forward_payload_lengths
        )
        # Backward bulk
        b_avg_pkts, b_avg_bytes, b_avg_dur = self._compute_bulk_metrics(
            st.backward_iat,
            st.backward_payload_lengths
        )

        f.update({
            "Fwd Avg Packets/Bulk": float(f_avg_pkts),
            "Fwd Avg Bytes/Bulk":   float(f_avg_bytes),
            "Fwd Avg Bulk Rate":    f_avg_bytes / f_avg_dur if f_avg_dur>0 else 0.0,
            "Bwd Avg Packets/Bulk": float(b_avg_pkts),
            "Bwd Avg Bytes/Bulk":   float(b_avg_bytes),
            "Bwd Avg Bulk Rate":    b_avg_bytes / b_avg_dur if b_avg_dur>0 else 0.0,
        })
        # Only keep expected features in the final dictionary
        f = {k: f[k] for k in EXPECTED_FEATURES if k in f}

        return f

    def _compute_bulk_metrics(self, iat_list: List[float], payload_list: List[int]):
        """
        Detect contiguous 'bulk' runs: sequences of >=4 packets
        with inter-arrival <= ACTIVE_IDLE_THRESHOLD.
        Returns (avg_pkts, avg_bytes, avg_duration_sec).
        """
        # 1. Validate input lengths
        n_iat = len(iat_list)
        n_payload = len(payload_list)
        # Need at least 4 packets to form a bulk -> at least 3 IATs
        if n_payload < 4 or n_iat + 1 != n_payload:
            # Cannot compute bulks reliably
            return 0.0, 0.0, 0.0

        bulks = []
        run_start_time_offset = None  # offset (in sec) from flow start
        run_pkt_count = 1             # current run’s packet count
        run_byte_count = payload_list[0]

        # 2. Only iterate safe range: 0 .. n_payload-2 (since we use payload_list[i+1])
        for i in range(n_payload - 1):
            iat = iat_list[i]
            if iat <= ACTIVE_IDLE_THRESHOLD:
                # Extend or start a bulk run
                if run_start_time_offset is None:
                    # The run starts at the arrival of packet i (i.e. sum of first i IATs)
                    run_start_time_offset = sum(iat_list[:i])
                    # Count packets i and i+1, and bytes of both
                    run_pkt_count = 2
                    run_byte_count = payload_list[i] + payload_list[i + 1]
                else:
                    # Already in a run -> just accumulate
                    run_pkt_count += 1
                    run_byte_count += payload_list[i + 1]
            else:
                # Gap too big -> close out any existing run
                if run_start_time_offset is not None and run_pkt_count >= 4:
                    # Duration is sum of IATs from run_start to this packet
                    duration = sum(iat_list[:i + 1]) - run_start_time_offset
                    bulks.append((run_pkt_count, run_byte_count, duration))
                # Reset to start looking for the next run
                run_start_time_offset = None
                run_pkt_count = 1
                run_byte_count = payload_list[i + 1]

        # 3. Finalize any run that reaches the end
        if run_start_time_offset is not None and run_pkt_count >= 4:
            duration = sum(iat_list) - run_start_time_offset
            bulks.append((run_pkt_count, run_byte_count, duration))

        # 4. Compute averages or return zeros
        if not bulks:
            return 0.0, 0.0, 0.0

        total_runs = len(bulks)
        avg_pkts = sum(b[0] for b in bulks) / total_runs
        avg_bytes = sum(b[1] for b in bulks) / total_runs
        avg_duration = sum(b[2] for b in bulks) / total_runs

        return avg_pkts, avg_bytes, avg_duration

    def update_flow(self, packet: Packet) -> Optional[FlowStatistics]:
        packet_info = self._extract_basic_info(packet)
        if not packet_info:
            return None

        flow_key = self._create_flow_key(packet_info)
        if not flow_key:
            return None

        now = packet_info["timestamp"]  # Current packet's timestamp

        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStatistics(
                start_time=now, last_seen=now, last_activity=now
            )
            self.flow_packets[flow_key] = []
            st = self.flows[flow_key]
        else:
            st = self.flows[flow_key]
            st.start_time = min(st.start_time, now)
            st.last_seen = max(st.last_seen, now)
            # last_activity will be updated later

        # Update duration
        st.duration = max(0, st.last_seen - st.start_time)

        # Store packet
        st.packets.append(packet)
        self.flow_packets[flow_key].append(packet)

        # Update direction
        direction = packet_info.get("direction", "forward")
        length = packet_info.get("length", 0)
        header_len = packet_info.get("header_length", 0)

        st.total_packets += 1
        if direction == "forward":
            st.forward_packets += 1
            st.total_length_forward += length
            st.forward_packet_lengths.append(length)
            st.forward_header_lengths.append(header_len)
            st.act_data_pkt_fwd += 1
        else:
            st.backward_packets += 1
            st.total_length_backward += length
            st.backward_packet_lengths.append(length)
            st.backward_header_lengths.append(header_len)

        # Update IATs
        if st.last_activity:
            iat = now - st.last_activity
            st.flow_iat.append(iat)
            if direction == "forward":
                st.forward_iat.append(iat)
            else:
                st.backward_iat.append(iat)

        st.last_activity = now

        # Unique destination IPs and protocol tracking
        ip = packet[IP]
        st.unique_dest_ips.add(ip.dst)
        st.protocols_seen.add(ip.proto)

        # TCP-specific
        if TCP in packet:
            tcp = packet[TCP]
            if direction == "backward":
                if tcp.flags & 0x08:  # PSH
                    st.backward_psh_flags += 1
                if tcp.flags & 0x20:  # URG
                    st.backward_urg_flags += 1

            flags = {
                "FIN": 0x01,
                "SYN": 0x02,
                "RST": 0x04,
                "PSH": 0x08,
                "ACK": 0x10,
                "URG": 0x20,
                "ECE": 0x40,
                "CWE": 0x80,
            }
            for name, bit in flags.items():
                if tcp.flags & bit:
                    st.tcp_flags_counts[name] += 1

            # Record TCP fields
            st.tcp_window_size = tcp.window
            st.tcp_urgent_pointer = tcp.urgptr
            st.tcp_sequence_number = tcp.seq
            st.tcp_acknowledgment_number = tcp.ack
            st.tcp_reserved_bits = tcp.reserved
            st.tcp_checksum = tcp.chksum
            st.tcp_options_count = len(tcp.options) if tcp.options else 0

        # Update sliding window (host_bytes_60s, connection_rate)
        src_ip = ip.src
        self.host_windows[src_ip].append(
            (now, length, ip.dst, tcp.dport if TCP in packet else 0)
        )

        return st

    def clear_flow(self, fk: FlowKey):
        """
        Cleanly remove the state associated with a completed or expired flow.
        Called after detecting flow termination (e.g., TCP FIN or RST).
        """
        flow_exists = fk in self.flows

        if flow_exists:
            del self.flows[fk]

            # Log flow cleanup (for debugging or audit purposes)
            # print(
            #     f"[INFO] Cleared flow: {fk.src_ip}:{fk.src_port} → {fk.dst_ip}:{fk.dst_port} (Protocol {fk.protocol})"
            # )

        else:
            # Log unexpected cleanup attempt
            print(
                f"[WARNING] Attempted to clear unknown flow: {fk.src_ip}:{fk.src_port} → {fk.dst_ip}:{fk.dst_port} (Protocol {fk.protocol})"
            )

    def cleanup_old_flows(self, timeout: float = 60.0):
        now = time.time()
        expired = [fk for fk, fs in self.flows.items() if now - fs.last_seen > timeout]
        for fk in expired:
            pkt_count = self.flows[fk].total_packets
            features = self.compute_features(fk)
            features = {k: features[k] for k in EXPECTED_FEATURES if k in features}

            
            # if features:
            #     self.append_features_row("ml_ready_features.csv", features)
            del self.flows[fk]
            if fk in self.flow_packets:
                del self.flow_packets[fk]

    # Removed old unsafe flow_key method. Use _create_flow_key(packet_info) instead.

    def default_ip_behavior(self):
        """Default behavior tracking for new IPs"""
        return {
            "port_scan_attempts": set(),
            "connection_attempts": 0,
            "failed_connections": 0,
            "unique_destinations": set(),
            "protocols_used": set(),
            "first_seen": time.time(),
            "packet_sizes": [],
            "request_rates": deque(maxlen=100),
        }

    def extract_features(self, packet: Packet) -> Dict[str, Any]:
        """Main feature extraction method"""
        try:
            with self.lock:
                # Cleanup old flows periodically
                if time.time() - self.last_cleanup > self.cleanup_interval:
                    self.cleanup_old_flows()  # This calls compute_features, which needs a flow_key. Ensure flows only contain IP flows.

                packet_info = self._extract_basic_info(packet)
                if not packet_info or not packet_info.get("is_ip_packet"):
                    # logger.debug("extract_features: Skipping non-IP packet or packet with no info.")
                    return {}

                flow_key = self._create_flow_key(
                    packet_info
                )  # Uses packet_info, already checked for is_ip_packet
                if not flow_key:
                    # logger.debug("extract_features: Could not create flow key.")
                    return {}

                # Get or create flow statistics
                now = packet.time  # Current packet's timestamp

                if flow_key not in self.flows:
                    self.flows[flow_key] = FlowStatistics(
                        start_time=now, last_seen=now, last_activity=now
                    )
                    self.flow_packets[flow_key] = []
                    flow_stats = self.flows[flow_key]
                else:
                    flow_stats = self.flows[flow_key]
                    # Ensure start_time is the minimum and last_seen is the maximum
                    flow_stats.start_time = min(flow_stats.start_time, now)
                    flow_stats.last_seen = max(flow_stats.last_seen, now)

                # Update duration consistently
                flow_stats.duration = max(
                    0, flow_stats.last_seen - flow_stats.start_time
                )

                # Append packet
                self.flow_packets[flow_key].append(packet)
                flow_stats.packets.append(packet)

                # Directional handling
                direction = packet_info.get("direction", "forward")
                length = packet_info.get("length", 0)
                header_len = packet_info.get("header_length", 0)

                flow_stats.total_packets += 1
                # flow_stats.duration = now - flow_stats.start_time # This was the old line
                # flow_stats.last_seen = now # This is already set prior to duration calculation

                if direction == "forward":
                    flow_stats.forward_packets += 1
                    flow_stats.total_length_forward += length
                    flow_stats.forward_packet_lengths.append(length)
                    flow_stats.forward_header_lengths.append(header_len)
                    flow_stats.act_data_pkt_fwd += 1
                else:
                    flow_stats.backward_packets += 1
                    flow_stats.total_length_backward += length
                    flow_stats.backward_packet_lengths.append(length)
                    flow_stats.backward_header_lengths.append(header_len)

                # IAT tracking
                if flow_stats.last_activity:
                    iat = now - flow_stats.last_activity
                    flow_stats.flow_iat.append(iat)
                    if direction == "forward":
                        flow_stats.forward_iat.append(iat)
                    else:
                        flow_stats.backward_iat.append(iat)
                flow_stats.last_activity = now

                # Unique destination tracking
                ip = packet[IP]
                flow_stats.unique_dest_ips.add(ip.dst)
                flow_stats.protocols_seen.add(ip.proto)

                # TCP field tracking
                if TCP in packet:
                    tcp = packet[TCP]
                    if direction == "backward":
                        if tcp.flags & 0x08:
                            flow_stats.backward_psh_flags += 1
                        if tcp.flags & 0x20:
                            flow_stats.backward_urg_flags += 1

                    flags = {
                        "FIN": 0x01,
                        "SYN": 0x02,
                        "RST": 0x04,
                        "PSH": 0x08,
                        "ACK": 0x10,
                        "URG": 0x20,
                        "ECE": 0x40,
                        "CWE": 0x80,
                    }
                    for name, bit in flags.items():
                        if tcp.flags & bit:
                            flow_stats.tcp_flags_counts[name] += 1

                    flow_stats.tcp_window_size = tcp.window
                    flow_stats.tcp_urgent_pointer = tcp.urgptr
                    flow_stats.tcp_sequence_number = tcp.seq
                    flow_stats.tcp_acknowledgment_number = tcp.ack
                    flow_stats.tcp_reserved_bits = tcp.reserved
                    flow_stats.tcp_checksum = tcp.chksum
                    flow_stats.tcp_options_count = (
                        len(tcp.options) if tcp.options else 0
                    )

                # Add to host-based sliding window
                self.host_windows[ip.src].append(
                    (now, length, ip.dst, tcp.dport if TCP in packet else 0)
                )

                # === Existing logic preserved ===
                # The following lines directly update flow_stats, which is also done by update_flow method.
                # However, extract_features is a comprehensive "do-it-all" for a single packet in some contexts.
                # The _update_flow_statistics method is an internal helper for this.
                packet_metrics = self._create_packet_metrics(packet, packet_info)
                self._update_flow_statistics(
                    flow_key, packet_metrics, packet_info
                )  # Internal update based on current packet

                features = self.compute_features(
                    flow_key
                )  # Use the main compute_features with flow_key only

                # Behavioral and protocol features are specific to the current packet, not the whole flow.
                # They are usually added on top of flow features if needed for real-time decisions.
                # For pure flow feature extraction as per CICIDS, these might not belong here
                # or should be clearly separated. compute_features now returns the 84 CICIDS features.
                # If these are needed, they should be added to the dict from compute_features.

                # For now, let's assume compute_features is the source of truth for flow-based features.
                # If behavioral/protocol features are needed *in addition*, they can be added:
                # behavioral_features = self._extract_behavioral_features(packet_info) # packet_info is IP specific
                # features.update(behavioral_features) # This would add non-CICIDS features

                # protocol_features = self._extract_protocol_features(packet, packet_info) # packet_info is IP specific
                # features.update(protocol_features)  # This would add non-CICIDS features

                # If the goal is strictly CICIDS features, then just return 'features' from compute_features.
                # The current structure of extract_features seems to try to do more.
                # For this refactoring, ensure it returns what compute_features returns.
                # If compute_features is comprehensive, then behavioral/protocol might be redundant here
                # if they are already incorporated into compute_features or not part of the target feature set.
                # Given compute_features was just refactored for CICIDS, let's trust its output.
                # The _extract_behavioral_features and _extract_protocol_features are IP-dependent.
                # Since we've guarded for IP packets, these calls are safe if uncommented.
                # However, to align with "output of compute_features", we should rely on that.
                # For now, returning 'features' which is the output of self.compute_features(flow_key)
                # is the most direct interpretation of making extract_features use the refactored compute_features.
                # The behavioral/protocol features are not part of the 84 CICIDS features.
                # If they are to be included, the function signature and purpose might need to be revisited.
                # For now, let's stick to returning the output of compute_features.
                # The _extract_behavioral_features and _extract_protocol_features are not called.
                # This aligns with the goal of making `extract_features` rely on `compute_features`.
                # If these additional features are desired, they should be added to the dict `f`
                # within `compute_features` itself or handled by the caller of `extract_features`.

                # The current `_compute_flow_features` does not exist. It was renamed to `compute_features`.
                # The call should be `features = self.compute_features(flow_key)`
                # The `packet_info` arg was removed from `compute_features`.
                # The behavioral and protocol features are not part of the 84 features from compute_features.
                # Let's remove them here to ensure extract_features returns the strict set from compute_features.
                # If they are needed, the calling context should handle merging them.

                # The features from compute_features are what we want.
                # The behavioral_features and protocol_features are extra and IP-dependent.
                # Since we are already guarded for IP packets, they *could* be added.
                # However, the task is about robustness for non-IP and using the refactored compute_features.
                # The current compute_features does NOT include behavioral/protocol features.
                # So, to make extract_features align, these should not be added here.
                # features = self.compute_features(flow_key) # This is already done above.

                # No, the call to self._compute_flow_features should be self.compute_features
                # The original code was: features = self._compute_flow_features(flow_key, packet_info)
                # This should now be: features = self.compute_features(flow_key)
                # which is already done.
                # The local _update_flow_statistics updates the flow state.
                # Then compute_features reads that state.

                # The current structure of extract_features is:
                # 1. Get packet_info (guard for non-IP)
                # 2. Get flow_key (guard if not created)
                # 3. Update flow_stats with current packet (_update_flow_statistics)
                # 4. Compute features for the *current state* of the flow (self.compute_features)
                # 5. Optionally add packet-specific behavioral/protocol features.
                # This structure seems reasonable. The key is that compute_features now returns the 84 features.
                # For this task, I will remove the addition of behavioral and protocol features
                # to make `extract_features` primarily a wrapper around `compute_features` after updating flow state.

                # features = self.compute_features(flow_key) # This line is already correct.
                # Let's remove the behavioral and protocol feature extraction for now from this method
                # as compute_features is supposed to be the source of the 84 features.
                # If they are needed, they should be added by compute_features or by the caller.
                # This simplifies extract_features to focus on flow state update and calling compute_features.
                pass  # Behavioral and protocol features are not part of the core 84 from compute_features.
                # If they were, compute_features would add them.
                # So, no features.update(behavioral_features) here.

                protocol_features = self._extract_protocol_features(packet, packet_info)
                features.update(protocol_features)

                return features

        except Exception as e:
            # Capture the full traceback—including the chain of causes—and log it
            tb = traceback.format_exc()
            logger.error("Feature extraction error: %s\nFull traceback:\n%s", e, tb)
            # Optionally, if you want to see __cause__ / __context__ explicitly:
            if e.__cause__:
                logger.error("Underlying cause: %s", repr(e.__cause__))
            elif e.__context__:
                logger.error("Context exception: %s", repr(e.__context__))
            return {}

    def _extract_basic_info(self, packet: Packet) -> Optional[Dict]:
        """Extract basic packet information"""
        timestamp = packet.time if hasattr(packet, "time") else time.time()

        if not packet.haslayer(IP) and not packet.haslayer(IPv6):
            if packet.haslayer(ARP):
                try:
                    arp_layer = packet[ARP]
                    arp_info = {
                        "timestamp": timestamp,
                        "size": len(packet),
                        "protocol": "ARP",
                        "src_mac": arp_layer.hwsrc,
                        "dst_mac": arp_layer.hwdst,
                        "src_ip_arp": arp_layer.psrc,
                        "dst_ip_arp": arp_layer.pdst,
                        "is_ip_packet": False,
                    }
                    return arp_info
                except (AttributeError, IndexError, TypeError) as e:
                    logger.debug(
                        f"Malformed ARP packet, cannot extract all ARP fields: {packet.summary()[:100]}. Error: {e}",
                        exc_info=True,
                    )
                    # Return minimal info, actual fields might be missing or None due to Scapy/packet issues
                    return {
                        "timestamp": timestamp,
                        "size": len(packet),
                        "protocol": "ARP_MALFORMED",
                        "is_ip_packet": False,
                    }
            else:  # Other non-IP/IPv6 packet
                logger.debug(
                    f"Skipping non-IP/IPv6/ARP packet: {packet.summary()[:100]} - Layers: {packet.layers()}"
                )
                return None

        try:
            info = {
                "timestamp": timestamp,
                "size": len(packet),
                "src_ip": None,
                "dst_ip": None,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "Other",
                "ip_version": None,
                "is_ip_packet": True,  # Mark as IP packet
            }

            # Layer 3 (Network Layer)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.update(
                    {
                        "src_ip": ip_layer.src,
                        "dst_ip": ip_layer.dst,
                        "ip_version": 4,
                        "ip_ttl": ip_layer.ttl,
                        "ip_flags": ip_layer.flags,
                        "ip_fragment_offset": ip_layer.frag,
                        "ip_header_len": ip_layer.ihl * 4,
                        "ip_tos": ip_layer.tos,
                        "ip_id": ip_layer.id,
                    }
                )
            elif packet.haslayer(
                IPv6
            ):  # This will be true if the initial check passed for IPv6
                ipv6_layer = packet[IPv6]
                info.update(
                    {
                        "src_ip": ipv6_layer.src,
                        "dst_ip": ipv6_layer.dst,
                        "ip_version": 6,
                        "ip_ttl": ipv6_layer.hlim,
                        "ip_flow_label": ipv6_layer.fl,
                    }
                )
            # No 'else' needed here as the initial check ensures it's IP or IPv6

            # Layer 4 (Transport Layer)
            if packet.haslayer(TCP):
                try:
                    tcp_layer = packet[TCP]
                    info.update(
                        {
                            "src_port": tcp_layer.sport,
                            "dst_port": tcp_layer.dport,
                            "protocol": "TCP",
                            "tcp_flags": tcp_layer.flags,  # Already a string/int from Scapy
                            "tcp_window_size": int(tcp_layer.window),
                            "tcp_urgent_ptr": int(tcp_layer.urgptr),
                            "tcp_seq": int(tcp_layer.seq),
                            "tcp_ack": int(tcp_layer.ack),
                            "tcp_header_len": (
                                int(tcp_layer.dataofs * 4)
                                if tcp_layer.dataofs is not None
                                else 0
                            ),
                        }
                    )
                    # TCP options processing
                    tcp_options_len = 0
                    if tcp_layer.options:  # Check if options exist and is not empty
                        try:
                            tcp_options_len = sum(
                                len(opt) if isinstance(opt, tuple) else 1
                                for opt in tcp_layer.options
                            )
                        except (
                            Exception
                        ) as opt_e:  # Catch error during option processing specifically
                            logger.debug(
                                f"Error processing TCP options for packet {packet.summary()[:100]}: {opt_e}",
                                exc_info=True,
                            )
                    info["tcp_options_len"] = tcp_options_len
                except (AttributeError, IndexError, TypeError, Exception) as e:
                    logger.debug(
                        f"Malformed or incomplete TCP layer for packet {packet.summary()[:100]}: {e}",
                        exc_info=True,
                    )
                    info["protocol"] = "TCP_MALFORMED"
                    info["src_port"], info["dst_port"] = -1, -1  # Indicate error

            elif packet.haslayer(UDP):
                try:
                    udp_layer = packet[UDP]
                    info.update(
                        {
                            "src_port": udp_layer.sport,
                            "dst_port": udp_layer.dport,
                            "protocol": "UDP",
                            "udp_length": udp_layer.len,
                        }
                    )
                except (AttributeError, IndexError, TypeError, Exception) as e:
                    logger.debug(
                        f"Malformed or incomplete UDP layer for packet {packet.summary()[:100]}: {e}",
                        exc_info=True,
                    )
                    info["protocol"] = "UDP_MALFORMED"
                    info["src_port"], info["dst_port"] = -1, -1

            elif packet.haslayer(ICMP):
                try:
                    icmp_layer = packet[ICMP]
                    info.update(
                        {
                            "protocol": "ICMP",
                            "icmp_type": icmp_layer.type,
                            "icmp_code": icmp_layer.code,
                        }
                    )
                except (AttributeError, IndexError, TypeError, Exception) as e:
                    logger.debug(
                        f"Malformed or incomplete ICMP layer for packet {packet.summary()[:100]}: {e}",
                        exc_info=True,
                    )
                    info["protocol"] = "ICMP_MALFORMED"

            # Calculate payload size
            if packet.haslayer(Raw):
                info["payload_size"] = len(packet[Raw])
            else:
                info["payload_size"] = 0

            info["header_size"] = info["size"] - info["payload_size"]

            return info

        except Exception as e:
            logger.error(
                f"Critical error during _extract_basic_info for packet {packet.summary()[:100]}: {e}",
                exc_info=True,
            )
            return None  # Critical failure in basic info extraction

    def _create_flow_key(self, packet_info: Dict) -> Optional[FlowKey]:
        """Create a flow key for packet categorization. Only for IP packets."""
        if not packet_info or not packet_info.get("is_ip_packet"):
            return None
        try:
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            src_port = packet_info.get("src_port", 0)
            dst_port = packet_info.get("dst_port", 0)
            protocol = packet_info.get("protocol", "Other")

            if not src_ip or not dst_ip:
                return None

            # Normalize flow direction (smaller IP first for bidirectional flows)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol)

        except Exception as e:
            logger.debug(
                f"Flow key creation error for packet_info {packet_info}: {e}",
                exc_info=True,
            )
            return None

    def _create_packet_metrics(
        self, packet: Packet, packet_info: Dict
    ) -> PacketMetrics:
        """Create packet metrics object"""
        return PacketMetrics(
            timestamp=packet_info.get("timestamp", time.time()),
            size=packet_info["size"],
            pkt=packet,
            payload_size=packet_info.get("payload_size", 0),
            header_size=packet_info.get("header_size", 0),
            flags=str(packet_info.get("tcp_flags", "")),
            tcp_window_size=packet_info.get("tcp_window_size", 0),
            tcp_urgent_ptr=packet_info.get("tcp_urgent_ptr", 0),
            tcp_options_len=packet_info.get("tcp_options_len", 0),
            ip_ttl=packet_info.get("ip_ttl", 0),
            ip_flags=packet_info.get("ip_flags", 0),
            ip_fragment_offset=packet_info.get("ip_fragment_offset", 0),
            icmp_type=packet_info.get("icmp_type", -1),
            icmp_code=packet_info.get("icmp_code", -1),
        )

    def _update_flow_statistics(
        self, flow_key: FlowKey, packet_metrics: PacketMetrics, packet_info: Dict
    ):
        """Update flow statistics with new packet"""
        flow_stats = self.flows[flow_key]
        flow_packets = self.flow_packets[flow_key]
        pkt = packet_metrics.pkt

        current_time = (
            packet_metrics.timestamp if packet_metrics.timestamp else time.time()
        )

        # current_time is packet_metrics.timestamp

        if (
            flow_stats.total_packets == 0
        ):  # This implies it's the first packet metric being processed for this flow_stats object
            flow_stats.start_time = current_time
            flow_stats.last_forward_time = current_time
            flow_stats.last_backward_time = current_time
            flow_stats.last_flow_time = current_time
            flow_stats.last_activity = current_time
            flow_stats.last_seen = current_time
        else:
            # Ensure start_time is the minimum and last_seen is the maximum
            flow_stats.start_time = min(flow_stats.start_time, current_time)
            flow_stats.last_seen = max(flow_stats.last_seen, current_time)

        flow_stats.duration = max(0, flow_stats.last_seen - flow_stats.start_time)
        # flow_stats.total_packets will be incremented after this block, so increment it here.
        flow_stats.total_packets += 1

        # Determine flow direction
        is_forward = (
            packet_info["src_ip"] == flow_key.src_ip
            and packet_info["src_port"] == flow_key.src_port
        )

        if is_forward:
            if flow_stats.last_forward_time is not None:
                if current_time < flow_stats.last_forward_time:
                    logger.warning(
                        f"Timestamp anomaly: current_time ({current_time}) < last_forward_time ({flow_stats.last_forward_time}) for flow {flow_key}"
                    )
                iat_forward = max(0, current_time - flow_stats.last_forward_time)
                flow_stats.forward_iat.append(iat_forward)
            flow_stats.last_forward_time = current_time
        else:
            if flow_stats.last_backward_time is not None:
                if current_time < flow_stats.last_backward_time:
                    logger.warning(
                        f"Timestamp anomaly: current_time ({current_time}) < last_backward_time ({flow_stats.last_backward_time}) for flow {flow_key}"
                    )
                iat_backward = max(0, current_time - flow_stats.last_backward_time)
                flow_stats.backward_iat.append(iat_backward)
            flow_stats.last_backward_time = current_time

        # Activity tracking with non-negative values
        time_since_last = max(0, current_time - flow_stats.last_activity)
        if time_since_last > ACTIVE_IDLE_THRESHOLD:
            flow_stats.idle_times.append(time_since_last)
        else:
            flow_stats.active_times.append(time_since_last)
        flow_stats.last_activity = current_time

        ##Newly added code to handle TCP window size
        tcp = pkt.getlayer(TCP)
        if tcp:
            if is_forward and flow_stats.init_win_forward is None:
                flow_stats.init_win_forward = tcp.window
            elif not is_forward and flow_stats.init_win_backward is None:
                flow_stats.init_win_backward = tcp.window
        payload_len = len(pkt[TCP].payload) if pkt.haslayer(TCP) else 0
        if is_forward:
            flow_stats.forward_payload_lengths.append(payload_len)
        else:
            flow_stats.backward_payload_lengths.append(payload_len)
        flow_stats.payload_lengths.append(payload_len)

        # Corrected code in _update_flow_statistics method
        if is_forward:
            if flow_stats.last_forward_time is not None:
                iat = max(
                    0, current_time - flow_stats.last_forward_time
                )  # Ensure non-negative
                flow_stats.forward_iat.append(iat)
            flow_stats.last_forward_time = current_time
        else:
            if flow_stats.last_backward_time is not None:
                iat = max(
                    0, current_time - flow_stats.last_backward_time
                )  # Ensure non-negative
                flow_stats.backward_iat.append(iat)
            flow_stats.last_backward_time = current_time

        # And for the overall flow IAT:
        # if flow_packets and hasattr(flow_packets[-1], 'time'):
        #     flow_stats.flow_iat.append(current_time - flow_packets[-1].time)

        if flow_stats.last_flow_time is not None:
            if current_time < flow_stats.last_flow_time:
                logger.warning(
                    f"Timestamp anomaly: current_time ({current_time}) < last_flow_time ({flow_stats.last_flow_time}) for flow {flow_key}"
                )
            iat_flow = max(0, current_time - flow_stats.last_flow_time)
            flow_stats.flow_iat.append(iat_flow)
        flow_stats.last_flow_time = current_time

        # Update directional statistics
        if is_forward:
            flow_stats.forward_packets += 1
            flow_stats.total_length_forward += packet_metrics.size
            flow_stats.forward_packet_lengths.append(packet_metrics.size)
            flow_stats.forward_header_lengths.append(packet_metrics.header_size)
        else:
            flow_stats.backward_packets += 1
            flow_stats.total_length_backward += packet_metrics.size
            flow_stats.backward_packet_lengths.append(packet_metrics.size)
            flow_stats.backward_header_lengths.append(packet_metrics.header_size)

        # Update inter-arrival times
        if len(flow_packets) > 0:
            # General flow IAT
            if current_time < flow_packets[-1].time:
                logger.warning(
                    f"Timestamp anomaly (flow_packets general): current_time ({current_time}) < prev_packet_timestamp ({flow_packets[-1].time}) for flow {flow_key}"
                )
            iat = max(0, current_time - flow_packets[-1].time)
            flow_stats.flow_iat.append(iat)

            if is_forward:
                # Find last forward packet
                # Iterate in reverse to find the most recent packet in the same direction
                for pkt_metric in reversed(flow_packets[:-1]):  # Exclude current packet
                    # Determine direction of pkt_metric based on its relation to flow_key

                    pkt_metric_is_forward = (
                        (
                            pkt[IP].src == flow_key.src_ip
                            and pkt[TCP].sport == flow_key.src_port
                        )
                        if pkt.haslayer(IP) and pkt.haslayer(TCP)
                        else False
                    )  # Default if not IP/TCP

                    if pkt_metric_is_forward:
                        if current_time < pkt_metric.timestamp:
                            logger.warning(
                                f"Timestamp anomaly (flow_packets forward): current_time ({current_time}) < pkt_metric.timestamp ({pkt_metric.timestamp}) for flow {flow_key}"
                            )
                        forward_iat = max(0, current_time - pkt_metric.timestamp)
                        flow_stats.forward_iat.append(forward_iat)
                        break
            else:  # Backward packet
                # Find last backward packet
                # Iterate in reverse to find the most recent packet in the same direction
                for pkt_metric in reversed(flow_packets[:-1]):  # Exclude current packet
                    pkt_metric_is_forward = (
                        (
                            pkt[IP].src == flow_key.src_ip
                            and pkt[TCP].sport == flow_key.src_port
                        )
                        if pkt.haslayer(IP) and pkt.haslayer(TCP)
                        else False
                    )  # Default if not IP/TCP

                    if (
                        not pkt_metric_is_forward
                    ):  # If this packet in flow_packets was backward
                        if current_time < pkt_metric.timestamp:
                            logger.warning(
                                f"Timestamp anomaly (flow_packets backward): current_time ({current_time}) < pkt_metric.timestamp ({pkt_metric.timestamp}) for flow {flow_key}"
                            )
                        backward_iat = max(0, current_time - pkt_metric.timestamp)
                        flow_stats.backward_iat.append(backward_iat)
                        break

        # Update TCP flags
        if packet_info.get("protocol") == "TCP":
            flags = packet_info.get("tcp_flags", 0)
            if not is_forward:  # Backward packet
                if flags & 0x08:  # PSH flag
                    flow_stats.backward_psh_flags += 1
                if flags & 0x20:  # URG flag
                    flow_stats.backward_urg_flags += 1
            if flags & 0x02:  # SYN
                flow_stats.syn_flag_count += 1
            if flags & 0x80 or flags & 0x40 or flags & 0x20:  # CWR, ECE, URG
                flow_stats.cwe_flag_count += 1

            # Count individual flags
            flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWE"]
            for i, flag_name in enumerate(flag_names):
                if flags & (1 << i):
                    flow_stats.tcp_flags_counts[flag_name] += 1
        # Track data packets in forward direction
        if is_forward and packet_metrics.payload_size > 0:
            flow_stats.act_data_pkt_fwd += 1
        if is_forward:
            if flow_stats.min_seg_size_forward == 0:
                flow_stats.min_seg_size_forward = packet_metrics.payload_size
            else:
                flow_stats.min_seg_size_forward = min(
                    flow_stats.min_seg_size_forward, packet_metrics.payload_size
                )
        #  Capture initial window sizes during TCP handshake
        if packet_info.get("protocol") == "TCP" and flags & 0x02:  # SYN flag
            if is_forward:
                flow_stats.init_win_forward = packet_info.get("tcp_window_size", 0)
            else:
                flow_stats.init_win_backward = packet_info.get("tcp_window_size", 0)

        # Add current packet size to temporary list for overall stats
        flow_stats.all_packet_lengths_temp.append(packet_metrics.size)

        # Update overall packet length statistics
        if flow_stats.all_packet_lengths_temp:
            flow_stats.packet_length_min = float(
                min(flow_stats.all_packet_lengths_temp)
            )
            flow_stats.packet_length_max = float(
                max(flow_stats.all_packet_lengths_temp)
            )
            flow_stats.packet_length_mean = statistics.mean(
                flow_stats.all_packet_lengths_temp
            )
            if len(flow_stats.all_packet_lengths_temp) > 1:
                flow_stats.packet_length_std = statistics.stdev(
                    flow_stats.all_packet_lengths_temp
                )
                flow_stats.packet_length_variance = statistics.variance(
                    flow_stats.all_packet_lengths_temp
                )
            else:
                flow_stats.packet_length_std = 0.0
                flow_stats.packet_length_variance = 0.0
        else:
            flow_stats.packet_length_min = 0.0
            flow_stats.packet_length_max = 0.0
            flow_stats.packet_length_mean = 0.0
            flow_stats.packet_length_std = 0.0
            flow_stats.packet_length_variance = 0.0

        # Update ECE flag count
        if packet_info.get("protocol") == "TCP":
            tcp_flags_val = packet_info.get(
                "tcp_flags", 0
            )  # Ensure we get the integer value
            if tcp_flags_val & 0x40:  # ECE flag (0x40)
                flow_stats.ece_flag_count += 1

        # Update fwd_seg_size_min (already updated by min_seg_size_forward logic)
        flow_stats.fwd_seg_size_min = float(flow_stats.min_seg_size_forward)

        # Update Bulk Rate Averages
        # Assuming bulk_size_avg_forward/backward are total bytes in current/last bulk
        # And bulk_packet_count_forward/backward are total packets in current/last bulk
        flow_stats.fwd_bytes_bulk_avg = flow_stats.bulk_size_avg_forward
        flow_stats.fwd_pkt_bulk_avg = float(flow_stats.bulk_packet_count_forward)
        if flow_stats.bulk_duration_forward > 0:
            flow_stats.fwd_bulk_rate_avg = (
                flow_stats.fwd_bytes_bulk_avg / flow_stats.bulk_duration_forward
            )
        else:
            flow_stats.fwd_bulk_rate_avg = 0.0

        flow_stats.bwd_bytes_bulk_avg = flow_stats.bulk_size_avg_backward
        flow_stats.bwd_pkt_bulk_avg = float(flow_stats.bulk_packet_count_backward)
        if flow_stats.bulk_duration_backward > 0:
            flow_stats.bwd_bulk_rate_avg = (
                flow_stats.bwd_bytes_bulk_avg / flow_stats.bulk_duration_backward
            )
        else:
            flow_stats.bwd_bulk_rate_avg = 0.0

        # Add packet to flow
        flow_packets.append(packet_metrics)

        # Limit packet history to prevent memory issues
        if len(flow_packets) > 1000:
            flow_packets.pop(0)

        # Update activity tracking
        # Corrected code in _update_flow_statistics method
        time_since_last = max(
            0, current_time - flow_stats.last_activity
        )  # Ensure non-negative
        if time_since_last > 1.0:  # 1 second threshold for idle time
            flow_stats.idle_times.append(time_since_last)
        else:
            flow_stats.active_times.append(time_since_last)

        flow_stats.last_activity = current_time

    def _compute_flow_features(
        self, flow_key: FlowKey, packet_info: Dict
    ) -> Dict[str, Any]:
        """Compute comprehensive flow features matching CICIDS datasets"""
        flow_stats = self.flows[flow_key]
        features = {}

        # Basic flow features
        features.update(
            {
                "Flow_Duration": flow_stats.duration * 1000000,  # microseconds
                "Total_Fwd_Packets": flow_stats.forward_packets,
                "Total_Backward_Packets": flow_stats.backward_packets,
                "Total_Length_of_Fwd_Packets": flow_stats.total_length_forward,
                "Total_Length_of_Bwd_Packets": flow_stats.total_length_backward,
            }
        )
        features.update(
            {
                "Bwd_PSH_Flags": flow_stats.backward_psh_flags,
                "Bwd_URG_Flags": flow_stats.backward_urg_flags,
                "act_data_pkt_fwd": flow_stats.act_data_pkt_fwd,
                "min_seg_size_forward": (
                    min(flow_stats.forward_payload_lengths)
                    if flow_stats.forward_payload_lengths
                    else 0
                ),
                "min_seg_size_backward": (
                    min(flow_stats.backward_payload_lengths)
                    if flow_stats.backward_payload_lengths
                    else 0
                ),
                "Init_Win_bytes_forward": flow_stats.init_win_forward,
                "Init_Win_bytes_backward": flow_stats.init_win_backward,
            }
        )
        # Packet length statistics
        all_lengths = (
            flow_stats.forward_packet_lengths + flow_stats.backward_packet_lengths
        )
        if all_lengths:
            features.update(
                {
                    "Fwd_Packet_Length_Max": (
                        max(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_25th": (
                        np.percentile(flow_stats.forward_packet_lengths, 25)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_50th": (
                        np.percentile(flow_stats.forward_packet_lengths, 50)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_75th": (
                        np.percentile(flow_stats.forward_packet_lengths, 75)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Min": (
                        min(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Mean": (
                        statistics.mean(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Std": (
                        statistics.stdev(flow_stats.forward_packet_lengths)
                        if len(flow_stats.forward_packet_lengths) > 1
                        else 0
                    ),
                    "Bwd_Packet_Length_Max": (
                        max(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Min": (
                        min(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Mean": (
                        statistics.mean(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_25th": (
                        np.percentile(flow_stats.backward_packet_lengths, 25)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_50th": (
                        np.percentile(flow_stats.backward_packet_lengths, 50)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_75th": (
                        np.percentile(flow_stats.backward_packet_lengths, 75)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Std": (
                        statistics.stdev(flow_stats.backward_packet_lengths)
                        if len(flow_stats.backward_packet_lengths) > 1
                        else 0
                    ),
                }
            )

        # Flow bytes/packets per second
        if flow_stats.duration > 0:
            features.update(
                {
                    "Flow_Bytes_s": (
                        flow_stats.total_length_forward
                        + flow_stats.total_length_backward
                    )
                    / flow_stats.duration,
                    "Flow_Packets_s": flow_stats.total_packets / flow_stats.duration,
                    "Flow_IAT_Mean": (
                        statistics.mean(flow_stats.flow_iat)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_25th": (
                        np.percentile(flow_stats.flow_iat, 25)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_50th": (
                        np.percentile(flow_stats.flow_iat, 50)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_75th": (
                        np.percentile(flow_stats.flow_iat, 75)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_Std": (
                        statistics.stdev(flow_stats.flow_iat)
                        if len(flow_stats.flow_iat) > 1
                        else 0
                    ),
                    "Flow_IAT_Max": (
                        max(flow_stats.flow_iat) if flow_stats.flow_iat else 0
                    ),
                    "Flow_IAT_Min": (
                        min(flow_stats.flow_iat) if flow_stats.flow_iat else 0
                    ),
                }
            )

        # Forward/Backward IAT statistics
        if flow_stats.forward_iat:
            features.update(
                {
                    "Fwd_IAT_Total": sum(flow_stats.forward_iat),
                    "Fwd_IAT_Mean": statistics.mean(flow_stats.forward_iat),
                    "Fwd_IAT_Std": (
                        statistics.stdev(flow_stats.forward_iat)
                        if len(flow_stats.forward_iat) > 1
                        else 0
                    ),
                    "Fwd_IAT_Max": max(flow_stats.forward_iat),
                    "Fwd_IAT_Min": min(flow_stats.forward_iat),
                }
            )

        if flow_stats.backward_iat:
            features.update(
                {
                    "Bwd_IAT_Total": sum(flow_stats.backward_iat),
                    "Bwd_IAT_Mean": statistics.mean(flow_stats.backward_iat),
                    "Bwd_IAT_Std": (
                        statistics.stdev(flow_stats.backward_iat)
                        if len(flow_stats.backward_iat) > 1
                        else 0
                    ),
                    "Bwd_IAT_Max": max(flow_stats.backward_iat),
                    "Bwd_IAT_Min": min(flow_stats.backward_iat),
                }
            )

        # TCP Flag features
        features.update(
            {
                "FIN_Flag_Count": flow_stats.tcp_flags_counts.get("FIN", 0),
                "SYN_Flag_Count": flow_stats.tcp_flags_counts.get("SYN", 0),
                "RST_Flag_Count": flow_stats.tcp_flags_counts.get("RST", 0),
                "PSH_Flag_Count": flow_stats.tcp_flags_counts.get("PSH", 0),
                "ACK_Flag_Count": flow_stats.tcp_flags_counts.get("ACK", 0),
                "URG_Flag_Count": flow_stats.tcp_flags_counts.get("URG", 0),
                "CWE_Flag_Count": flow_stats.cwe_flag_count,
                "ECE_Flag_Count": flow_stats.tcp_flags_counts.get("ECE", 0),
            }
        )

        # Header length statistics
        if flow_stats.forward_header_lengths:
            features["Fwd_Header_Length"] = statistics.mean(
                flow_stats.forward_header_lengths
            )
        if flow_stats.backward_header_lengths:
            features["Bwd_Header_Length"] = statistics.mean(
                flow_stats.backward_header_lengths
            )

        # Packets per second features
        if flow_stats.duration > 0:
            features.update(
                {
                    "Fwd_Packets_s": flow_stats.forward_packets / flow_stats.duration,
                    "Bwd_Packets_s": flow_stats.backward_packets / flow_stats.duration,
                }
            )

        # Packet size ratios and statistics
        total_packets = flow_stats.total_packets
        if total_packets > 0:
            features.update(
                {
                    "Down_Up_Ratio": flow_stats.backward_packets
                    / max(flow_stats.forward_packets, 1),
                    "Average_Packet_Size": (
                        flow_stats.total_length_forward
                        + flow_stats.total_length_backward
                    )
                    / total_packets,
                    "Avg_Fwd_Segment_Size": flow_stats.total_length_forward
                    / max(flow_stats.forward_packets, 1),
                    "Avg_Bwd_Segment_Size": flow_stats.total_length_backward
                    / max(flow_stats.backward_packets, 1),
                }
            )

        # Active/Idle time features
        if flow_stats.active_times:
            features.update(
                {
                    "Active_Mean": statistics.mean(flow_stats.active_times),
                    "Active_Std": (
                        statistics.stdev(flow_stats.active_times)
                        if len(flow_stats.active_times) > 1
                        else 0
                    ),
                    "Active_Max": max(flow_stats.active_times),
                    "Active_Min": min(flow_stats.active_times),
                }
            )

        if flow_stats.idle_times:
            features.update(
                {
                    "Idle_Mean": statistics.mean(flow_stats.idle_times),
                    "Idle_Std": (
                        statistics.stdev(flow_stats.idle_times)
                        if len(flow_stats.idle_times) > 1
                        else 0
                    ),
                    "Idle_Max": max(flow_stats.idle_times),
                    "Idle_Min": min(flow_stats.idle_times),
                }
            )

        # Subflow features (simplified - can be expanded)
        features.update(
            {
                "Subflow_Fwd_Packets": flow_stats.forward_packets,
                "Subflow_Fwd_Bytes": flow_stats.total_length_forward,
                "Subflow_Bwd_Packets": flow_stats.backward_packets,
                "Subflow_Bwd_Bytes": flow_stats.total_length_backward,
            }
        )

        return features

    def _extract_behavioral_features(self, packet_info: Dict) -> Dict[str, Any]:
        """Extract behavioral features for anomaly detection"""
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "Other")

        behavior = self.ip_behavior[src_ip]

        # Update behavioral tracking
        behavior["connection_attempts"] += 1
        behavior["unique_destinations"].add(dst_ip)
        behavior["protocols_used"].add(protocol)
        behavior["packet_sizes"].append(packet_info["size"])
        behavior["request_rates"].append(time.time())

        # Port scanning detection
        if dst_port > 0:
            behavior["port_scan_attempts"].add((dst_ip, dst_port))

        # Calculate behavioral features
        current_time = time.time()
        time_window = current_time - behavior["first_seen"]

        features = {
            "unique_destinations_count": len(behavior["unique_destinations"]),
            "protocols_count": len(behavior["protocols_used"]),
            "connection_rate": behavior["connection_attempts"] / max(time_window, 1),
            "port_scan_score": len(behavior["port_scan_attempts"]),
            "packet_size_variance": (
                statistics.variance(behavior["packet_sizes"][-100:])
                if len(behavior["packet_sizes"]) > 1
                else 0
            ),
        }

        # Request rate in last minute
        recent_requests = [
            t for t in behavior["request_rates"] if current_time - t <= 60
        ]
        features["requests_per_minute"] = len(recent_requests)

        return features

    def _extract_protocol_features(
        self, packet: Packet, packet_info: Dict
    ) -> Dict[str, Any]:
        """Extract protocol-specific features"""
        features = {}

        # HTTP-specific features
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            features.update(self._extract_http_features(packet))

        # DNS-specific features
        if packet.haslayer(DNS):
            features.update(self._extract_dns_features(packet))

        # TCP-specific advanced features
        if packet.haslayer(TCP):
            features.update(self._extract_tcp_advanced_features(packet))

        return features

    def _extract_http_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract HTTP-specific features"""
        features = {}

        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            features.update(
                {
                    "http_method": (
                        req.Method.decode("utf-8", errors="ignore")
                        if req.Method
                        else ""
                    ),
                    "http_uri_length": (
                        len(req.Path.decode("utf-8", errors="ignore"))
                        if req.Path
                        else 0
                    ),
                    "http_user_agent_length": (
                        len(req.User_Agent.decode("utf-8", errors="ignore"))
                        if req.User_Agent
                        else 0
                    ),
                    "http_host_length": (
                        len(req.Host.decode("utf-8", errors="ignore"))
                        if req.Host
                        else 0
                    ),
                }
            )

        if packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            if hasattr(resp, "Status_Code"):
                features["http_status_code"] = int(
                    resp.Status_Code.decode("utf-8", errors="ignore")
                )

        return features

    def _extract_dns_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract DNS-specific features"""
        features = {}
        dns = packet[DNS]

        features.update(
            {
                "dns_query_count": dns.qdcount,
                "dns_answer_count": dns.ancount,
                "dns_authority_count": dns.nscount,
                "dns_additional_count": dns.arcount,
                "dns_query_type": dns.qd.qtype if dns.qd else 0,
            }
        )

        return features

    def _extract_tcp_advanced_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract advanced TCP features"""
        features = {}
        tcp = packet[TCP]

        features.update(
            {
                "tcp_window_size": tcp.window,
                "tcp_urgent_pointer": tcp.urgptr,
                "tcp_sequence_number": tcp.seq,
                "tcp_acknowledgment_number": tcp.ack,
                "tcp_reserved_bits": (tcp.reserved << 1) | ((tcp.flags >> 8) & 1),
                "tcp_checksum": tcp.chksum,
                "tcp_options_count": len(tcp.options) if tcp.options else 0,
            }
        )

        return features
    

    def append_features_row(self, filename: str, features: Dict[str, Any]):
        # Filter & order by module-level EXPECTED_FEATURES
        filtered = {key: features.get(key, 0.0) for key in EXPECTED_FEATURES}
        write_header = not os.path.exists(filename) or os.path.getsize(filename) == 0

        with open(filename, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=EXPECTED_FEATURES)
            if write_header:
                writer.writeheader()
            writer.writerow(filtered)


    def get_flow_summary(self, flow_key: FlowKey) -> Dict[str, Any]:
        """Get comprehensive flow summary for threat detection"""
        if flow_key not in self.flows:
            return {}

        flow_stats = self.flows[flow_key]
        packets = self.flow_packets.get(flow_key, [])

        summary = {
            "flow_key": {
                "src_ip": flow_key.src_ip,
                "dst_ip": flow_key.dst_ip,
                "src_port": flow_key.src_port,
                "dst_port": flow_key.dst_port,
                "protocol": flow_key.protocol,
            },
            "duration": flow_stats.duration,
            "total_packets": flow_stats.total_packets,
            "total_bytes": flow_stats.total_length_forward
            + flow_stats.total_length_backward,
            "packets_per_second": flow_stats.total_packets
            / max(flow_stats.duration, 1),
            "bytes_per_second": (
                flow_stats.total_length_forward + flow_stats.total_length_backward
            )
            / max(flow_stats.duration, 1),
            "forward_backward_ratio": flow_stats.forward_packets
            / max(flow_stats.backward_packets, 1),
            "avg_packet_size": (
                flow_stats.total_length_forward + flow_stats.total_length_backward
            )
            / max(flow_stats.total_packets, 1),
            "tcp_flags_diversity": len(
                [f for f, c in flow_stats.tcp_flags_counts.items() if c > 0]
            ),
            "is_suspicious": self._assess_flow_suspicion(flow_stats, packets),
        }

        return summary

    def _assess_flow_suspicion(
        self, flow_stats: FlowStatistics, packets: List[PacketMetrics]
    ) -> bool:
        """Assess if a flow shows suspicious characteristics"""
        suspicion_score = 0

        # High packet rate
        if flow_stats.duration > 0:
            pps = flow_stats.total_packets / flow_stats.duration
            if pps > 100:  # More than 100 packets per second
                suspicion_score += 2

        # Unusual packet sizes
        all_sizes = (
            flow_stats.forward_packet_lengths + flow_stats.backward_packet_lengths
        )
        if all_sizes:
            avg_size = statistics.mean(all_sizes)
            if avg_size < 64 or avg_size > 1400:  # Very small or large packets
                suspicion_score += 1

        # TCP flag anomalies
        if flow_stats.syn_flag_count > 10:  # Multiple SYN packets
            suspicion_score += 2
        if flow_stats.tcp_flags_counts.get("RST", 0) > 5:  # Multiple resets
            suspicion_score += 1

        # Port scanning indicators
        if len(packets) > 0:
            unique_ports = set()
            for i, pkt in enumerate(packets[-50:]):  # Check last 50 packets
                if hasattr(pkt, "dst_port"):
                    unique_ports.add(pkt.dst_port)
            if len(unique_ports) > 20:  # Accessing many different ports
                suspicion_score += 3

        # Unusual timing patterns
        if flow_stats.flow_iat:
            iat_variance = (
                statistics.variance(flow_stats.flow_iat)
                if len(flow_stats.flow_iat) > 1
                else 0
            )
            if iat_variance < 0.001:  # Very regular timing (possible automation)
                suspicion_score += 1

        return suspicion_score >= 3

    def get_real_time_features(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Get features optimized for real-time prediction"""
        features = self.extract_features(packet)
        if not features:
            return None

        # Select most important features for real-time prediction
        important_features = [
            "Flow_Duration",
            "Total_Fwd_Packets",
            "Total_Backward_Packets",
            "Total_Length_of_Fwd_Packets",
            "Total_Length_of_Bwd_Packets",
            "Fwd_Packet_Length_Max",
            "Fwd_Packet_Length_Mean",
            "Fwd_Packet_Length_Std",
            "Bwd_Packet_Length_Max",
            "Bwd_Packet_Length_Mean",
            "Bwd_Packet_Length_Std",
            "Flow_Bytes_s",
            "Flow_Packets_s",
            "Flow_IAT_Mean",
            "Flow_IAT_25th",
            "Flow_IAT_50th",
            "Flow_IAT_75th",
            "Flow_IAT_Std",
            "Fwd_IAT_Mean",
            "Bwd_IAT_Mean",
            "SYN_Flag_Count",
            "RST_Flag_Count",
            "PSH_Flag_Count",
            "ACK_Flag_Count",
            "URG_Flag_Count",
            "CWE_Flag_Count",
            "Fwd_Packet_Length_25th",
            "Fwd_Packet_Length_50th",
            "Fwd_Packet_Length_75th",
            "Bwd_Packet_Length_25th",
            "Bwd_Packet_Length_50th",
            "Bwd_Packet_Length_75th",
            "Down_Up_Ratio",
            "Average_Packet_Size",
            "unique_destinations_count",
            "connection_rate",
            "port_scan_score",
            "requests_per_minute",
        ]

        # Create feature vector with only important features
        feature_vector = {}
        for feature_name in important_features:
            feature_vector[feature_name] = features.get(feature_name, 0)

        # Add packet-level features for immediate detection
        packet_info = self._extract_basic_info(packet)
        if packet_info:
            feature_vector.update(
                {
                    "packet_size": packet_info["size"],
                    "payload_size": packet_info.get("payload_size", 0),
                    "header_size": packet_info.get("header_size", 0),
                    "protocol_numeric": self._protocol_to_numeric(
                        packet_info.get("protocol", "Other")
                    ),
                    "src_port": packet_info.get("src_port", 0),
                    "dst_port": packet_info.get("dst_port", 0),
                    "is_common_port": self._is_common_port(
                        packet_info.get("dst_port", 0)
                    ),
                    "timestamp": packet_info.get("timestamp", time.time()),
                }
            )

        return feature_vector

    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convert protocol string to numeric value"""
        protocol_map = {
            "TCP": 1,
            "UDP": 2,
            "ICMP": 3,
            "ARP": 4,
            "HTTP": 5,
            "HTTPS": 6,
            "DNS": 7,
            "FTP": 8,
            "SSH": 9,
            "TELNET": 10,
            "SMTP": 11,
            "Other": 0,
        }
        return protocol_map.get(protocol, 0)

    def _is_common_port(self, port: int) -> int:
        """Check if port is commonly used (1) or uncommon (0)"""
        common_ports = {
            20,
            21,
            22,
            23,
            25,
            53,
            67,
            68,
            80,
            110,
            119,
            123,
            143,
            161,
            194,
            220,
            443,
            465,
            587,
            993,
            995,
            3389,
            5432,
            3306,
        }
        return 1 if port in common_ports else 0

    def export_features_csv(self, filename: str, max_flows: int = 1000):
        """Export current flow features to CSV for model training"""
        import csv
        import os

        with self.lock:  # Thread-safe access
            flows_to_export = list(self.flows.items())[:max_flows]  # Copy current state
            if not flows_to_export:
                logger.warning("No flows to export")
                return

        file_exists = os.path.isfile(filename)

        with open(filename, "a", newline="") as csvfile:  # Append mode
            # Get fieldnames from first flow
            sample_flow_key, _ = flows_to_export[0]
            packet_info = {
                "src_ip": sample_flow_key.src_ip,
                "dst_ip": sample_flow_key.dst_ip,
                "src_port": sample_flow_key.src_port,
                "dst_port": sample_flow_key.dst_port,
                "protocol": sample_flow_key.protocol,
            }
            sample_features = self._compute_flow_features(sample_flow_key, packet_info)
            fieldnames = list(sample_features.keys()) + ["Label"]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header only once
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writeheader()

            # Write rows
            count = 0
            for flow_key, _ in flows_to_export:
                packet_info = {
                    "src_ip": flow_key.src_ip,
                    "dst_ip": flow_key.dst_ip,
                    "src_port": flow_key.src_port,
                    "dst_port": flow_key.dst_port,
                    "protocol": flow_key.protocol,
                }
                features = self._compute_flow_features(flow_key, packet_info)
                features = self._ensure_data_types(features)
                features["Label"] = "BENIGN"
                writer.writerow(features)
                count += 1

        logger.info(f"Appended {count} flows to {filename}")

    def _ensure_data_types(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: (float(v) if isinstance(v, (int, float)) else 0.0)
            for k, v in features.items()
            if k != "Label"
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get current extractor statistics"""
        total_flows = len(self.flows)
        total_ips = len(self.ip_behavior)

        if total_flows > 0:
            avg_flow_duration = statistics.mean(
                [f.duration for f in self.flows.values()]
            )
            avg_packets_per_flow = statistics.mean(
                [f.total_packets for f in self.flows.values()]
            )
        else:
            avg_flow_duration = 0
            avg_packets_per_flow = 0

        return {
            "total_flows": total_flows,
            "total_tracked_ips": total_ips,
            "avg_flow_duration": avg_flow_duration,
            "avg_packets_per_flow": avg_packets_per_flow,
            "memory_usage_flows": len(self.flows),
            "memory_usage_packets": sum(
                len(packets) for packets in self.flow_packets.values()
            ),
            "last_cleanup": self.last_cleanup,
        }

    def reset(self):
        """Reset all tracked flows and statistics"""
        with self.lock:
            self.flows.clear()
            self.flow_packets.clear()
            self.ip_behavior.clear()
            logger.info("Feature extractor reset completed")


class ThreatDetector:
    """Real-time threat detection using extracted features"""

    def __init__(
        self, feature_extractor: AdvancedFeatureExtractor, sio_queue: Queue = None
    ):
        self.feature_extractor = feature_extractor
        self.sio_queue = sio_queue  # Optional Socket.IO queue for real-time updates
        self.threat_thresholds = {
            "port_scan_threshold": 50,
            "high_packet_rate": 100,
            "suspicious_packet_size": (0, 64, 1400, 9000),
            "connection_rate_threshold": 10,
            "syn_flood_threshold": 20,
            "dns_amplification_threshold": 100,
        }

        self.detected_threats = deque(maxlen=1000)
        self.threat_stats = defaultdict(int)

    def detect_threats(self, packet: Packet) -> List[Dict[str, Any]]:
        """Detect threats with full context: port, service, severity, and user actions."""
        threats = []

        # === Step 1: Extract features ===
        features = self.feature_extractor.get_real_time_features(packet)
        if not features:
            return threats

        total_packets = features.get("Total_Fwd_Packets", 0) + features.get(
            "Total_Backward_Packets", 0
        )
        flow_duration = features.get("Flow_Duration", 0)
        pps = features.get("Flow_Packets_s", 0)
        syn_count = features.get("SYN_Flag_Count", 0)
        port_scan_score = features.get("port_scan_score", 0)
        dst_port = features.get("dst_port", 0)
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        timestamp = time.time()
        packet_size = features.get("packet_size", 0)
        is_dns_amp = (
            packet.haslayer(UDP)
            and packet.haslayer(DNS)
            and packet[UDP].dport == 53
            and len(packet) > 512
        )

        # === Step 2: Critical ports & services ===
        critical_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-ALT",
        }
        service = critical_ports.get(dst_port, "Unknown")
        is_critical = dst_port in critical_ports

        # === Step 3: Evidence filter ===
        if total_packets < 5 or flow_duration < 1.0:
            return threats

        # === Step 4: Attack Detection Rules ===

        # 4.1 Port Scan
        if port_scan_score > self.threat_thresholds.get("port_scan_threshold", 10):
            threats.append(
                {
                    "type": "PORT_SCAN",
                    "severity": "HIGH" if is_critical else "MEDIUM",
                    "confidence": 0.95,
                    "details": f"Scan on {service} (port {dst_port}) - score {port_scan_score}",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_port" if is_critical else "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.2 DDoS (High packet rate)
        if pps > self.threat_thresholds.get("high_packet_rate", 500):
            threats.append(
                {
                    "type": "DDOS_ATTACK",
                    "severity": "CRITICAL" if is_critical else "HIGH",
                    "confidence": 0.9,
                    "details": f"High packet rate: {pps:.2f} pps targeting {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.3 SYN Flood
        if syn_count > self.threat_thresholds.get("syn_flood_threshold", 100):
            threats.append(
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "details": f"{syn_count} SYN packets to {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.4 Suspicious Packet Size
        if total_packets >= 5 and (packet_size < 64 or packet_size > 1400):
            threats.append(
                {
                    "type": "SUSPICIOUS_PACKET_SIZE",
                    "severity": "MEDIUM",
                    "confidence": 0.65,
                    "details": f"Suspicious size: {packet_size} bytes on {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["monitor_flow"],
                    "timestamp": timestamp,
                }
            )

        # 4.5 DNS Amplification
        if is_dns_amp:
            threats.append(
                {
                    "type": "DNS_AMPLIFICATION",
                    "severity": "HIGH",
                    "confidence": 0.8,
                    "details": f"DNS response >512 bytes: {len(packet)} bytes",
                    "src_ip": src_ip,
                    "dst_port": 53,
                    "service": "DNS",
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # === Step 5: Emit and store threats ===
        for threat in threats:
            self.detected_threats.append(threat)
            self.threat_stats[threat["type"]] += 1
            logger.warning(
                f"THREAT DETECTED: {threat['type']} from {threat['src_ip']} → {threat['service']}:{threat['dst_port']} - {threat['details']}"
            )

            # Send to frontend via Socket.IO (if configured)
            if self.sio_queue:
                self.sio_queue.put_nowait(("threat_detected", threat))

        return threats

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        recent_threats = [
            t for t in self.detected_threats if time.time() - t["timestamp"] <= 3600
        ]  # Last hour

        return {
            "total_threats_detected": len(self.detected_threats),
            "threats_last_hour": len(recent_threats),
            "threat_types": dict(self.threat_stats),
            "most_recent_threats": (
                list(self.detected_threats)[-10:] if self.detected_threats else []
            ),
        }


# Usage example for integration with your packet sniffer
class EnhancedPacketProcessor:
    """Enhanced packet processor with feature extraction and threat detection"""

    def __init__(self):
        self.feature_extractor = AdvancedFeatureExtractor()
        self.threat_detector = ThreatDetector(self.feature_extractor)
        self._pkt_counts: Dict[FlowKey, int] = defaultdict(int)
        self.prediction_model = None  # Placeholder for ML model

        # Define the order of features for the CSV and feature vector preparation.
        # This list must match the keys produced by compute_features, including identifiers.
        

    def load_model(self, model_path: str):
        """Load pre-trained threat detection model"""
        # Placeholder for model loading
        # Example: self.prediction_model = joblib.load(model_path)
        pass

    def process_packet(self, packet: Packet) -> None:
        packet_info = self.feature_extractor._extract_basic_info(packet)

        if not packet_info or not packet_info.get("is_ip_packet"):
            # logger.debug(f"EnhancedPacketProcessor: Skipping non-IP packet: {packet.summary()}")
            return

        # At this point, packet_info is valid and is_ip_packet is True
        flow_key_obj = self.feature_extractor._create_flow_key(packet_info)
        if not flow_key_obj:
            # logger.debug(f"EnhancedPacketProcessor: Could not create flow key for IP packet: {packet.summary()}")
            return

        # Update packet count for the flow
        self._pkt_counts[flow_key_obj] += 1

        # Feed the packet to the feature extractor for real-time updates
        # update_flow is now robust and will return None if it can't process this packet for flow stats
        flow_stats_instance = self.feature_extractor.update_flow(packet)
        if flow_stats_instance is None:
            # logger.debug(f"EnhancedPacketProcessor: update_flow did not process packet: {packet.summary()}")
            # Decrement packet count if update_flow fails after incrementing
            # self._pkt_counts[flow_key_obj] -= 1 # Or handle this state more carefully
            return

        # Check if this packet contains a FIN or RST flag to mark end of flow
        # This check should ideally use packet_info for protocol and flags if available
        # to avoid redundant layer checks, but direct packet access is also common.
        if packet_info.get("protocol") == "TCP":
            tcp_flags = packet_info.get("tcp_flags", 0)  # From _extract_basic_info
            if tcp_flags & (0x01 | 0x04):  # FIN=0x01 (1), RST=0x04 (4)
                # Compute final flow features
                # compute_features signature is (self, flow_key: FlowKey)
                features = self.feature_extractor.compute_features(flow_key_obj)

                # If features are computed successfully, append them to CSV
                # if features:
                #     self.feature_extractor.append_features_row(
                #         "ml_ready_features.csv", features
                #     )

                # Clear flow-specific data to free memory
                self.feature_extractor.clear_flow(flow_key_obj)
                if flow_key_obj in self._pkt_counts:  # Check before deleting
                    del self._pkt_counts[flow_key_obj]

    def prepare_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare aligned feature vector for real-time ML model prediction."""
        vector = []

        for feat_name in EXPECTED_FEATURES:
            raw_value = features.get(feat_name, 0.0)

            if isinstance(raw_value, (int, float)):
                val = float(raw_value) if np.isfinite(raw_value) else 0.0
            elif isinstance(raw_value, str):
                try:
                    val = float(raw_value)
                    if not np.isfinite(val):
                        val = 0.0
                except ValueError:
                    val = 0.0
            elif raw_value is None:
                val = 0.0
            else:
                try:
                    val = float(raw_value)
                    if not np.isfinite(val):
                        val = 0.0
                except (TypeError, ValueError):
                    val = 0.0

            vector.append(val)

        if len(vector) != len(EXPECTED_FEATURES):
            logger.warning(
                f"Feature vector length mismatch. Got: {len(vector)}, Expected: {len(EXPECTED_FEATURES)}"
            )

        return vector


    # x_raw = self._prepare_feature_vector(features)
    # x_scaled = preprocessor.transform([x_raw])
    # pred = model.decision_function(x_scaled)  # or predict_proba, etc.

    def _ensure_data_types(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: (float(v) if isinstance(v, (int, float)) else 0.0)
            for k, v in features.items()
            if k != "Label"
        }

    @staticmethod
    def json_to_custom_csv(json_path, csv_path):
        # Define column order exactly matching your features
        COLUMN_ORDER = [
            "Flow_Duration",
            "Total_Fwd_Packets",
            "Total_Backward_Packets",
            "Total_Length_of_Fwd_Packets",
            "Total_Length_of_Bwd_Packets",
            "Bwd_PSH_Flags",
            "Bwd_URG_Flags",
            "act_data_pkt_fwd",
            "min_seg_size_forward",
            "Init_Win_bytes_forward",
            "Init_Win_bytes_backward",
            "Fwd_Packet_Length_Max",
            "Fwd_Packet_Length_25th",
            "Fwd_Packet_Length_50th",
            "Fwd_Packet_Length_75th",
            "Fwd_Packet_Length_Min",
            "Fwd_Packet_Length_Mean",
            "Fwd_Packet_Length_Std",
            "Bwd_Packet_Length_Max",
            "Bwd_Packet_Length_Min",
            "Bwd_Packet_Length_Mean",
            "Bwd_Packet_Length_25th",
            "Bwd_Packet_Length_50th",
            "Bwd_Packet_Length_75th",
            "Bwd_Packet_Length_Std",
            "Flow_Bytes_s",
            "Flow_Packets_s",
            "Flow_IAT_Mean",
            "Flow_IAT_25th",
            "Flow_IAT_50th",
            "Flow_IAT_75th",
            "Flow_IAT_Std",
            "Flow_IAT_Max",
            "Flow_IAT_Min",
            "Fwd_IAT_Total",
            "Fwd_IAT_Mean",
            "Fwd_IAT_Std",
            "Fwd_IAT_Max",
            "Fwd_IAT_Min",
            "Bwd_IAT_Total",
            "Bwd_IAT_Mean",
            "Bwd_IAT_Std",
            "Bwd_IAT_Max",
            "Bwd_IAT_Min",
            "FIN_Flag_Count",
            "SYN_Flag_Count",
            "RST_Flag_Count",
            "PSH_Flag_Count",
            "ACK_Flag_Count",
            "URG_Flag_Count",
            "CWE_Flag_Count",
            "ECE_Flag_Count",
            "Fwd_Header_Length",
            "Bwd_Header_Length",
            "Fwd_Packets_s",
            "Bwd_Packets_s",
            "Down_Up_Ratio",
            "Average_Packet_Size",
            "Avg_Fwd_Segment_Size",
            "Avg_Bwd_Segment_Size",
            "Active_Mean",
            "Active_Std",
            "Active_Max",
            "Active_Min",
            "Subflow_Fwd_Packets",
            "Subflow_Fwd_Bytes",
            "Subflow_Bwd_Packets",
            "Subflow_Bwd_Bytes",
            "unique_destinations_count",
            "protocols_count",
            "connection_rate",
            "port_scan_score",
            "packet_size_variance",
            "requests_per_minute",
            "tcp_window_size",
            "tcp_urgent_pointer",
            "tcp_sequence_number",
            "tcp_acknowledgment_number",
            "tcp_reserved_bits",
            "tcp_checksum",
            "tcp_options_count",
            "Label",
        ]

        with open(json_path) as f:
            features_list = json.load(f)

        # Process each feature set
        processed = []
        for feat in features_list:
            ordered = OrderedDict()
            for col in COLUMN_ORDER:
                if col == "Label":  # Handle label separately
                    ordered[col] = feat.get(col, "BENIGN")
                else:
                    # Convert to appropriate type
                    value = feat.get(col, 0)
                    if isinstance(value, float):
                        ordered[col] = round(value, 6)
                    else:
                        ordered[col] = value
            processed.append(ordered)

        # Write to CSV
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMN_ORDER)
            writer.writeheader()
            writer.writerows(processed)

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "feature_extractor_stats": self.feature_extractor.get_statistics(),
            "threat_summary": self.threat_detector.get_threat_summary(),
            "model_loaded": self.prediction_model is not None,
        }

    def export_features_to_csv(self, feature_vectors: List[List[float]], filepath: str):
        """
        Exports a list of feature vectors to a CSV file.

        Args:
            feature_vectors: A list of lists, where each inner list is a numerical feature vector.
            filepath: The path to the CSV file.
        """
        if not feature_vectors:
            logger.info("No feature vectors to export.")
            return

        # self.expected_features is used as the header
        header = EXPECTED_FEATURES

        file_exists = os.path.exists(filepath)
        # Check if file is empty only if it exists
        is_empty = not file_exists or os.path.getsize(filepath) == 0

        try:
            with open(filepath, "a", newline="") as csvfile:
                writer = csv.writer(csvfile)
                if is_empty:  # Write header only if file is new or was empty
                    writer.writerow(header)
                writer.writerows(feature_vectors)
            logger.info(
                f"Successfully exported {len(feature_vectors)} feature vectors to {filepath}"
            )
        except IOError as e:
            logger.error(
                f"IOError while exporting features to CSV {filepath}: {e}",
                exc_info=True,
            )
        except Exception as e:
            logger.error(
                f"Unexpected error while exporting features to CSV {filepath}: {e}",
                exc_info=True,
            )
