import multiprocessing as mp
import queue
import time
import psutil
import cpuinfo
import platform
import math
import win32api
import win32security
import os
import glob
import asyncio
import aiohttp
import socket
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
import socketio
import logging
from collections import deque, OrderedDict
import signal
import json

from ml.feature_extraction import flatten_complex_data
from ...utils.save_to_json import save_telemetry_to_json
from ...utils.map_telemetry_to_frontend import map_to_system_telemetry_format
from ...utils.report import get_24h_network_traffic,get_daily_threat_summary
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SystemMonitor")
IS_WINDOWS = platform.system() == "Windows"


class SystemMonitorProcess(mp.Process):
    """Main monitoring process that collects all system metrics"""

    def __init__(
        self, sio: socketio.AsyncServer, data_queue: mp.Queue, control_queue: mp.Queue
    ):
        super().__init__()
        self.sio = sio
        self.data_queue = data_queue

        self.control_queue = control_queue
        self.running = True
        self.interval = 5  # seconds between updates
        self.history = {
            "cpu": deque(maxlen=60),
            "memory": deque(maxlen=60),
            "network": deque(maxlen=60),
            "disk": deque(maxlen=60),
            "process_count": deque(maxlen=60),
            "user_logins": deque(maxlen=60),
        }
        self.anomaly_thresholds = {
            "cpu": 90,
            "memory": 90,
            "disk": 90,
            "network": 100_000_000,
        }
        self.suspicious_processes = ["mimikatz", "powersploit", "cobaltstrike"]
        self.suspicious_ports = {4444: "Metasploit", 8080: "Webshell", 9999: "C2"}
        self.file_hashes = {}
        self.sensitive_keywords = ["confidential", "password", "secret"]
        self._dns_cache = OrderedDict()
        self._dns_cache_max_size = 1000
        self._dns_cache_ttl = 3600  # 1 hour
        self._dns_lock = mp.Lock()
        self._max_file_size = 250 * 1024 * 1024  # 250MB

        # File hash calculation parameters
        self._hash_buffer_size = 65536

    def run(self):
        """Main process monitoring loop"""
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ignore interrupts in child

        while self.running:
            start_time = time.time()

            try:
                # Check for control commands
                self._check_commands()

                # Collect all system stats
                stats = self.collect_system_stats()

                # Check for anomalies
                stats["anomalies"] = self._check_anomalies(stats)

                # Send data to main process
                self.data_queue.put(stats)

                # Sleep for remaining interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.interval - elapsed)
                time.sleep(sleep_time)

            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(1)

    def _calculate_file_hash(self, file_path: str) -> Optional[Dict[str, str]]:
        """Safe file hashing with large file support and error handling"""
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return None

        try:
            file_size = os.path.getsize(file_path)
            if file_size > self._max_file_size:
                logger.warning(
                    f"File too large for hashing: {file_path} ({file_size/1024/1024:.2f}MB)"
                )
                return None

            sha256 = hashlib.sha256()
            md5 = hashlib.md5()

            with open(file_path, "rb") as f:
                while chunk := f.read(self._hash_buffer_size):
                    sha256.update(chunk)
                    md5.update(chunk)

            return {
                "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest(),
                "file_size": file_size,
                "last_modified": os.path.getmtime(file_path),
            }
        except PermissionError:
            logger.warning(f"Permission denied accessing {file_path}")
            return None
        except OSError as e:
            logger.error(f"File access error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected hashing error: {str(e)}")
            return None

    def _resolve_dns(self, ip: str) -> Optional[str]:
        """Thread-safe DNS resolution with caching and TTL"""
        if not ip or ip.startswith(("127.", "10.", "192.168.")):
            return None

        with self._dns_lock:
            # Check cache and validate TTL
            entry = self._dns_cache.get(ip)
            if entry and (time.time() - entry["timestamp"]) < self._dns_cache_ttl:
                return entry["domain"]

            try:
                # Async-friendly DNS resolution
                domain, _, _ = socket.gethostbyaddr(ip)
                self._dns_cache[ip] = {"domain": domain, "timestamp": time.time()}

                # Maintain cache size
                if len(self._dns_cache) > self._dns_cache_max_size:
                    self._dns_cache.popitem(last=False)

                return domain
            except (socket.herror, socket.gaierror) as e:
                logger.debug(f"DNS resolution failed for {ip}: {str(e)}")
                self._dns_cache[ip] = {"domain": None, "timestamp": time.time()}
                return None
            except Exception as e:
                logger.error(f"Unexpected DNS error: {str(e)}")
                return None

    def _check_commands(self):
        """Process any control commands"""
        try:
            while not self.control_queue.empty():
                cmd = self.control_queue.get_nowait()
                if cmd == "stop":
                    self.running = False
                elif isinstance(cmd, dict) and cmd.get("action") == "set_interval":
                    self.interval = cmd["value"]
        except queue.Empty:
            pass

    def collect_system_stats(self) -> Dict[str, Any]:
        """Collect all system statistics"""
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu": self._get_cpu_stats(),
            "memory": self._get_memory_stats(),
            "disk": self.get_disk_stats(),
            "network": self.get_network_stats(),
            "processes": self.get_process_stats(),
            "process_count": len(self.get_process_stats()),
            "system": self.get_system_info(),
            "security": self._get_security_status(),
        }

        logger.debug(f"Collected stats: {stats}")
        # Update history for anomaly detection
        self._update_history(stats)

        return stats

    def _get_cpu_stats(self) -> Dict:
        """Get comprehensive CPU statistics"""
        cpu_times = psutil.cpu_times_percent(interval=1)
        freq = psutil.cpu_freq()
        load = os.getloadavg() if hasattr(os, "getloadavg") else None

        return {
            "usage": psutil.cpu_percent(interval=1),
            "cores": {
                "physical": psutil.cpu_count(logical=False),
                "logical": psutil.cpu_count(logical=True),
            },
            "times": cpu_times._asdict(),
            "frequency": freq._asdict() if freq else None,
            "load_avg": load,
        }

    def _get_memory_stats(self) -> Dict:
        """Get memory and swap statistics"""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return {
            "total": mem.total,
            "available": mem.available,
            "used": mem.used,
            "percent": mem.percent,
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        }

    def get_disk_stats(self) -> Dict:
        """Get disk usage and IO statistics with robust error handling"""
        partitions = []
        for part in psutil.disk_partitions():
            try:
                # Skip removable drives that might not be ready
                if "cdrom" in part.opts or part.fstype == "":
                    continue

                usage = psutil.disk_usage(part.mountpoint)
                partitions.append(
                    {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "total": usage.total,
                        "used": usage.used,
                        "percent": usage.percent,
                        "status": "active",
                    }
                )
            except Exception as e:
                partitions.append(
                    {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "status": "error",
                        "error": str(e),
                    }
                )

        try:
            io = psutil.disk_io_counters()
            io_stats = io._asdict() if io else None
        except Exception as e:
            io_stats = None
            logger.warning(f"Disk IO stats error: {e}")

        return {"partitions": partitions, "io": io_stats}

    def get_network_stats(self) -> Dict:
        """Get network interface and connection statistics"""
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            try:
                remote_ip = conn.raddr.ip if conn.raddr else None
                domain = self._resolve_dns(remote_ip)

                if conn.status == "ESTABLISHED":
                    connections.append(
                        {
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": (
                                f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn.raddr
                                else None
                            ),
                            "status": conn.status,
                            "pid": conn.pid,
                            "domain": domain,
                            "suspicious": self._is_suspicious_port(conn.laddr.port),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        try:
            io = psutil.net_io_counters()
            io_stats = io._asdict() if io else None
        except Exception as e:
            io_stats = None
            logger.warning(f"Network IO stats error: {e}")

        return {
            "connections": connections,
            "io": io_stats,
            "dns_cache": list(self._dns_cache.items()),
            "arp_table": self._get_arp_table(),
            "interfaces": self._get_network_interfaces(),
        }

    def _resolve_dns(self, ip: str) -> str:
        """Reverse DNS lookup with caching"""
        if ip not in self._dns_cache:
            try:
                self._dns_cache[ip] = socket.gethostbyaddr(ip)[0]
            except:
                self._dns_cache[ip] = ""
        return self._dns_cache[ip]

    def _get_arp_table(self) -> List[Dict]:
        """Get ARP table entries"""
        arp = []
        for line in os.popen("arp -a" if platform.system() != "Windows" else "arp -a"):
            if "dynamic" in line.lower():
                parts = line.split()
                arp.append({"ip": parts[0], "mac": parts[1]})
        return arp

    def _get_network_interfaces(self) -> List[Dict]:
        """Get detailed network interface information"""
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            interfaces.append(
                {
                    "name": name,
                    "addresses": [
                        {
                            "family": addr.family.name,
                            "address": addr.address,
                            "netmask": addr.netmask,
                        }
                        for addr in addrs
                    ],
                    "is_up": stats.isup if stats else False,
                    "speed": stats.speed if stats else 0,
                }
            )
        return interfaces

    def get_process_stats(self) -> List[Dict]:
        """Get process information with security context"""
        processes = []
        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "username",
                "cpu_percent",
                "memory_percent",
                "exe",
                "cmdline",
                "status",
                "ppid",
            ]
        ):
            try:
                info = proc.info
                exe_path = info.get("exe")
                # Compute security-related fields first
                signed = self._check_binary_signature(exe_path) if exe_path else None
                # Add validation for Windows system processes
                if IS_WINDOWS and not self._is_valid_windows_exe(exe_path):
                    bin_hash = None
                    signed = None
                else:
                    bin_hash = self._calculate_file_hash(exe_path) if exe_path else None
                    signed = (
                        self._check_binary_signature(exe_path) if exe_path else None
                    )
                suspicious = any(
                    p.lower() in info["name"].lower() for p in self.suspicious_processes
                )
                cmdline = " ".join(info["cmdline"]) if info.get("cmdline") else ""

                # Calculate risk score with required parameters
                risk_score = self._calculate_process_risk(
                    name=info["name"],
                    cmdline=cmdline,
                    signed=signed,
                    suspicious=suspicious,
                )

                # Build process entry with all fields
                processes.append(
                    {
                        "pid": info["pid"],
                        "name": info["name"],
                        "user": info["username"],
                        "cpu": info["cpu_percent"],
                        "cmdline": cmdline,
                        "ppid": info["ppid"],
                        "memory": info["memory_percent"],
                        "status": info["status"],
                        "bin_hash": bin_hash,
                        "risk_score": risk_score,
                        "suspicious": suspicious,
                        "signed": signed,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(processes, key=lambda p: p["cpu"], reverse=True)[
            :50
        ]  # Top 50 by CPU

    # Add to SystemMonitorProcess class
    def _is_valid_windows_exe(self, path: Optional[str]) -> bool:
        """Check if path belongs to a valid Windows executable"""
        if not path:
            return False

        # Filter known Windows pseudo-processes
        invalid_paths = {
            "System",
            "Registry",
            "MemCompression",
            r"\SystemRoot\System32",
            r"\Device\HarddiskVolume",
        }

        return all(
            not path.startswith(invalid) and not path in invalid_paths
            for invalid in invalid_paths
        ) and os.path.isfile(path)

    def _calculate_process_risk(
        self, name: str, cmdline: str, signed: Optional[bool], suspicious: bool
    ) -> int:
        """Calculate risk score using direct parameters instead of a dict"""
        score = 0
        if suspicious:
            score += 30
        if not signed:  # Now uses the pre-computed 'signed' value
            score += 25
        if "powershell" in cmdline.lower():
            score += 20
        return min(score, 100)

    def _get_system_services(self) -> List[Dict]:
        """Collect running services"""
        services = []
        if platform.system() == "Windows":
            for s in psutil.win_service_iter():
                services.append(
                    {"name": s.name(), "status": s.status(), "binpath": s.binpath()}
                )
        return services

    def get_system_info(self) -> Dict:
        """Get static system information"""
        return {
            "os": platform.system(),
            "hostname": platform.node(),
            "cpu": cpuinfo.get_cpu_info().get("brand_raw", "Unknown"),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "uptime": time.time() - psutil.boot_time(),
            "critical_files": self._check_system_files(),
            "services": self._get_system_services(),
        }

    def _check_system_files(self) -> Dict:
        """Monitor critical system files"""
        targets = {
            "Windows": [r"C:\Windows\System32\*.dll", r"C:\Windows\System32\*.exe"],
            "Linux": ["/bin/*", "/usr/bin/*", "/sbin/*"],
        }
        return {
            fpath: self._calculate_file_hash(fpath)
            for pattern in targets.get(platform.system(), [])
            for fpath in glob.glob(pattern)
        }

    def _get_security_status(self) -> Dict:
        """Get security-related status information"""
        return {
            "firewall": self._check_firewall_status(),
            "updates": self._check_system_updates(),
            "suspicious": {
                "processes": len(
                    [p for p in self.get_process_stats() if p["suspicious"]]
                ),
                "connections": len(
                    [
                        c
                        for c in self.get_network_stats()["connections"]
                        if c["suspicious"]
                    ]
                ),
            },
        }

    def _update_history(self, stats: Dict):
        monitor = SystemMonitor(self.sio)
        """Update historical data for anomaly detection"""
        self.history["cpu"].append(stats["cpu"]["usage"])
        self.history["memory"].append(stats["memory"]["percent"])
        self.history["process_count"].append(len(stats["processes"]))
        self.history["user_logins"].append(len(monitor.get_logged_in_users()))

        if stats["disk"]["partitions"]:
            self.history["disk"].append(stats["disk"]["partitions"][0]["percent"])

        if stats["network"]["io"]:
            net_io = stats["network"]["io"]
            self.history["network"].append(
                (net_io["bytes_sent"] + net_io["bytes_recv"]) / self.interval
            )

    def _check_anomalies(self, stats: Dict) -> List[Dict]:
        """Check system metrics for anomalous patterns"""
        anomalies = []

        # CPU anomaly check
        if len(self.history["cpu"]) > 10:
            avg_cpu = sum(self.history["cpu"]) / len(self.history["cpu"])
            if avg_cpu > self.anomaly_thresholds["cpu"]:
                anomalies.append(
                    {
                        "type": "cpu",
                        "severity": "high",
                        "message": f"Sustained high CPU usage: {avg_cpu:.1f}%",
                    }
                )

        # Check memory usage
        if len(self.history["memory"]) > 10:
            avg_mem = sum(self.history["memory"]) / len(self.history["memory"])
            if avg_mem > self.anomaly_thresholds["memory"]:
                anomalies.append(
                    {
                        "type": "memory",
                        "severity": "high",
                        "message": f"Sustained high memory usage: {avg_mem:.1f}%",
                    }
                )

        # Check network activity
        if len(self.history["network"]) > 10:
            avg_net = sum(self.history["network"]) / len(self.history["network"])
            if avg_net > self.anomaly_thresholds["network"]:
                anomalies.append(
                    {
                        "type": "network",
                        "severity": "medium",
                        "message": f"High network throughput: {avg_net/1000000:.2f} MB/s",
                    }
                )
            if len(self.history["process_count"]) > 100:
                avg_procs = sum(self.history["process_count"][-100:]) / 100
                if stats["process_count"] > avg_procs * 1.5:
                    anomalies.append(
                        {
                            "type": "process_count",
                            "severity": "medium",
                            "message": f"Process count spike: {stats['process_count']} (avg: {avg_procs})",
                        }
                    )

            if anomalies:
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit(
                        "system_alerts",
                        {
                            "timestamp": datetime.utcnow().isoformat(),
                            "alerts": anomalies,
                        },
                    ),
                    asyncio.get_event_loop(),
                )

        return anomalies

    def _check_binary_signature(self, path: str) -> Optional[bool]:
        """Check if binary is signed/trusted (simplified example)"""
        if not path or not os.path.exists(path):
            return None

        trusted_paths = {
            "Windows": [r"C:\Windows\System32", r"C:\Program Files"],
            "Linux": ["/bin", "/usr/bin", "/sbin", "/usr/sbin"],
        }

        system = platform.system()
        return any(path.startswith(p) for p in trusted_paths.get(system, []))

    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly used by malware"""
        return port in self.suspicious_ports

    def _check_firewall_status(self) -> bool:
        """Check if firewall is active (simplified)"""
        try:
            if platform.system() == "Windows":
                import subprocess

                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True,
                    text=True,
                )
                return "ON" in result.stdout
            elif platform.system() == "Linux":
                return any(
                    os.path.exists(f) for f in ["/usr/sbin/ufw", "/usr/bin/firewalld"]
                )
            return False
        except Exception:
            return False

    def _check_system_updates(self) -> bool:
        """Check if system updates are available (simplified)"""
        try:
            if platform.system() == "Linux":
                if os.path.exists("/usr/bin/apt"):
                    return bool(
                        os.popen("apt list --upgradable 2>/dev/null").read().strip()
                    )
            return False
        except Exception:
            return False

    def stop(self):
        """Gracefully stop the monitoring process"""
        self.running = False
        self.control_queue.put("stop")


class SystemMonitor(mp.Process):
    """Main interface for the monitoring system with Socket.IO integration"""

    def __init__(self, sio: socketio.AsyncServer):
        super().__init__()
        self.sio = sio
        self.data_queue = mp.Queue()
        self.control_queue = mp.Queue()
        self.threat_log: List[Dict] = [] 

        # Pass all required arguments in order
        self.monitor_process = SystemMonitorProcess(
            sio=self.sio,  # Required first
            data_queue=self.data_queue,
            control_queue=self.control_queue,
        )
        self.running = False

    async def start(self):
        """Start the monitoring system"""
        if not self.running:
            self.monitor_process.start()
            self.running = True
            asyncio.create_task(self._emit_updates())
            logger.info("System monitor started")

    async def _emit_updates(self):
        """Continuously emit updates to Socket.IO"""
        while self.running:
            try:
                if not self.data_queue.empty():
                    stats = self.data_queue.get_nowait()
                    flattened_telemetry = flatten_complex_data(stats)
                    telemetry = map_to_system_telemetry_format(stats, sample_interval=self.monitor_process.interval)
                    await self.sio.emit("system_telemetry", telemetry)
                await asyncio.sleep(0.1)  # Prevent busy waiting
            except queue.Empty:
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Emit error: {e}")
                await asyncio.sleep(1)

    async def stop(self):
        """Stop the monitoring system"""
        if self.running:
            self.running = False
            self.monitor_process.stop()
            self.monitor_process.join(timeout=5)
            if self.monitor_process.is_alive():
                self.monitor_process.terminate()
            logger.info("System monitor stopped")

    def set_update_interval(self, interval: int):
        """Change the monitoring update interval"""
        if self.running:
            self.control_queue.put({"action": "set_interval", "value": interval})

    ##SYSTEM PROTECTION AGAINST THREATS AND SUSPICIONS

    async def terminate_suspicious_process(self, pid: int, reason: str):
        """Terminate process and notify frontend"""
        try:
            proc = psutil.Process(pid)
            proc_info = {
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
                "username": proc.username(),
            }

            proc.terminate()
            await self.sio.emit(
                "threat_response",
                {
                    "action": "process_terminated",
                    "pid": pid,
                    "reason": reason,
                    "process_info": proc_info,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            await self.sio.emit(
                "threat_error",
                {"action": "process_termination_failed", "pid": pid, "error": str(e)},
            )

    async def block_malicious_connection(
        self, ip: str, port: int, direction: str, reason: str
    ):
        """Block IP connection across platforms"""
        try:
            if platform.system() == "Windows":
                rule_name = f"Block_{ip}_{port}"
                cmd = (
                    f"netsh advfirewall firewall add rule name='{rule_name}' "
                    f"dir={direction} action=block protocol=TCP "
                    f"remoteip={ip} remoteport={port}"
                )
                os.system(cmd)
            elif platform.system() == "Linux":
                if direction == "in":
                    cmd = f"iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP"
                else:
                    cmd = f"iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP"
                os.system(cmd)

            await self.sio.emit(
                "threat_response",
                {
                    "action": "connection_blocked",
                    "ip": ip,
                    "port": port,
                    "direction": direction,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        except Exception as e:
            logger.error(f"Failed to block {ip}:{port}: {e}")
            await self.sio.emit(
                "threat_error", {"action": "block_failed", "ip": ip, "error": str(e)}
            )

    def _check_binary_signature(self, path: str) -> Optional[bool]:
        """Check if binary is signed/trusted (simplified example)"""
        if not path or not os.path.exists(path):
            return None

        trusted_paths = {
            "Windows": [r"C:\Windows\System32", r"C:\Program Files"],
            "Linux": ["/bin", "/usr/bin", "/sbin", "/usr/sbin"],
        }

        system = platform.system()
        return any(path.startswith(p) for p in trusted_paths.get(system, []))

    async def inspect_process(self, pid: int) -> Dict:
        """Deep forensic analysis of a process"""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():  # Optimize multiple property accesses
                analysis = {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cmdline": proc.cmdline(),
                    "username": proc.username(),
                    "connections": [],
                    "threads": proc.num_threads(),
                    "memory_maps": [],
                    "security": {
                        "signed": self._check_binary_signature(proc.exe()),
                        "dlls": self._scan_loaded_dlls(pid),
                    },
                }

                # Network connections
                try:
                    analysis["connections"] = [
                        {
                            "fd": conn.fd,
                            "family": conn.family.name,
                            "local": (
                                f"{conn.laddr.ip}:{conn.laddr.port}"
                                if conn.laddr
                                else None
                            ),
                            "remote": (
                                f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn.raddr
                                else None
                            ),
                            "status": conn.status,
                        }
                        for conn in proc.connections()
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Memory regions
                try:
                    analysis["memory_maps"] = [
                        {"path": m.path, "rss": m.rss, "size": m.size, "perms": m.perms}
                        for m in proc.memory_maps()
                    ][
                        :20
                    ]  # Limit to first 20 regions
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                await self.sio.emit("process_inspection", analysis)
                return analysis  ##THIS MAY BE SENT VIA ROUTES TO USER TO SEE ANALYSIS

        except Exception as e:
            logger.error(f"Process inspection failed for PID {pid}: {e}")
            await self.sio.emit(
                "threat_error",
                {"action": "inspection_failed", "pid": pid, "error": str(e)},
            )
            return None

    async def analyze_connection(self, conn_details: Dict):
        """Deep analysis of network connections"""
        try:
            analysis = {
                **conn_details,
                "geoip": await self._lookup_ip_geo(conn_details.get("remote_ip")),
                "whois": await self._lookup_whois(conn_details.get("remote_ip")),
                "threat_intel": await self._check_threat_feeds(
                    conn_details.get("remote_ip")
                ),
                "protocol_analysis": self._analyze_packet_patterns(conn_details),
            }

            await self.sio.emit("connection_analysis", analysis)
            return analysis  # THIS MUST BE SENT TO USER TOO

        except Exception as e:
            logger.error(f"Connection analysis failed: {e}")
            return None

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate multiple hash types for file identification"""
        hashes = {}
        with open(file_path, "rb") as f:
            data = f.read()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
            hashes["md5"] = hashlib.md5(data).hexdigest()
        return hashes

    async def quarantine_file(self, file_path: str, reason: str):
        """Move file to quarantine with forensic metadata"""
        try:
            quarantine_dir = (
                "/var/quarantine"
                if platform.system() != "Windows"
                else "C:\\Quarantine"
            )
            os.makedirs(quarantine_dir, exist_ok=True)

            file_hash = self._calculate_file_hash(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_name = f"{timestamp}_{os.path.basename(file_path)}.quarantined"
            dest_path = os.path.join(quarantine_dir, new_name)

            # Preserve original metadata
            stat = os.stat(file_path)
            metadata = {
                "original_path": file_path,
                "quarantine_time": datetime.utcnow().isoformat(),
                "file_hash": file_hash,
                "original_perms": oct(stat.st_mode),
                "owner": stat.st_uid,
                "reason": reason,
            }

            # Move file and create metadata
            os.rename(file_path, dest_path)
            with open(f"{dest_path}.meta", "w") as f:
                json.dump(metadata, f)

            await self.sio.emit(
                "file_quarantined",
                {
                    "original_path": file_path,
                    "quarantine_path": dest_path,
                    "metadata": metadata,
                },
            )
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            await self.sio.emit(
                "threat_error",
                {"action": "quarantine_failed", "file": file_path, "error": str(e)},
            )

    async def capture_system_snapshot(self, trigger_event: Dict):
        """Capture complete system state at time of detection"""
        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "trigger_event": trigger_event,
            "processes": self.monitor_process.get_process_stats(),
            "network": self.monitor_process.get_network_stats(),
            "users": self.get_logged_in_users(),
            "system": self.monitor_process.get_system_info(),
            "performance": self._get_performance_metrics(),
        }

        # Save to file
        filename = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(snapshot, f, indent=2)

        await self.sio.emit(
            "system_snapshot",
            {
                "filename": filename,
                "summary": {
                    "process_count": len(snapshot["processes"]),
                    "alert_severity": trigger_event.get("severity", "unknown"),
                },
            },
        )
        return filename

    async def update_threat_dashboard(self):
        """Send aggregated threat intelligence to frontend"""

        while self.running:
            try:
                threats = {
                    "active_processes": len(
                        [
                            p
                            for p in self.monitor_process.get_process_stats()
                            if p.get("is_suspicious")
                        ]
                    ),
                    "blocked_connections": self._get_firewall_block_count(),
                    "quarantined_files": self._get_quarantine_count(),
                    "current_anomalies": self._get_current_anomalies(),
                    "threat_timeline": self._get_recent_threats(),
                }

                await self.sio.emit("threat_dashboard", threats)
                await asyncio.sleep(10)  # Update every 10 seconds

            except Exception as e:
                logger.error(f"Dashboard update failed: {e}")
                await asyncio.sleep(30)

    async def _send_system_stats(self):

        while self.running:
            stats = await self.monitor_process.collect_system_stats()

            # Threat detection logic
            threats = self._detect_threats(stats)
            if threats:
                await self.sio.emit("threat_detected", threats)
                for threat in threats:
                    if threat["severity"] == "critical":
                        await self.trigger_auto_response(threat)
            flattened_telemetry = flatten_complex_data(stats)
            telemetry = map_to_system_telemetry_format(stats, sample_interval=self.monitor_process.interval)
            await self.sio.emit("system_telemetry", telemetry)
            await asyncio.sleep(5)

    async def trigger_auto_response(self, threat: Dict):
        """Automated response based on threat type"""
        response_actions = {
            "malicious_process": lambda: self.terminate_suspicious_process(
                threat["pid"], threat["reason"]
            ),
            "c2_connection": lambda: self.block_malicious_connection(
                threat["ip"], threat["port"], "out", "C2 server connection"
            ),
            "suspicious_file": lambda: self.quarantine_file(
                threat["file_path"], threat["reason"]
            ),
        }

        action = response_actions.get(threat["type"])
        if action:
            await action()
            await self.capture_system_snapshot(threat)

    def _detect_threats(self, stats: Dict) -> List[Dict]:
        """Analyze system state for potential threats"""
        threats = []
        
        now = datetime.utcnow()
        
        # Process analysis
        for proc in stats["processes"][:20]:  # Check top 20 processes
            if proc["is_suspicious"]:
                threats.append(
                    {
                        "type": "malicious_process",
                        "severity": "high",
                        "pid": proc["pid"],
                        "name": proc["name"],
                        "reason": "Matches known malicious process patterns",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        # Network analysis
        for conn in stats["network"]["connections"]:
            if conn["suspicious"]:
                threats.append(
                    {
                        "type": "suspicious_connection",
                        "severity": "medium",
                        "ip": conn["remote"].split(":")[0] if conn["remote"] else None,
                        "port": (
                            int(conn["remote"].split(":")[1])
                            if conn["remote"]
                            else None
                        ),
                        "pid": conn["pid"],
                        "reason": f"Connection to known suspicious port {conn.get('port')}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
        for threat in threats:
            record = {'timestamp': now, **threat}  
            self.threat_log.append(record)

        return threats

    def _scan_loaded_dlls(self, pid: int) -> List[Dict]:
        """Scan loaded libraries/DLLs for suspicious modules"""
        modules = []
        try:
            proc = psutil.Process(pid)

            if platform.system() == "Windows":
                # Windows implementation using psutil
                for m in proc.memory_maps():
                    modules.append(
                        {
                            "path": m.path,
                            "perms": m.perms,
                            "signed": self._check_binary_signature(m.path),
                            "suspicious": any(
                                x in m.path.lower()
                                for x in ["temp", "appdata", "tmp", ".dll"]
                            ),
                        }
                    )
            else:
                # Linux implementation parsing /proc
                maps_file = f"/proc/{pid}/maps"
                if os.path.exists(maps_file):
                    with open(maps_file) as f:
                        for line in f:
                            if ".so" in line or "lib" in line:
                                path = line.strip().split()[-1]
                                if os.path.exists(path):
                                    modules.append(
                                        {
                                            "path": path,
                                            "perms": line.split()[1],
                                            "signed": False,  # Linux binaries typically aren't signed
                                            "suspicious": any(
                                                x in path
                                                for x in [
                                                    "/tmp/",
                                                    "/dev/",
                                                    "libfakeroot",
                                                ]
                                            ),
                                        }
                                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            pass

        return modules

    async def _lookup_ip_geo(self, ip: str) -> Optional[Dict]:
        """Geolocation lookup using free API"""
        if not ip or ip.startswith(("127.", "10.", "192.168.", "172.")):
            return None

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}") as resp:
                    data = await resp.json()
                    return (
                        {
                            "country": data.get("country"),
                            "region": data.get("regionName"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "asn": data.get("as"),
                        }
                        if data.get("status") == "success"
                        else None
                    )
        except Exception as e:
            logger.debug(f"GeoIP lookup failed: {e}")
            return None

    async def _lookup_whois(self, ip: str) -> Optional[Dict]:
        """WHOIS lookup using system whois command"""
        if not ip or ip.startswith(("127.", "10.", "192.168.", "172.")):
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                "whois",
                ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            # Parse common whois fields
            whois_data = {}
            for line in stdout.decode().splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    if key in ["netname", "orgname", "country", "descr"]:
                        whois_data[key] = val.strip()

            return whois_data if whois_data else None
        except Exception as e:
            logger.debug(f"WHOIS lookup failed: {e}")
            return None

    async def _check_threat_feeds(self, ip: str) -> Optional[Dict]:
        """Check IP against threat intelligence feeds"""
        if not ip or ip.startswith(("127.", "10.", "192.168.", "172.")):
            return None

        try:
            async with aiohttp.ClientSession() as session:
                # AbuseIPDB (requires API key in config)
                abuse_resp = await session.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip},
                    headers={"Key": os.getenv("ABUSEIPDB_KEY")},
                )
                abuse_data = await abuse_resp.json()

                # VirusTotal (requires API key)
                vt_resp = await session.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": os.getenv("VIRUSTOTAL_KEY")},
                )
                vt_data = await vt_resp.json()
                async with session.get(
                    f"https://www.hybrid-analysis.com/api/v2/search/terms",
                    params={"host": ip},
                    headers={"api-key": os.getenv("HYBRID_KEY")},
                ) as ha_resp:
                    ha_data = await ha_resp.json()

                return {
                    "abuse_score": abuse_data.get("data", {}).get(
                        "abuseConfidenceScore"
                    ),
                    "vt_malicious": vt_data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                    .get("malicious"),
                    "hybrid_analysis": ha_data.get("result", [])[:3],
                    "is_tor": abuse_data.get("data", {}).get("isTor"),
                    "is_cloud": abuse_data.get("data", {}).get("isCloudProvider"),
                }
        except Exception as e:
            logger.debug(f"Threat feed check failed: {e}")
            return None

    def _analyze_packet_patterns(self, conn: Dict) -> Dict:
        """Analyze network patterns for anomalies"""
        if not conn.get("remote"):
            return {}

        ip, port = conn["remote"].split(":")
        port = int(port)

        # Check for known malicious patterns
        return {
            "beaconing": self._check_beaconing(ip, port),
            "data_exfiltration": port in [21, 22, 53, 80, 443]
            and conn.get("bytes_sent", 0) > 10_000_000,
            "port_hopping": port > 30000 and port < 40000,
            "known_c2_ports": port in [443, 8080, 8443, 53],
            "dns_tunneling": port == 53 and conn.get("bytes_sent", 0) > 1000,
        }

    def get_logged_in_users(self) -> List[Dict]:
        """
        Retrieve a list of currently logged-in users with detailed session information.

        Returns:
            List[Dict]: A list of dictionaries, each containing user session details.
        """
        users = []
        seen = set()

        try:
            for user in psutil.users():
                try:
                    user_info = {
                        "username": user.name,
                        "terminal": user.terminal or "N/A",
                        "host": user.host or "localhost",
                        "login_time": user.started,
                        "session_type": self._get_session_type(user),
                        "login_duration": round(time.time() - user.started, 2),
                    }

                    if IS_WINDOWS:
                        user_info.update(self._get_windows_user_details(user.name))
                    else:
                        user_info.update(self._get_unix_user_details(user.name))

                    # Deduplicate user entries based on key fields
                    key = (
                        user_info["username"],
                        user_info["terminal"],
                        user_info["host"],
                    )
                    if key not in seen:
                        seen.add(key)
                        users.append(user_info)

                except Exception as user_error:
                    logger.debug(f"Error processing user '{user.name}': {user_error}")

        except Exception as e:
            logger.error(f"Failed to retrieve logged-in users: {e}", exc_info=True)
        return users

    def _get_session_type(self, user: psutil._common.suser) -> str:
        """
        Infer session type (console, gui, remote) based on user context.
        """
        if user.host and user.host not in ("localhost", "0.0.0.0", "::1"):
            return "remote"
        if IS_WINDOWS:
            return "console"
        if user.terminal and user.terminal.startswith(":"):
            return "gui"
        return "console"

    def _get_windows_user_details(self, username: str) -> Dict:
        """
        Return additional user information for Windows systems.
        Requires `pywin32`, fallback to minimal info if unavailable.
        """
        try:
            sid, domain, _ = win32security.LookupAccountName(None, username)
            return {"domain": domain, "sid": win32security.ConvertSidToStringSid(sid)}
        except ImportError:
            logger.warning("pywin32 not installed; skipping Windows user details.")
        except Exception as e:
            logger.debug(f"Failed to retrieve Windows details for {username}: {e}")
        return {}

    def _get_unix_user_details(self, username: str) -> Dict:
        """
        Return additional user information for Unix-like systems using the `pwd` module.
        """
        import pwd

        try:
            pw = pwd.getpwnam(username)
            return {
                "uid": pw.pw_uid,
                "gid": pw.pw_gid,
                "home_dir": pw.pw_dir,
                "shell": pw.pw_shell,
            }
        except KeyError:
            logger.debug(f"User '{username}' not found in /etc/passwd.")
        except Exception as e:
            logger.debug(f"Failed to retrieve Unix details for {username}: {e}")
        return {}

    def _get_performance_metrics(self) -> Dict:
        """Calculate comprehensive performance metrics"""

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = max(
            [
                p["usage_percent"]
                for p in self.monitor_process.get_disk_stats()["partitions"]
            ]
            or [0]
        )

        # Calculate weighted performance score (0-100)
        score = 100 - ((cpu * 0.4) + (mem * 0.3) + (disk * 0.3))

        return {
            "score": round(score, 1),
            "cpu_usage": cpu,
            "memory_usage": mem,
            "disk_usage": disk,
            "status": (
                "excellent"
                if score > 90
                else "good" if score > 70 else "fair" if score > 50 else "poor"
            ),
        }

    def _get_firewall_block_count(self) -> int:
        """Get count of currently blocked connections"""
        try:
            if platform.system() == "Windows":
                output = os.popen(
                    "netsh advfirewall firewall show rule name=all"
                ).read()
                return output.count("Block")
            else:
                output = os.popen("iptables -L -n -v | grep DROP").read()
                return len(output.splitlines())
        except:
            return 0

    def _get_quarantine_count(self) -> int:
        """Count quarantined files"""
        quarantine_dir = (
            "/var/quarantine" if platform.system() != "Windows" else "C:\\Quarantine"
        )
        try:
            return len(
                [f for f in os.listdir(quarantine_dir) if f.endswith(".quarantined")]
            )
        except:
            return 0

    def _get_current_anomalies(self) -> List[Dict]:
        """Get currently detected anomalies"""
        stats = self.monitor_process.collect_system_stats()  # Reuse existing method
        return self._detect_threats(stats)  # Reuse threat detection

    def _get_recent_threats(self, limit: int = 5) -> List[Dict]:
        """Get recent threats from log"""
        try:
            with open("threat_log.json", "r") as f:
                return [json.loads(line) for line in f.readlines()[-limit:]]
        except:
            return []

    def _check_beaconing(self, ip: str, port: int) -> bool:
        """Detect periodic beaconing behavior with advanced pattern analysis"""
        if not hasattr(self, "_connection_history"):
            self._connection_history = {}  # Stores {ip: [timestamps]}

        now = time.time()

        # Initialize history for this IP if needed
        if ip not in self._connection_history:
            self._connection_history[ip] = {
                "timestamps": deque(maxlen=50),  # Track last 50 connections
                "intervals": deque(maxlen=10),  # Track last 10 intervals
                "first_seen": now,
            }

        # Record current connection
        history = self._connection_history[ip]
        history["timestamps"].append(now)

        # Need at least 5 data points for analysis
        if len(history["timestamps"]) < 5:
            return False

        # Calculate intervals between connections
        intervals = []
        prev_time = history["timestamps"][0]
        for t in list(history["timestamps"])[1:]:
            intervals.append(t - prev_time)
            prev_time = t
        history["intervals"].extend(intervals)

        # Beaconing detection heuristics
        beaconing_score = 0

        # 1. Check for regular periodicity (low standard deviation)
        if len(intervals) >= 3:
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance**0.5

            # More points for tighter intervals (likely beaconing)
            if std_dev < 5:  # Very consistent timing
                beaconing_score += 3
            elif std_dev < 15:  # Moderately consistent
                beaconing_score += 1

        # 2. Check for common C2 intervals (e.g., 5s, 30s, 1m, 5m)
        common_intervals = [5, 10, 15, 30, 60, 300, 600, 1800]
        for interval in intervals[-3:]:  # Check last 3 intervals
            for common in common_intervals:
                if abs(interval - common) < (
                    common * 0.2
                ):  # Within 20% of common interval
                    beaconing_score += 2
                    break

        # 3. Check for small, consistent payload sizes (if available)
        if hasattr(self, "_connection_sizes") and ip in self._connection_sizes:
            sizes = self._connection_sizes[ip]
            if len(sizes) > 3:
                size_variance = sum(
                    (x - sum(sizes) / len(sizes)) ** 2 for x in sizes
                ) / len(sizes)
                if size_variance < 100:  # Very consistent payload sizes
                    beaconing_score += 2

        # 4. Check for known malicious ports
        if port in [443, 8080, 8443, 53]:  # Common C2 ports
            beaconing_score += 1

        # 5. Check for low-entropy domains (if DNS resolution available)
        if hasattr(self, "_dns_cache") and ip in self._dns_cache:
            domain = self._dns_cache[ip]
            if domain and len(domain) > 10:
                entropy = self._calculate_entropy(domain)
                if entropy < 2.5:  # Low entropy domains often used by malware
                    beaconing_score += 2

        # Threshold for beaconing detection (adjust based on testing)
        return beaconing_score >= 5

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        prob = [
            float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))
        ]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def _update_connection_size(self, ip: str, size: int):
        """Track connection payload sizes for analysis"""
        if not hasattr(self, "_connection_sizes"):
            self._connection_sizes = {}
        if ip not in self._connection_sizes:
            self._connection_sizes[ip] = deque(maxlen=20)
        self._connection_sizes[ip].append(size)

    def _update_dns_cache(self, ip: str, domain: str):
        """Maintain DNS resolution cache"""
        if not hasattr(self, "_dns_cache"):
            self._dns_cache = {}
        self._dns_cache[ip] = domain
