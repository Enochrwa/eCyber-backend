# telemetry_formatter.py
# Standalone module to map raw telemetry stats into frontend-friendly format
from datetime import datetime
from typing import Any, Dict, List, Optional


def generate_history(
    values: List[float], interval: float, now: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Convert a sequence of metric values into DataPoint dicts for the frontend.

    Args:
        values: Numeric samples (e.g. CPU usage % history).
        interval: Seconds between each sample.
        now: Optional current time (UTC) for testing; defaults to datetime.utcnow().

    Returns:
        List of {
            "timestamp": int(ms since epoch),
            "value": float
        }.
    """
    now = now or datetime.utcnow()
    now_ms = int(now.timestamp() * 1000)
    interval_ms = int(interval * 1000)
    length = len(values)
    return [
        {
            "timestamp": now_ms - (length - idx - 1) * interval_ms,
            "value": float(val),
        }
        for idx, val in enumerate(values)
    ]


def format_disk_io(
    disk_stats: Dict[str, Any], now: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Format disk I/O counters into chart-friendly structure.

    Args:
        disk_stats: Output from get_disk_stats(), with an 'io' dict.
        now: Optional current time for timestamp labels.

    Returns:
        {
            "read": [MB_read],
            "write": [MB_written],
            "timestamps": [str(HH:MM)]
        }.
    """
    now = now or datetime.utcnow()
    io = disk_stats.get("io") or {}
    ts = now.strftime("%H:%M")
    return {
        "read": [io.get("read_bytes", 0) / (1024**2)],
        "write": [io.get("write_bytes", 0) / (1024**2)],
        "timestamps": [ts],
    }


def format_processes(procs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map raw process entries into frontend ProcessItem dicts.

    Args:
        procs: List from get_process_stats().

    Returns:
        List of {
            "pid", "name", "user", "cpu", "memory", "status", "signed", "suspicious"
        }.
    """
    formatted: List[Dict[str, Any]] = []
    for p in procs:
        formatted.append(
            {
                "pid": p.get("pid"),
                "name": p.get("name", ""),
                "user": p.get("user") or p.get("username") or "",
                "cpu": p.get("cpu", 0.0),
                "memory": p.get("memory", 0.0),
                "status": p.get("status"),
                "signed": p.get("signed"),
                "suspicious": p.get("suspicious", False),
            }
        )
    return formatted


def format_connections(conns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map network connections into frontend NetworkConnection dicts.

    Args:
        conns: List from get_network_stats()["connections"].

    Returns:
        List of {
            "localAddress", "remoteAddress", "status", "pid", "process",
            "suspicious", "isInternal"
        }.
    """
    formatted: List[Dict[str, Any]] = []
    for c in conns:
        local = c.get("local", "")
        remote = c.get("remote", "")
        ip = remote.split(":", 1)[0]
        is_internal = ip.startswith(("10.", "192.168.", "172."))
        formatted.append(
            {
                "localAddress": local,
                "remoteAddress": remote,
                "status": c.get("status", ""),
                "pid": c.get("pid"),
                "process": c.get("domain") or "",
                "suspicious": c.get("suspicious", False),
                "isInternal": is_internal,
            }
        )
    return formatted


def format_interfaces(ifaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Format network interface info into frontend NetworkInterface dicts.

    Args:
        ifaces: Output from get_network_stats()["interfaces"].

    Returns:
        List of {
            "name", "ipAddress", "macAddress", "speed", "is_up", "status", "addresses", "stats"
        }.
    """
    formatted: List[Dict[str, Any]] = []
    for iface in ifaces:
        addresses = iface.get("addresses", [])
        ip = next((a["address"] for a in addresses if a.get("family") == "AF_INET"), "")
        mac = next(
            (a["address"] for a in addresses if a.get("family") == "AF_LINK"), ""
        )
        up = iface.get("is_up", False)
        formatted.append(
            {
                "name": iface.get("name", ""),
                "ipAddress": ip,
                "macAddress": mac,
                "speed": iface.get("speed", 0),
                "is_up": up,
                "status": "up" if up else "down",
                "addresses": addresses,
                "stats": iface.get("stats"),
            }
        )
    return formatted


def format_security(stats: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract security overview for the frontend.

    Args:
        stats: Full output of collect_system_stats().

    Returns:
        {
            "firewall", "suspiciousConnections", "suspiciousProcesses", "systemUpdates"
        }.
    """
    sec = stats.get("security", {})
    sus = sec.get("suspicious", {})
    return {
        "firewall": "Enabled" if sec.get("firewall") else "Disabled",
        "suspiciousConnections": sus.get("connections", 0),
        "suspiciousProcesses": sus.get("processes", 0),
        "systemUpdates": "Enabled" if sec.get("updates") else "Disabled",
    }


def map_to_system_telemetry_format(
    stats: Dict[str, Any], sample_interval: float
) -> Dict[str, Any]:
    """
    Build a SystemTelemetryData payload from raw stats.

    Args:
        stats: Raw stats dict from collect_system_stats().
        sample_interval: Seconds between history samples.

    Returns:
        Dict matching the frontend's SystemTelemetryData interface.
    """
    # Prepare overview cards
    overview = [
        {
            "title": "CPU Usage",
            "value": f"{stats['cpu']['usage']:.1f}%",
            "color": "var(--chart-purple)",
            "icon": "cpu",
            "details": f"{stats['cpu']['cores']['physical']} physical, {stats['cpu']['cores']['logical']} logical",
        },
        {
            "title": "Memory Usage",
            "value": f"{stats['memory']['percent']:.1f}%",
            "color": "var(--chart-red)",
            "icon": "memory",
            "details": f"{stats['memory']['used']//(1024**3)} GB used of {stats['memory']['total']//(1024**3)} GB",
        },
        {
            "title": "Disk Usage",
            "value": f"{stats['disk']['partitions'][0]['percent']:.1f}%",
            "color": "var(--chart-green)",
            "icon": "disk",
            "details": f"{stats['disk']['partitions'][0]['used']//(1024**3)} GB used",
        },
        {
            "title": "Network",
            "value": f"{(stats['network']['io']['bytes_recv']/(1024**2)):.1f} MB recv",
            "color": "var(--chart-yellow)",
            "icon": "network",
            "details": f"{(stats['network']['io']['bytes_sent']/(1024**2)):.1f} MB sent",
        },
        {
            "title": "System Uptime",
            "value": f"{int(stats['system']['uptime']//3600)}h {int((stats['system']['uptime']%3600)//60)}m",
            "color": "var(--chart-blue)",
            "icon": "clock",
        },
    ]

    return {
        "systemOverview": overview,
        "cpuHistory": generate_history([stats["cpu"]["usage"]], sample_interval),
        "memoryHistory": generate_history(
            [stats["memory"]["percent"]], sample_interval
        ),
        "diskIO": format_disk_io(stats["disk"]),
        "networkIO": {
            "timestamp": int(datetime.utcnow().timestamp() * 1000),
            "sent": stats["network"]["io"]["bytes_sent"],
            "received": stats["network"]["io"]["bytes_recv"],
        },
        "processes": format_processes(stats["processes"]),
        "networkConnections": format_connections(stats["network"]["connections"]),
        "networkInterfaces": format_interfaces(stats["network"]["interfaces"]),
        "securityOverview": format_security(stats),
        "anomalies": stats.get("anomalies", []),
        "cpuDetails": stats["cpu"],
        "memoryDetails": stats["memory"],
    }
