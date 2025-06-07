from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Optional, Any 

def handle_network_history(stats):
    # In your SystemMonitor __init__ (or as module-level globals):
    network_history = deque()  # each entry: (timestamp:datetime, bytes_sent:int, bytes_recv:int)

    # In your _emit_updates loop, right after you retrieve stats:
    now = datetime.utcnow()
    bytes_sent = stats['network']['io']['bytes_sent']
    bytes_recv = stats['network']['io']['bytes_recv']

    # Append new sample
    network_history.append((now, bytes_sent, bytes_recv))

    # Purge anything older than 24h
    cutoff = now - timedelta(hours=24)
    while network_history and network_history[0][0] < cutoff:
        network_history.popleft()
    return network_history


def get_24h_network_traffic(stats) -> Dict[str, float]:
    """
    Returns total MB sent and received over the last 24 hours.
    """
    network_history = handle_network_history(stats)
    if len(network_history) < 2:
        return {"sent_mb": 0.0, "recv_mb": 0.0}

    # Use oldest vs newest sample
    t0, sent0, recv0 = network_history[0]
    tn, sentn, recvn = network_history[-1]
    return {
        "sent_mb": (sentn - sent0) / (1024**2),
        "recv_mb": (recvn - recv0) / (1024**2),
    }


def get_daily_threat_summary(self) -> Dict[str, Any]:
    """
    Returns today's threats grouped by severity, and full details.
    """
    today = datetime.utcnow().date()
    today_threats = [t for t in self.threat_log if t["timestamp"].date() == today]

    summary = {
        "critical": [],
        "warning": [],
        "info": [],
    }
    for t in today_threats:
        sev = t.get("severity", "info").lower()
        if sev not in summary:
            sev = "info"
        summary[sev].append(t)

    return {
        "counts": {sev: len(lst) for sev, lst in summary.items()},
        "details": summary,
    }
