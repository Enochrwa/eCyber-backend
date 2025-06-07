# reporter.py

import time
from datetime import datetime
from collections.abc import Mapping, Iterable
from multiprocessing.managers import DictProxy, ListProxy
from multiprocessing import Event
import signal
from scapy.all import wrpcap, Packet, Queue

import os
def default_asn():
    return {"asn": 0, "org": "Unknown"}


def default_geo():
    return {"country": "Unknown", "city": "Unknown"}


# reporter.py

def _serialize(obj):
    """Recursively serialize objects while handling tuple keys and Manager proxies"""
    if isinstance(obj, datetime):
        return obj.isoformat()

    # Convert Manager proxies to native types first
    if isinstance(obj, (DictProxy, ListProxy)):
        obj = dict(obj) if isinstance(obj, DictProxy) else list(obj)

    # Handle dictionaries and convert tuple keys
    if isinstance(obj, Mapping):
        return {
            _safe_key(k): _serialize(v)
            for k, v in obj.items()
        }

    # Handle other iterables
    if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes)):
        return [_serialize(item) for item in obj]

    return obj

def _safe_key(key):
    """Convert non-JSON-safe keys to strings"""
    if isinstance(key, tuple):
        return '|'.join(str(x) for x in key)
    if isinstance(key, (int, float, bool, type(None))):
        return key
    return str(key)

def _reporter_loop(sio_queue, stats_proxy, stop_event, interval: float = 5.0):
    """
    Runs in its own Process. Periodically snapshots `stats_proxy`
    (a Manager().dict proxy), serializes it, and pushes to sio_queue.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    while not stop_event.is_set():
        try:
            # make a shallow copy of the current stats
            snapshot = dict(stats_proxy)

            # convert datetimes and proxies into JSON-safe types
            serialized_snapshot = _serialize(snapshot)

            # enqueue for the socket-emitter service
            sio_queue.put(("system_stats", serialized_snapshot))
        # except KeyboardInterrupt:
        #     # swallow it and let the loop continue or break
        #     break
        except Exception as e:
            # no logger in child; fall back to print
            print("Reporter loop error:", e)
        stop_event.wait(interval)
