# packet_sniffer_events.py
import logging
from socketio import AsyncNamespace
from multiprocessing import Manager, Queue
from typing import Any, Dict

logger = logging.getLogger(__name__)


class PacketSnifferNamespace(AsyncNamespace):
    def __init__(self, namespace: str, sio_queue: Queue):
        super().__init__(namespace)
        self.sio_queue = sio_queue

