# packet_sniffer_service.py

import asyncio
import logging
from multiprocessing import Queue
from queue import Empty
from typing import Optional
from socketio import AsyncServer

logger = logging.getLogger(__name__)


class PacketSnifferService:
    def __init__(self, sio: AsyncServer, sio_queue: Queue):
        self.sio = sio
        self.sio_queue = sio_queue
        self._running = False
        self.monitor_task: Optional[asyncio.Task] = None

    @property
    def is_running(self) -> bool:
        """True if the queue-monitoring loop is active."""
        return self._running

    async def start(self) -> None:
        """Start monitoring the queue for packet events."""
        if self._running:
            logger.warning("PacketSnifferService already running")
            return

        self._running = True
        logger.info("PacketSnifferService starting up")
        self.monitor_task = asyncio.create_task(self._monitor_queue())

    async def stop(self) -> None:
        """Stop the queue-monitoring loop and wait for cleanup."""
        if not self._running:
            return

        logger.info("PacketSnifferService shutting down")
        self._running = False

        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
            logger.info("PacketSnifferService monitor task stopped")

    async def _emit_event(self, event) -> None:
        """
        Validate then emit a (event_type, data) tuple into the
        '/packet_sniffer' namespace.
        """
        if not (isinstance(event, tuple) and len(event) == 2):
            logger.error("Malformed event on queue: %r", event)
            return

        event_type, data = event
        ns = "/packet_sniffer"

        # Safely get the set of clients in this namespace
        room_clients = self.sio.manager.rooms.get(ns, set())
        

        try:
            await self.sio.emit(event_type, data, namespace=ns)
        except Exception:
            logger.exception("Failed to emit %s", event_type)

    async def _monitor_queue(self) -> None:
        logger.info("📡 [Service] monitor loop started")
        while self._running:
            try:
                event = await asyncio.to_thread(self.sio_queue.get, True, 1)
                await self._emit_event(event)

            except Empty:
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("🔥 [Service] error in monitor loop")
                await asyncio.sleep(1)
        logger.info("📡 [Service] monitor loop exiting")
