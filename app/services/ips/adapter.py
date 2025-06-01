# backend/app/services/ips/adapter.py
import asyncio
from typing import Optional
from scapy.all import Packet
from sqlalchemy.ext.asyncio import AsyncSession
from .engine import IPSEngine

class IPSPacketAdapter:
    def __init__(self, ips_engine: IPSEngine):
        self.ips_engine = ips_engine
        self.queue = asyncio.Queue(maxsize=10000)
        self.processing_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start processing packets from the queue"""
        self.processing_task = asyncio.create_task(self._process_packets())

    async def stop(self):
        """Stop processing packets"""
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass

    async def handle_packet(self, packet: Packet, db: AsyncSession):
        """Add packet to the processing queue"""
        await self.queue.put((packet, db))

    async def _process_packets(self):
        """Process packets from the queue"""
        while True:
            try:
                packet, db = await self.queue.get()
                await self.ips_engine.process_packet(packet, db)
            except Exception as e:
                # PROD_CLEANUP: print(f"Error processing packet in IPS: {e}")