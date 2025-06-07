# backend/app/services/prevention/app_blocker.py
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
import socketio
import asyncio

from ...models.blocklist import BlockedIP
from ...database import AsyncSessionLocal  # Make sure this is properly defined

class ApplicationBlocker:
    def __init__(self, sio: socketio.AsyncServer):
        self.sio = sio
        self.block_duration = timedelta(hours=1)  # Default block duration

    async def add_to_blocklist(self, ip: str, reason: str = "IPS Block") -> bool:
        """Add IP to application-level blocklist with automatic expiration"""
        async with AsyncSessionLocal() as db:
            try:
                # Check if already blocked
                existing = await db.execute(
                    select(BlockedIP).where(BlockedIP.ip == ip)
                )
                if existing.scalar_one_or_none():
                    return True

                # Add new block
                blocked_ip = BlockedIP(
                    ip=ip,
                    reason=reason,
                    blocked_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + self.block_duration
                )
                db.add(blocked_ip)
                await db.commit()

                # Send real-time event
                await self.emit_block_event("BLOCK_ADDED", ip, reason, blocked_ip.expires_at)

                # Schedule automatic unblock
                asyncio.create_task(self._remove_after_expiry(ip))
                return True

            except Exception as e:
                await self.emit_block_error(ip, str(e))
                return False

    async def _remove_after_expiry(self, ip: str):
        """Background task to remove block after expiration"""
        await asyncio.sleep(self.block_duration.total_seconds())
        async with AsyncSessionLocal() as db:
            try:
                await db.execute(
                    delete(BlockedIP).where(BlockedIP.ip == ip)
                )
                await db.commit()
                await self.emit_block_event("BLOCK_EXPIRED", ip)
            except Exception as e:
                await self.emit_block_error(ip, str(e))

    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIP)
                .where(BlockedIP.ip == ip)
                .where(BlockedIP.expires_at > datetime.utcnow())
            )
            return result.scalar_one_or_none() is not None

    async def emit_block_event(self, event_type: str, ip: str, reason: str = None, expires_at: datetime = None):
        """Helper to emit block events"""
        event_data = {
            "type": event_type,
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        if reason:
            event_data["reason"] = reason
        if expires_at:
            event_data["expires_at"] = expires_at.isoformat()
        await self.sio.emit("app_block_event", event_data)

    async def emit_block_error(self, ip: str, error: str):
        """Helper to emit error events"""
        await self.sio.emit(
            "app_block_error",
            {"error": error, "ip": ip, "timestamp": datetime.utcnow().isoformat()}
        )