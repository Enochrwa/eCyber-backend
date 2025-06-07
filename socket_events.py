# socket_events.py
import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import socketio
# from app.services.ips.adapter import IPSPacketAdapter
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal
# from app.services.ips.engine import IPSEngine
from app.models.ips import IPSRule, IPSEvent
from sio_instance import sio

logger = logging.getLogger(__name__)


@sio.event
async def connect(sid, environ):
    """Handle new socket.io connections"""
    logger.info(f"Client connected: {sid}")
    await sio.emit("ips_status", {"status": "active"}, room=sid)


@sio.event
async def disconnect(sid):
    """Handle socket.io disconnections"""
    logger.info(f"Client disconnected: {sid}")


def get_socket_app(fastapi_app):
    """Create ASGI app combining FastAPI and Socket.IO"""
    from socketio import ASGIApp

    return ASGIApp(sio, other_asgi_app=fastapi_app)
