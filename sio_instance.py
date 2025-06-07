# sio_instance.py
from socketio import ASGIApp, AsyncServer
import logging
from app.core.config import settings
import os


logger = logging.getLogger(__name__)


sio = AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4000",
        "http://127.0.0.1:4000",
        "https://ecyber.vercel.app",
    ],
    logger=False,
    engineio_logger=settings.DEBUG,
)


async def broadcast_new_alert(alert_data: dict):
    """
    Broadcasts a new alert to all connected Socket.IO clients.
    """
    try:
        # You might want to structure alert_data more formally if needed,
        # e.g., using a Pydantic model, but a dict is fine for Socket.IO.
        await sio.emit("new_alert", alert_data)
        logger.info(f"Broadcasted new alert: {alert_data.get('name', 'Unknown Alert')}")
    except Exception as e:
        logger.error(f"Error broadcasting new alert: {e}", exc_info=True)
