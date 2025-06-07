# backend/app/api/network.py
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from datetime import datetime, timedelta
from typing import List, Optional, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
import asyncio
import json
import socketio
from ..database import get_db
from ..schemas.network import NetworkEvent, NetworkStats
from ..models.network import NetworkEvent as DBEvent
from ..services.monitoring.sniffer import PacketSniffer
from ..core.security import get_current_active_user
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Dependency Setup
def get_sio():
    """This would be overridden in main.py"""
    raise RuntimeError("Socket.IO instance not configured")

def get_packet_sniffer(sio: socketio.AsyncServer = Depends(get_sio)):
    """Dependency to get packet sniffer instance"""
    return PacketSniffer(sio)

@router.get("/events", response_model=List[NetworkEvent], tags=["Network"])
async def get_network_events(
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    threat_class: Optional[str] = Query(None, description="Filter by threat class"),
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_active_user),
):
    """
    Retrieve historical network events with filtering capabilities.
    Returns up to 1000 events matching the specified criteria.
    """
    query = select(DBEvent)
    
    # Apply filters
    filters = []
    if start_time:
        filters.append(DBEvent.timestamp >= start_time)
    if end_time:
        filters.append(DBEvent.timestamp <= end_time)
    if source_ip:
        filters.append(DBEvent.source_ip == source_ip)
    if destination_ip:
        filters.append(DBEvent.destination_ip == destination_ip)
    if protocol:
        filters.append(DBEvent.protocol == protocol)
    if threat_class:
        filters.append(DBEvent.threat_class == threat_class)
    
    if filters:
        query = query.where(*filters)
    
    # Execute query
    result = await db.execute()
    query.order_by(desc(DBEvent.timestamp)).limit(limit)
    return result.scalars().all()

@router.get("/stats", response_model=NetworkStats, tags=["Network"])
async def get_network_statistics(
    sniffer: PacketSniffer = Depends(get_packet_sniffer),
    _=Depends(get_current_active_user),
):
    """
    Get real-time network statistics including:
    - Total packets processed
    - Protocol distribution
    - Top talkers
    - Threat distribution
    - System uptime
    """
    return await sniffer.get_stats()

@router.get("/events/stream", tags=["Network"])
async def stream_network_events(
    sniffer: PacketSniffer = Depends(get_packet_sniffer),
    _=Depends(get_current_active_user),
):
    """
    Stream real-time network events via Server-Sent Events (SSE).
    Provides continuous updates of network activity.
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                stats = await sniffer.get_stats()
                yield f"data: {json.dumps(stats)}\n\n"
                await asyncio.sleep(1)  # Update every second
        except asyncio.CancelledError:
            logger.info("Client disconnected from event stream")
        except Exception as e:
            logger.error(f"Error in event stream: {e}")
            raise

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"}
    )

@router.get("/top-threats", response_model=List[NetworkEvent], tags=["Network"])
async def get_top_threats(
    time_window: int = Query(3600, description="Time window in seconds (default: 1 hour)"),
    limit: int = Query(10, le=50, description="Maximum number of threats to return"),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_active_user),
):
    """
    Get the most significant threats detected in the specified time window.
    Results are ordered by risk score (highest first).
    """
    start_time = datetime.utcnow() - timedelta(seconds=time_window)
    result = await db.execute(
        select(DBEvent)
        .where(DBEvent.timestamp >= start_time)
        .where(DBEvent.is_malicious == True)  # noqa: E712
        .order_by(desc(DBEvent.risk_score))
        .limit(limit)
    )
    return result.scalars().all()

@router.post("/reset", tags=["Network"])
async def reset_statistics(
    sniffer: PacketSniffer = Depends(get_packet_sniffer),
    _=Depends(get_current_active_user),
):
    """
    Reset the packet sniffer statistics counters.
    Maintains existing connections but clears accumulated data.
    """
    await sniffer.clear_stats()
    return {"status": "Statistics reset successfully"}