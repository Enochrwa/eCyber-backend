from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from app.services.monitoring.sniffer import PacketSniffer
from app.core.dependencies import get_packet_sniffer
from utils.get_system_info import get_system_info

router = APIRouter()


@router.get("/stats", response_model=dict)
async def get_system_stats(sniffer: PacketSniffer = Depends(get_packet_sniffer)):
    """Get current system statistics"""
    return sniffer.get_stats()


@router.get("/system_info")
def system_status():
    return get_system_info()
