from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Dict
from datetime import datetime, timedelta
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..services.detection.signature import SignatureEngine
from ..database import get_db
from ..models.log import NetworkLog

router = APIRouter()
signature_engine = SignatureEngine()


@router.get("/", response_model=List[Dict])
async def get_threats(
    db: AsyncSession = Depends(get_db),
    limit: int = 100,
    severity: str = None,
    time_range: str = "24h",
):
    """Get detected threats with filtering options"""
    # Calculate time filter
    if time_range == "1h":
        time_filter = datetime.utcnow() - timedelta(hours=1)
    elif time_range == "24h":
        time_filter = datetime.utcnow() - timedelta(hours=24)
    elif time_range == "7d":
        time_filter = datetime.utcnow() - timedelta(days=7)
    else:
        time_filter = datetime.utcnow() - timedelta(hours=24)

    # Build base query
    stmt = (
        select(NetworkLog)
        .where(NetworkLog.timestamp >= time_filter)
        .order_by(desc(NetworkLog.timestamp))
    )

    # Apply severity filter if provided
    if severity:
        stmt = stmt.where(NetworkLog.threat_type.ilike(f"%{severity}%"))

    # Execute query
    result = await db.execute(stmt.limit(limit))
    threats = result.scalars().all()

    return [
        {
            "id": threat.id,
            "timestamp": threat.timestamp.isoformat(),
            "threat_type": threat.threat_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "protocol": threat.protocol,
            "raw_data": (
                threat.raw_data[:500] + "..."
                if len(threat.raw_data) > 500
                else threat.raw_data
            ),
        }
        for threat in threats
    ]


@router.get("/rules", response_model=List[Dict])
async def get_signature_rules():
    """Get all signature-based detection rules"""
    return signature_engine.get_rules()


@router.post("/rules")
async def add_signature_rule(rule: Dict):
    """Add a new signature rule"""
    if signature_engine.add_rule(rule):
        return JSONResponse(
            content={"status": "success", "message": "Rule added successfully"},
            status_code=201,
        )
    else:
        raise HTTPException(status_code=400, detail="Failed to add rule")


@router.get("/summary", response_model=Dict)
async def get_threat_summary(db: AsyncSession = Depends(get_db)):
    """Get threat summary statistics"""
    # Last 24 hours
    time_filter = datetime.utcnow() - timedelta(hours=24)

    # Total threats count
    total_result = await db.execute(
        select(func.count())
        .select_from(NetworkLog)
        .where(NetworkLog.timestamp >= time_filter)
    )
    total_threats = total_result.scalar_one()

    # Group by threat type
    threat_types_result = await db.execute(
        select(NetworkLog.threat_type, func.count(NetworkLog.id).label("count"))
        .where(NetworkLog.timestamp >= time_filter)
        .group_by(NetworkLog.threat_type)
    )
    threat_types = threat_types_result.all()

    return {
        "total_threats": total_threats,
        "threat_types": [{"type": t[0], "count": t[1]} for t in threat_types],
        "time_range": "24h",
    }
