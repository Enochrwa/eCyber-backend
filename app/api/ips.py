# backend/app/api/ips.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from app.database import get_db
from app.schemas.ips import (
    IPSRule, IPSRuleCreate, IPSRuleUpdate, 
    IPSEvent, IPSStats
)
from app.models.ips import IPSRule as DBRule, IPSEvent as DBEvent
# from ..services.ips.engine import IPSEngine

router = APIRouter()
logger = logging.getLogger("ips_api")

@router.post("/rules/", response_model=IPSRule, tags=["IPS"])
async def create_ips_rule(
    rule: IPSRuleCreate, 
    db: AsyncSession = Depends(get_db)
):
    """Create a new IPS rule"""
    try:
        # Check if rule ID already exists
        existing = await db.execute(
            select(DBRule).where(DBRule.rule_id == rule.rule_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail=f"Rule with ID {rule.rule_id} already exists"
            )
            
        db_rule = DBRule(**rule.dict())
        db.add(db_rule)
        await db.commit()
        await db.refresh(db_rule)
        
        # Reload rules in engine
        ips_engine: IPSEngine = Depends(get_ips_engine)
        await ips_engine.load_rules(db)
        
        return db_rule
    except Exception as e:
        logger.error(f"Error creating IPS rule: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to create IPS rule"
        )

@router.get("/rules/", response_model=List[IPSRule], tags=["IPS"])
async def list_ips_rules(
    active_only: bool = True,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List all IPS rules with optional filtering"""
    try:
        query = select(DBRule)
        
        if active_only:
            query = query.where(DBRule.is_active == True)
            
        if search:
            query = query.where(
                or_(
                    DBRule.name.ilike(f"%{search}%"),
                    DBRule.description.ilike(f"%{search}%"),
                    DBRule.rule_id.ilike(f"%{search}%")
                )
            )
            
        result = await db.execute(
            query.order_by(DBRule.updated_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    except Exception as e:
        logger.error(f"Error listing IPS rules: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve IPS rules"
        )

@router.get("/rules/{rule_id}", response_model=IPSRule, tags=["IPS"])
async def get_ips_rule(
    rule_id: str, 
    db: AsyncSession = Depends(get_db)
):
    """Get details of a specific IPS rule"""
    try:
        result = await db.execute(
            select(DBRule).where(DBRule.rule_id == rule_id)
        )
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(
                status_code=404, 
                detail="Rule not found"
            )
        return rule
    except Exception as e:
        logger.error(f"Error getting IPS rule {rule_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve IPS rule"
        )

@router.put("/rules/{rule_id}", response_model=IPSRule, tags=["IPS"])
async def update_ips_rule(
    rule_id: str,
    rule_update: IPSRuleUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing IPS rule"""
    try:
        result = await db.execute(
            select(DBRule).where(DBRule.rule_id == rule_id)
        )
        db_rule = result.scalar_one_or_none()
        if not db_rule:
            raise HTTPException(
                status_code=404, 
                detail="Rule not found"
            )
            
        update_data = rule_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_rule, field, value)
            
        db_rule.updated_at = datetime.now()
        await db.commit()
        await db.refresh(db_rule)
        
        # Reload rules in engine
        ips_engine: IPSEngine = Depends(get_ips_engine)
        await ips_engine.load_rules(db)
        
        return db_rule
    except Exception as e:
        logger.error(f"Error updating IPS rule {rule_id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to update IPS rule"
        )

@router.get("/events/", response_model=List[IPSEvent], tags=["IPS"])
async def list_ips_events(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    mitigated: Optional[bool] = None,
    false_positive: Optional[bool] = None,
    hours: int = 24,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List IPS events with filtering options"""
    try:
        time_threshold = datetime.now() - timedelta(hours=hours)
        query = select(DBEvent).where(
            DBEvent.timestamp >= time_threshold
        )
        
        # Apply filters
        if severity:
            query = query.where(DBEvent.severity == severity)
        if category:
            query = query.where(DBEvent.category == category)
        if rule_id:
            query = query.where(DBEvent.rule_id == rule_id)
        if source_ip:
            query = query.where(DBEvent.source_ip == source_ip)
        if destination_ip:
            query = query.where(DBEvent.destination_ip == destination_ip)
        if mitigated is not None:
            query = query.where(DBEvent.mitigated == mitigated)
        if false_positive is not None:
            query = query.where(DBEvent.false_positive == false_positive)
            
        result = await db.execute(
            query.order_by(DBEvent.timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    except Exception as e:
        logger.error(f"Error listing IPS events: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve IPS events"
        )

@router.get("/stats/", response_model=IPSStats, tags=["IPS"])
async def get_ips_stats(
    hours: int = 24,
    db: AsyncSession = Depends(get_db)
):
    """Get statistical overview of IPS activity"""
    try:
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        # Total events
        total = await db.execute(
            select(func.count(DBEvent.id))
            .where(DBEvent.timestamp >= time_threshold)
        )
        
        # Severity breakdown
        severities = ["critical", "high", "medium", "low", "info"]
        severity_counts = {}
        for severity in severities:
            count = await db.execute(
                select(func.count(DBEvent.id))
                .where(
                    and_(
                        DBEvent.timestamp >= time_threshold,
                        DBEvent.severity == severity
                    )
                )
            )
            severity_counts[severity] = count.scalar_one()
        
        # Category breakdown
        categories = ["exploit", "malware", "policy", "scan", "dos", "lateral", "credential"]
        category_counts = {}
        for category in categories:
            count = await db.execute(
                select(func.count(DBEvent.id))
                .where(
                    and_(
                        DBEvent.timestamp >= time_threshold,
                        DBEvent.category == category
                    )
                )
            )
            category_counts[category] = count.scalar_one()
        
        # Top rules
        top_rules_result = await db.execute(
            select(
                DBEvent.rule_id,
                func.count(DBEvent.id).label("count")
            )
            .where(DBEvent.timestamp >= time_threshold)
            .group_by(DBEvent.rule_id)
            .order_by(func.count(DBEvent.id).desc())
            .limit(10)
        )
        top_rules = [{"rule_id": r[0], "count": r[1]} for r in top_rules_result]
        
        # Top source IPs
        top_src_ips_result = await db.execute(
            select(
                DBEvent.source_ip,
                func.count(DBEvent.id).label("count")
            )
            .where(DBEvent.timestamp >= time_threshold)
            .group_by(DBEvent.source_ip)
            .order_by(func.count(DBEvent.id).desc())
            .limit(10)
        )
        top_src_ips = [{"ip": r[0], "count": r[1]} for r in top_src_ips_result]
        
        # Top destination IPs
        top_dst_ips_result = await db.execute(
            select(
                DBEvent.destination_ip,
                func.count(DBEvent.id).label("count")
            )
            .where(DBEvent.timestamp >= time_threshold)
            .group_by(DBEvent.destination_ip)
            .order_by(func.count(DBEvent.id).desc())
            .limit(10)
        )
        top_dst_ips = [{"ip": r[0], "count": r[1]} for r in top_dst_ips_result]
        
        # Mitigation stats
        blocked = await db.execute(
            select(func.count(DBEvent.id))
            .where(
                and_(
                    DBEvent.timestamp >= time_threshold,
                    DBEvent.action == "block",
                    DBEvent.mitigated == True
                )
            )
        )
        
        alerted = await db.execute(
            select(func.count(DBEvent.id))
            .where(
                and_(
                    DBEvent.timestamp >= time_threshold,
                    DBEvent.action == "alert"
                )
            )
        )
        
        stats = {
            "total_events": total.scalar_one(),
            "events_by_severity": severity_counts,
            "events_by_category": category_counts,
            "top_rules": top_rules,
            "top_source_ips": top_src_ips,
            "top_destination_ips": top_dst_ips,
            "mitigation_stats": {
                "blocked": blocked.scalar_one(),
                "alerted": alerted.scalar_one()
            }
        }
        
        return stats
    except Exception as e:
        logger.error(f"Error generating IPS stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate IPS statistics"
        )

def get_ips_engine():
    # This will be provided via dependency override
    pass