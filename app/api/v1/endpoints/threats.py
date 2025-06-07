from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, aliased
from sqlalchemy import desc, func, case
import datetime

from app.database import get_db
from app.models.threat import ThreatLog as ThreatLogModel
from app.schemas.threat import ThreatBase  # Using ThreatBase from existing schema file
import logging  # Added for logging in new function
from sio_instance import broadcast_new_alert

router = APIRouter()
logger = logging.getLogger(__name__)  # Added for logging in new function


class EmergingThreatResponse(ThreatBase):
    id: int
    name: str
    severity: str
    type: str
    details: str
    affectedSystems: List[str] = []
    timestamp: datetime.datetime
    detectionCount: int = 1
    rule_id: Optional[str] = None  # Added rule_id as it's useful

    class Config:
        from_attributes = True


@router.get("/", response_model=List[EmergingThreatResponse])
async def get_emerging_threats(
    db: Session = Depends(get_db),
    limit: int = Query(
        default=20, ge=1, le=100, description="Maximum number of threats to return."
    ),
    days_ago: int = Query(
        default=7,
        ge=1,
        le=90,
        description="How many days back to look for distinct threats.",
    ),
    min_severity: Optional[str] = Query(
        default=None,
        description="Filter by minimum severity (e.g., 'medium', 'high', 'critical'). Case-insensitive.",
    ),
) -> Any:
    """
    Retrieve recent and distinct emerging threats.
    Tries to identify unique threats based on rule_id or description and returns the latest occurrence.
    """
    start_date = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)

    # Define severity order for filtering and sorting
    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    min_severity_numeric = 0
    if min_severity and min_severity.lower() in severity_order:
        min_severity_numeric = severity_order[min_severity.lower()]

    # Subquery to rank threats within each group (rule_id or description) by timestamp
    # This helps in picking the latest occurrence of a potentially recurring threat.
    ThreatLogAlias = aliased(ThreatLogModel)
    subquery = (
        db.query(
            ThreatLogModel.id,
            func.row_number()
            .over(
                partition_by=(
                    ThreatLogModel.rule_id,  # Group by rule_id first
                    func.substr(
                        ThreatLogModel.description, 1, 100
                    ),  # Then by first 100 chars of description if rule_id is null
                ),
                order_by=desc(ThreatLogModel.timestamp),
            )
            .label("rnk"),
        )
        .filter(ThreatLogModel.timestamp >= start_date)
        .subquery()
    )

    query = (
        db.query(ThreatLogModel, subquery.c.rnk)
        .join(subquery, ThreatLogModel.id == subquery.c.id)
        .filter(subquery.c.rnk == 1)  # Select only the most recent threat in each group
    )

    # Apply severity filter if provided
    if min_severity_numeric > 0:
        # This requires mapping string severity to a numeric value in the query
        # Or filtering after fetching if the DB doesn't easily support custom string order
        # For simplicity here, we'll filter after fetching, but a DB-level filter is more efficient.
        # Adding a case statement for severity order to allow DB level filtering/sorting
        severity_case = case(
            value=func.lower(ThreatLogModel.severity),
            whens={
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            },
            else_=0,  # Default for unknown severities
        ).label("severity_numeric")
        query = query.add_columns(severity_case).filter(
            severity_case >= min_severity_numeric
        )

    # Order by timestamp descending to get the most recent unique threats
    # If severity filter is applied, also sort by severity
    if min_severity_numeric > 0:
        ordered_threats_db = (
            query.order_by(desc(severity_case), desc(ThreatLogModel.timestamp))
            .limit(limit)
            .all()
        )
    else:
        ordered_threats_db = (
            query.order_by(desc(ThreatLogModel.timestamp)).limit(limit).all()
        )

    if not ordered_threats_db:
        return []

    response_threats = []
    for item in ordered_threats_db:
        threat_db = (
            item[0] if isinstance(item, tuple) else item
        )  # Adjust if query returns tuples due to add_columns

        name = threat_db.threat_type or "Unknown Event"
        if threat_db.rule_id:
            name = f"{threat_db.rule_id.replace('_', ' ').title()}"
        elif threat_db.description and len(threat_db.description) < 50:
            name = threat_db.description

        type_val = threat_db.category or threat_db.threat_type or "N/A"
        if threat_db.protocol:
            type_val = f"{type_val} ({threat_db.protocol})"

        details = threat_db.description or "No additional details."
        if threat_db.source_ip:
            details = f"Source: {threat_db.source_ip}. {details}"

        affected_systems = []
        if threat_db.destination_ip:
            affected_systems.append(f"Target IP: {threat_db.destination_ip}")
        if threat_db.destination_port:
            affected_systems.append(f"Port: {threat_db.destination_port}")
        if not affected_systems:
            affected_systems = ["Undetermined"]

        # For detectionCount, we are currently selecting distinct threats.
        # A true detectionCount would require a separate aggregation query.
        # For now, each distinct "emerging" threat instance is counted as 1.
        detection_count = 1
        # If you wanted to show how many times this specific rule_id appeared in the timeframe:
        # detection_count = db.query(func.count(ThreatLogModel.id)).filter(ThreatLogModel.rule_id == threat_db.rule_id, ThreatLogModel.timestamp >= start_date).scalar()

        response_threats.append(
            EmergingThreatResponse(
                id=threat_db.id,
                name=name,
                severity=(
                    threat_db.severity.lower() if threat_db.severity else "unknown"
                ),
                type=type_val,
                details=details,
                affectedSystems=affected_systems,
                timestamp=threat_db.timestamp,
                detectionCount=detection_count,
                rule_id=threat_db.rule_id,
            )
        )

    return response_threats


async def record_and_broadcast_threat(db: Session, threat_data: dict) -> ThreatLogModel:
    """
    Simulates recording a new threat and then broadcasting it.
    In a real system, this logic would be part of the threat detection/logging pipeline.
    """
    # Simplified threat creation for demonstration
    # A real implementation would take more structured input, validate it, etc.
    new_threat = ThreatLogModel(
        rule_id=threat_data.get("rule_id"),
        description=threat_data.get("description", "No description provided."),
        severity=threat_data.get("severity", "unknown"),
        source_ip=threat_data.get("source_ip"),
        destination_ip=threat_data.get("destination_ip"),
        destination_port=threat_data.get("destination_port"),
        protocol=threat_data.get("protocol"),
        action_taken=threat_data.get("action_taken"),
        raw_log=threat_data.get("raw_log"),
        threat_type=threat_data.get(
            "type", "generic"
        ),  # Match EmergingThreatResponse 'type'
        category=threat_data.get("category"),
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)

    logger.info(
        f"New threat recorded: ID {new_threat.id} - {new_threat.description[:50]}"
    )

    # Prepare data for broadcast (similar to EmergingThreatResponse)
    # This transformation should ideally be robust
    name = new_threat.threat_type or "Unknown Event"
    if new_threat.rule_id:
        name = f"{new_threat.rule_id.replace('_', ' ').title()}"
    elif new_threat.description and len(new_threat.description) < 50:
        name = new_threat.description

    type_val = new_threat.category or new_threat.threat_type or "N/A"
    if new_threat.protocol:
        type_val = f"{type_val} ({new_threat.protocol})"

    details = new_threat.description or "No additional details."
    if new_threat.source_ip:
        details = f"Source: {new_threat.source_ip}. {details}"

    alert_payload = {
        "id": new_threat.id,
        "name": name,  # Or use 'title' if frontend expects that
        "description": details,  # Or use 'description'
        "severity": new_threat.severity.lower() if new_threat.severity else "unknown",
        "timestamp": new_threat.timestamp.isoformat() + "Z",
        "type": type_val,
        # Add any other fields the frontend notification system might expect,
        # like 'read: false', 'affectedSystems', etc.
        # These should align with what Header.tsx will eventually use.
    }

    await broadcast_new_alert(alert_payload)
    return new_threat
