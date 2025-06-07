from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, func, text, inspect
import datetime

from app.database import get_db
from app.models.firewall import FirewallLog as FirewallLogModel
from app.models.log import NetworkLog as NetworkLogModel, Log as GenericLogModel
from app.schemas.log import (
    FirewallLogResponse, PaginatedFirewallLogResponse,
    NetworkEventLogResponse, PaginatedNetworkEventLogResponse, # Updated schema will be used
    SystemLogResponse, PaginatedSystemLogResponse,     # Updated schema will be used
    MonitoringLogResponse, PaginatedMonitoringLogResponse # Updated schema will be used
)
# from app.core.dependencies import get_current_active_user # If auth is needed
# from app.models.user import User # If using current_user

router = APIRouter()

def apply_common_filters(
    query: Any,
    model: Any,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    start_timestamp: Optional[datetime.datetime] = None,
    end_timestamp: Optional[datetime.datetime] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None, 
    level: Optional[str] = None, 
    log_type_filter: Optional[str] = None, # Renamed to avoid conflict with model 'type' field
    component_source: Optional[str] = None, # Renamed for clarity
    message_contains: Optional[str] = None,
    event_type: Optional[str] = None, # For NetworkLog's threat_type
):
    if source_ip and hasattr(model, 'source_ip'):
        query = query.filter(model.source_ip.ilike(f"%{source_ip}%"))
    if destination_ip and hasattr(model, 'destination_ip'):
        query = query.filter(model.destination_ip.ilike(f"%{destination_ip}%"))
    if start_timestamp and hasattr(model, 'timestamp'):
        query = query.filter(model.timestamp >= start_timestamp)
    if end_timestamp and hasattr(model, 'timestamp'):
        query = query.filter(model.timestamp <= end_timestamp)
    
    if hasattr(model, 'protocol') and protocol:
        query = query.filter(model.protocol.ilike(f"%{protocol}%"))
    if hasattr(model, 'action') and action:
        query = query.filter(model.action == action)
    if hasattr(model, 'level') and level:
        query = query.filter(model.level == level)
    if hasattr(model, 'type') and log_type_filter: # Filter by the 'type' column of GenericLogModel
        query = query.filter(model.type == log_type_filter)
    if hasattr(model, 'source') and component_source: # Filter by the 'source' column of GenericLogModel
        query = query.filter(model.source.ilike(f"%{component_source}%"))
    if hasattr(model, 'message') and message_contains:
        query = query.filter(model.message.ilike(f"%{message_contains}%"))
    if hasattr(model, 'threat_type') and event_type: # For NetworkLogModel
        query = query.filter(model.threat_type.ilike(f"%{event_type}%"))
        
    return query

@router.get("/firewall", response_model=PaginatedFirewallLogResponse)
async def get_firewall_logs(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
    source_ip: Optional[str] = Query(None), destination_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None), action: Optional[str] = Query(None),
    start_timestamp: Optional[datetime.datetime] = Query(None),
    end_timestamp: Optional[datetime.datetime] = Query(None),
    sort_by: str = Query("timestamp"), sort_direction: str = Query("desc")
):
    query = db.query(FirewallLogModel)
    query = apply_common_filters(
        query, FirewallLogModel,
        source_ip=source_ip, destination_ip=destination_ip,
        start_timestamp=start_timestamp, end_timestamp=end_timestamp,
        protocol=protocol, action=action
    )
    total = query.count()
    sort_column = getattr(FirewallLogModel, sort_by, FirewallLogModel.timestamp)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    logs_db = query.offset(skip).limit(limit).all()
    response_logs = []
    for log_db in logs_db:
        response_logs.append(
            FirewallLogResponse(
                id=log_db.id, timestamp=log_db.timestamp,
                action=str(log_db.action.value) if log_db.action else None,
                source_ip=log_db.source_ip, destination_ip=log_db.destination_ip,
                protocol=log_db.protocol,
                matched_rule=log_db.matched_rule, 
                rule_id=str(log_db.rule_id) if log_db.rule_id else None
            )
        )
    return PaginatedFirewallLogResponse(total=total, logs=response_logs)

@router.get("/network", response_model=PaginatedNetworkEventLogResponse)
async def get_network_logs(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
    source_ip: Optional[str] = Query(None), destination_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None, description="Filter by event type (maps to model's threat_type)."),
    start_timestamp: Optional[datetime.datetime] = Query(None),
    end_timestamp: Optional[datetime.datetime] = Query(None),
    sort_by: str = Query("timestamp"), sort_direction: str = Query("desc")
):
    query = db.query(NetworkLogModel)
    query = apply_common_filters(
        query, NetworkLogModel,
        source_ip=source_ip, destination_ip=destination_ip,
        start_timestamp=start_timestamp, end_timestamp=end_timestamp,
        protocol=protocol, event_type=event_type
    )
    total = query.count()
    sort_column = getattr(NetworkLogModel, sort_by, NetworkLogModel.timestamp)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    logs_db = query.offset(skip).limit(limit).all()
    
    response_logs = []
    for log_db in logs_db:
        response_logs.append(
            NetworkEventLogResponse(
                id=log_db.id,
                timestamp=log_db.timestamp,
                event_type=log_db.threat_type, # Mapping threat_type to event_type
                source_ip=log_db.source_ip,
                destination_ip=log_db.destination_ip,
                protocol=log_db.protocol,
                length=log_db.length,
                # Fields like source_mac, application, payload, geo are not in NetworkLogModel
                # So they will use default values (None or empty list) from Pydantic model
            )
        )
    return PaginatedNetworkEventLogResponse(total=total, logs=response_logs)

@router.get("/system", response_model=PaginatedSystemLogResponse)
async def get_system_logs(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
    level: Optional[str] = Query(None), 
    component_source: Optional[str] = Query(None, description="Filter by component/source (partial match)."), # Maps to GenericLogModel.source
    message_contains: Optional[str] = Query(None),
    start_timestamp: Optional[datetime.datetime] = Query(None),
    end_timestamp: Optional[datetime.datetime] = Query(None),
    sort_by: str = Query("timestamp"), sort_direction: str = Query("desc")
):
    query = db.query(GenericLogModel).filter(GenericLogModel.type == 'SYSTEM')
    query = apply_common_filters(
        query, GenericLogModel,
        start_timestamp=start_timestamp, end_timestamp=end_timestamp,
        level=level, component_source=component_source, message_contains=message_contains
    )
    total = query.count()
    sort_column = getattr(GenericLogModel, sort_by, GenericLogModel.timestamp)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    logs_db = query.offset(skip).limit(limit).all()
    response_logs = [SystemLogResponse.from_orm(log) for log in logs_db]
    return PaginatedSystemLogResponse(total=total, logs=response_logs)

@router.get("/monitoring", response_model=PaginatedMonitoringLogResponse)
async def get_monitoring_logs(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
    level: Optional[str] = Query(None),
    component_source: Optional[str] = Query(None, description="Filter by component/source (e.g., monitoring_service)."), # Maps to GenericLogModel.source
    message_contains: Optional[str] = Query(None),
    start_timestamp: Optional[datetime.datetime] = Query(None),
    end_timestamp: Optional[datetime.datetime] = Query(None),
    sort_by: str = Query("timestamp"), sort_direction: str = Query("desc")
):
    query = db.query(GenericLogModel).filter(GenericLogModel.type == 'MONITORING')
    query = apply_common_filters(
        query, GenericLogModel,
        start_timestamp=start_timestamp, end_timestamp=end_timestamp,
        level=level, component_source=component_source, message_contains=message_contains
    )
    total = query.count()
    sort_column = getattr(GenericLogModel, sort_by, GenericLogModel.timestamp)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    logs_db = query.offset(skip).limit(limit).all()
    response_logs = [MonitoringLogResponse.from_orm(log) for log in logs_db]
    return PaginatedMonitoringLogResponse(total=total, logs=response_logs)
