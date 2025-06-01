from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, func

import datetime

from app.database import get_db
from app.models.firewall import FirewallRule as FirewallRuleModel
from app.models.ids_rule import IDSRule as IDSRuleModel
from app.schemas.rule import (
    FirewallRuleResponse, PaginatedFirewallRuleResponse,
    IDSRuleResponse, PaginatedIDSRuleResponse
)

router = APIRouter()

def apply_rule_filters(
    query: Any,
    model: Any,
    is_active: Optional[bool] = None,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None, # For IDS rules
    direction: Optional[str] = None, # For Firewall rules
    name_contains: Optional[str] = None,
):
    if is_active is not None and hasattr(model, 'is_active'):
        query = query.filter(model.is_active == is_active)
    if action and hasattr(model, 'action'):
        query = query.filter(model.action.ilike(f"%{action}%")) # Using ilike for case-insensitive partial match on action
    if protocol and hasattr(model, 'protocol'):
        query = query.filter(model.protocol.ilike(f"%{protocol}%"))
    if severity and hasattr(model, 'severity'): # For IDS Rules
        query = query.filter(model.severity.ilike(f"%{severity}%"))
    if direction and hasattr(model, 'direction'): # For Firewall Rules
        query = query.filter(model.direction.ilike(f"%{direction}%"))
    if name_contains and hasattr(model, 'name'):
        query = query.filter(model.name.ilike(f"%{name_contains}%"))
    return query

@router.get("/firewall", response_model=PaginatedFirewallRuleResponse)
async def get_firewall_rules(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
    is_active: Optional[bool] = Query(None),
    action: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    name_contains: Optional[str] = Query(None),
    sort_by: str = Query("id"), sort_direction: str = Query("asc")
):
    query = db.query(FirewallRuleModel)
    query = apply_rule_filters(
        query, FirewallRuleModel,
        is_active=is_active, action=action, protocol=protocol, direction=direction, name_contains=name_contains
    )
    total = query.count()
    sort_column = getattr(FirewallRuleModel, sort_by, FirewallRuleModel.id)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    rules_db = query.offset(skip).limit(limit).all()
    
    response_rules = []
    for rule_db in rules_db:
        response_rules.append(
            FirewallRuleResponse(
                id=rule_db.id,
                name=rule_db.name,
                action=str(rule_db.action.value) if rule_db.action else None,
                direction=str(rule_db.direction.value) if rule_db.direction else None,
                source_ip=rule_db.source_ip,
                destination_ip=rule_db.destination_ip,
                source_port=rule_db.source_port,
                destination_port=rule_db.destination_port,
                protocol=str(rule_db.protocol.value) if rule_db.protocol else None,
                is_active=rule_db.is_active,
                created_at=rule_db.created_at,
                updated_at=rule_db.updated_at
            )
        )
    return PaginatedFirewallRuleResponse(total=total, rules=response_rules)

@router.get("/ids", response_model=PaginatedIDSRuleResponse)
async def get_ids_rules(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
    active: Optional[bool] = Query(None), # Note: frontend uses 'active', model uses 'active'
    action: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    name_contains: Optional[str] = Query(None),
    sort_by: str = Query("id"), sort_direction: str = Query("asc")
):
    query = db.query(IDSRuleModel)
    query = apply_rule_filters(
        query, IDSRuleModel,
        is_active=active, action=action, protocol=protocol, severity=severity, name_contains=name_contains
    )
    total = query.count()
    sort_column = getattr(IDSRuleModel, sort_by, IDSRuleModel.id)
    if sort_direction.lower() == "asc": query = query.order_by(asc(sort_column))
    else: query = query.order_by(desc(sort_column))
    rules_db = query.offset(skip).limit(limit).all()
    
    # Use from_orm for simpler mapping if fields align well, otherwise manual map
    response_rules = [IDSRuleResponse.from_orm(rule_db) for rule_db in rules_db]
    return PaginatedIDSRuleResponse(total=total, rules=response_rules)
