# backend/app/api/ids.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..schemas.ids_rule import IDSRule, IDSRuleCreate, IDSRuleUpdate
from ..models.ids_rule import IDSRule as DBIDSRule

router = APIRouter()


@router.post("/", response_model=IDSRule, tags=["IDS"])
def create_rule(rule: IDSRuleCreate, db: Session = Depends(get_db)):
    db_rule = DBIDSRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.get("/", response_model=List[IDSRule], tags=["IDS"])
def read_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(DBIDSRule).offset(skip).limit(limit).all()


@router.get("/{rule_id}", response_model=IDSRule, tags=["IDS"])
def read_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DBIDSRule).filter(DBIDSRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=IDSRule, tags=["IDS"])
def update_rule(rule_id: int, rule: IDSRuleUpdate, db: Session = Depends(get_db)):
    db_rule = db.query(DBIDSRule).filter(DBIDSRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_data = rule.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_rule, field, value)

    db.commit()
    db.refresh(db_rule)
    return db_rule


@router.delete("/{rule_id}", tags=["IDS"])
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(DBIDSRule).filter(DBIDSRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}
