# backend/app/schemas/ids_rule.py
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class RuleAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    LOG = "log"


class RuleProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class IDSRuleBase(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    action: RuleAction
    protocol: RuleProtocol
    source_ip: Optional[str] = Field(
        None, pattern=r"^\d{1,3}(\.\d{1,3}){0,3}(\/\d{1,2})?$"
    )
    source_port: Optional[str] = Field(None, pattern=r"^\d{1,5}(:\d{1,5})?$")
    destination_ip: Optional[str] = Field(
        None, pattern=r"^\d{1,3}(\.\d{1,3}){0,3}(\/\d{1,2})?$"
    )
    destination_port: Optional[str] = Field(None, pattern=r"^\d{1,5}(:\d{1,5})?$")
    pattern: Optional[str] = Field(None, max_length=500)
    content_modifiers: Optional[List[str]] = Field(None)
    threshold: Optional[int] = Field(None, ge=1)
    window: Optional[int] = Field(None, ge=1)  # seconds
    active: bool = True
    severity: str = Field("medium", pattern=r"^(low|medium|high|critical)$")


class IDSRuleCreate(IDSRuleBase):
    pass


class IDSRuleUpdate(BaseModel):
    active: Optional[bool]
    action: Optional[RuleAction]
    severity: Optional[str]


class IDSRule(IDSRuleBase):
    id: int
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True
