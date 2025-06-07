from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict # Added Dict
import datetime

class FirewallLogBase(BaseModel):
    action: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    # rule_id from frontend sample is a string like "MATCHED-2170"
    # model.FirewallLog.matched_rule (String) seems to be the one.
    # model.FirewallLog.rule_id is an Integer FK.
    matched_rule: Optional[str] = None 

class FirewallLogResponse(FirewallLogBase):
    id: int
    timestamp: datetime.datetime
    rule_id: Optional[str] = None # This can store the FK as a string if needed by frontend.

    class Config:
        from_attributes = True

class PaginatedFirewallLogResponse(BaseModel):
    total: int
    logs: List[FirewallLogResponse]

# NetworkEventLog: Aligning with NetworkLogModel from backend/app/models/log.py
# Fields like source_mac, application, payload, geo are NOT in NetworkLogModel.
# The frontend will have to handle their absence or they need to be added to the model.
class NetworkEventLogBase(BaseModel):
    event_type: Optional[str] = None # Mapped from NetworkLogModel.threat_type
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    length: Optional[int] = None
    # raw_data from model is not included by default, can be added if needed.

    # Optional fields that are in frontend type but not in current backend model
    source_mac: Optional[str] = None
    destination_port: Optional[int] = None
    application: Optional[str] = None
    payload: Optional[str] = None # Model has raw_data (Text), could be a preview
    # geo: Optional[Dict[str, str]] = None # Geo is an object, not directly in model

class NetworkEventLogResponse(NetworkEventLogBase):
    id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class PaginatedNetworkEventLogResponse(BaseModel):
    total: int
    logs: List[NetworkEventLogResponse]

# SystemLog: Aligning with GenericLogModel from backend/app/models/log.py
# Frontend sample fields: component, level, message, details, user_id, source_ip, request_id
# GenericLogModel fields: type, level, message, source, details, timestamp, action, user_id
class SystemLogBase(BaseModel):
    level: Optional[str] = None # Maps to GenericLogModel.level
    message: Optional[str] = None # Maps to GenericLogModel.message
    component: Optional[str] = None # This will map to GenericLogModel.source
    details: Optional[Dict[Any, Any]] = None # Maps to GenericLogModel.details (JSON)
    user_id: Optional[int] = None # Maps to GenericLogModel.user_id
    source_ip: Optional[str] = None # Not directly in GenericLogModel, might be in details JSON
    request_id: Optional[str] = None # Not directly in GenericLogModel, might be in details JSON
    # GenericLogModel.type will be used for filtering (e.g. 'SYSTEM') but not directly in response here.
    # GenericLogModel.action is also available.

class SystemLogResponse(SystemLogBase):
    id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class PaginatedSystemLogResponse(BaseModel):
    total: int
    logs: List[SystemLogResponse]

# MonitoringLog: Aligning with GenericLogModel
# Frontend sample fields: type (SYSTEM), level (WARNING), message, source (monitoring_service), details, timestamp, action (AlertRaised), user_id
# GenericLogModel fields: type, level, message, source, details, timestamp, action, user_id
class MonitoringLogBase(BaseModel):
    # 'type' from frontend sample (e.g. "SYSTEM") seems to map to GenericLogModel.type (e.g. "MONITORING")
    # For clarity, the API will filter by GenericLogModel.type='MONITORING', this field can represent something else from details if needed.
    log_subtype: Optional[str] = Field(None, alias="type") # To match frontend's 'type' field like "SYSTEM" for a monitoring log
    level: Optional[str] = None # Maps to GenericLogModel.level
    message: Optional[str] = None # Maps to GenericLogModel.message
    source: Optional[str] = None # Maps to GenericLogModel.source (e.g. "monitoring_service")
    details: Optional[Dict[Any, Any]] = None # Maps to GenericLogModel.details
    action: Optional[str] = None # Maps to GenericLogModel.action
    user_id: Optional[int] = None # Maps to GenericLogModel.user_id

class MonitoringLogResponse(MonitoringLogBase):
    id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True
        validate_by_name = True


class PaginatedMonitoringLogResponse(BaseModel):
    total: int
    logs: List[MonitoringLogResponse]
