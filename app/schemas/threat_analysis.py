from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime


class ThreatAnalysisCoordinate(BaseModel):
    x: Union[str, int, float, datetime]
    y: Union[str, int, float, datetime]


class ThreatAnalysisTopType(BaseModel):
    type: str
    count: int


class ThreatAnalysisSummary(BaseModel):
    total_threats: int
    benign_percentage: float
    malicious_percentage: float
    average_anomaly_score_24h: Optional[float] = None
    retraining_last_occurred: Optional[str] = None
    top_3_attack_types: List[ThreatAnalysisTopType]


class ThreatAnalysisTrendPoint(BaseModel):
    time_bucket: datetime
    count: int


class ThreatAnalysisScoreHeatmapPoint(BaseModel):
    time_bucket: str  # e.g., "YYYY-MM-DD HH:00"
    score_range: str  # e.g., "0.8-0.9"
    count: int


class ThreatAnalysisOriginPoint(BaseModel):
    country: str
    count: int


class ThreatAnalysisModelDecisionPoint(BaseModel):
    model_name: str
    above_threshold_count: int
    below_threshold_count: int


class ThreatAnalysisTrends(BaseModel):
    threats_over_time: List[ThreatAnalysisTrendPoint]
    anomaly_score_heatmap_data: List[ThreatAnalysisScoreHeatmapPoint]
    threat_origins: List[ThreatAnalysisOriginPoint]
    model_decision_stats: List[ThreatAnalysisModelDecisionPoint]


class ThreatAnalysisTableRow(BaseModel):
    id: str
    timestamp: datetime
    threat_type: str
    anomaly_score: Optional[float] = None
    verdict: str  # e.g., "Malicious", "Benign", "Suspicious"
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


class PaginatedThreatAnalysisTableResponse(BaseModel):
    total: int
    items: List[ThreatAnalysisTableRow]
    page: int
    size: int
    pages: int


class ThreatFlowFeature(BaseModel):
    feature_name: str
    value: float


class ThreatFlowMetadataDetail(BaseModel):
    packet_counts: Optional[Dict[str, int]] = None
    duration_seconds: Optional[float] = None
    flags_summary: Optional[Dict[str, int]] = None
    active_idle_stats: Optional[Dict[str, float]] = None
    payload_length_stats: Optional[Dict[str, float]] = None
    raw_features: Optional[Dict[str, Any]] = None


class ThreatAnalysisDetailResponse(ThreatAnalysisTableRow):
    description: Optional[str] = None
    rule_id: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    feature_contributions: Optional[List[ThreatFlowFeature]] = None
    flow_metadata: Optional[ThreatFlowMetadataDetail] = None
    raw_alert_data: Optional[Dict[str, Any]] = None
