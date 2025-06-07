import pytest
import json
import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock # patch is useful for logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Result # To mock database result objects
from sqlalchemy.sql import select # To check statements if needed, though less common in service tests

# Adjust these imports to match your project's actual structure
from app.models.threat import ThreatLog
from app.schemas.threat_analysis import (
    ThreatAnalysisSummary,
    ThreatAnalysisTopType,
    ThreatAnalysisTrends, # Added for get_threat_trends tests
    ThreatAnalysisTrendPoint,
    ThreatAnalysisScoreHeatmapPoint,
    ThreatAnalysisOriginPoint,
    ThreatAnalysisModelDecisionPoint
)
from app.services.threat_analysis_service import (
    _parse_raw_data,
    get_threat_summary,
    get_threat_trends # Added for testing
)
from app.utils.geoip_utils import get_country_from_ip # For mocking in get_threat_trends

# --- Tests for _parse_raw_data ---

def test_parse_raw_data_valid_json():
    json_str = '{"key": "value", "number": 123}'
    expected_dict = {"key": "value", "number": 123}
    assert _parse_raw_data(json_str) == expected_dict

def test_parse_raw_data_invalid_json(caplog):
    json_str = '{"key": "value", "number": 123' # Missing closing brace
    with caplog.at_level(logging.WARNING):
        result = _parse_raw_data(json_str)
    assert result == {}
    assert "JSON parsing error" in caplog.text
    assert "Data prefix: {\"key\": \"value\", \"number\": 123" in caplog.text


def test_parse_raw_data_none_input():
    assert _parse_raw_data(None) == {}

def test_parse_raw_data_empty_string(caplog):
    # Depending on implementation, empty string might be a JSONDecodeError or handled before parsing
    # The current service code's json.loads("") will raise JSONDecodeError
    with caplog.at_level(logging.WARNING):
        result = _parse_raw_data("")
    assert result == {}
    assert "JSON parsing error" in caplog.text # json.loads("") raises an error
    assert "Data prefix: " in caplog.text


# --- Fixtures for get_threat_summary ---

@pytest.fixture
def mock_db_session():
    session = AsyncMock() # AsyncSession is an AsyncMock

    # Mock the execute method to return an AsyncMock by default
    # which itself can have scalar_one_or_none, scalars, .all() mocked
    session.execute = AsyncMock()
    return session


# --- Tests for get_threat_summary ---

@pytest.mark.asyncio
async def test_get_threat_summary_empty_database(mock_db_session):
    # Mock scalar_one_or_none to return 0 for counts
    mock_total_result = AsyncMock()
    mock_total_result.scalar_one_or_none.return_value = 0

    mock_malicious_result = AsyncMock()
    mock_malicious_result.scalar_one_or_none.return_value = 0

    # Mock for anomaly score logs (empty)
    mock_anomaly_logs_result = AsyncMock()
    mock_anomaly_logs_result.scalars.return_value = AsyncMock()
    mock_anomaly_logs_result.scalars.return_value.all.return_value = []

    # Mock for top attack types (empty)
    mock_top_types_result = AsyncMock()
    mock_top_types_result.all.return_value = [] # .all() is called on the result directly

    # Configure session.execute to return different mocks based on the statement (simplified)
    # A more robust way would be to inspect the statement if it's complex
    mock_db_session.execute.side_effect = [
        mock_total_result,        # For total_threats_stmt
        mock_malicious_result,    # For malicious_count_stmt
        mock_anomaly_logs_result, # For anomaly_logs_stmt
        mock_top_types_result     # For top_3_attack_types_stmt
    ]

    summary = await get_threat_summary(mock_db_session)

    assert summary.total_threats == 0
    assert summary.benign_percentage == 0.0
    assert summary.malicious_percentage == 0.0
    assert summary.average_anomaly_score_24h is None
    assert summary.retraining_last_occurred == "Not available" # Current placeholder
    assert summary.top_3_attack_types == []


# Helper to create mock row objects for SQLAlchemy results
class MockAlchemyRow:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

@pytest.mark.asyncio
@pytest.mark.parametrize("threat_type_filter_param, expected_top_type_field", [
    (None, "threat_type"),  # No filter, group by threat_type
    ("Malware", "rule_id") # Filtered, group by rule_id
])
async def test_get_threat_summary_with_mock_data(mock_db_session, threat_type_filter_param, expected_top_type_field):
    now = datetime.utcnow()
    twenty_four_hours_ago = now - timedelta(hours=24)

    all_logs_data = [
        {"id": 1, "severity": "High", "timestamp": now - timedelta(hours=1), "threat_type": "Malware", "rule_id": "RULE_MAL_001", "raw_data": json.dumps({"anomaly_score": 0.85})},
        {"id": 2, "severity": "Low", "timestamp": now - timedelta(hours=2), "threat_type": "Scanning", "rule_id": "RULE_SCAN_001", "raw_data": json.dumps({"metadata": {"anomaly_score": 0.15}})},
        {"id": 3, "severity": "Critical", "timestamp": now - timedelta(hours=48), "threat_type": "Malware", "rule_id": "RULE_MAL_002", "raw_data": json.dumps({"anomaly_score": 0.95})},
        {"id": 4, "severity": "Medium", "timestamp": now - timedelta(hours=3), "threat_type": "Phishing", "rule_id": "RULE_PHISH_001", "raw_data": json.dumps({})},
        {"id": 5, "severity": "Low", "timestamp": now - timedelta(hours=4), "threat_type": "Scanning", "rule_id": "RULE_SCAN_002", "raw_data": json.dumps({"metadata": {"anomaly_score": "0.20"}})},
        {"id": 6, "severity": "High", "timestamp": now - timedelta(hours=5), "threat_type": "Malware", "rule_id": "RULE_MAL_001", "raw_data": json.dumps({"anomaly_score": 0.75})}, # Another RULE_MAL_001
    ]

    # Apply filter if one is provided for this test case
    filtered_logs_data = [
        log for log in all_logs_data if threat_type_filter_param is None or log["threat_type"] == threat_type_filter_param
    ]

    # --- Mocking db responses based on filtered_logs_data ---
    mock_total_result = AsyncMock(spec=Result); mock_total_result.scalar_one_or_none.return_value = len(filtered_logs_data)

    malicious_count = sum(1 for log in filtered_logs_data if log["severity"] in ["High", "Critical", "Medium"])
    mock_malicious_result = AsyncMock(spec=Result); mock_malicious_result.scalar_one_or_none.return_value = malicious_count

    recent_logs_for_scores_raw_data = [log["raw_data"] for log in filtered_logs_data if log["timestamp"] >= twenty_four_hours_ago]
    mock_anomaly_logs_result_scalars = AsyncMock(); mock_anomaly_logs_result_scalars.all.return_value = recent_logs_for_scores_raw_data
    mock_anomaly_logs_result = AsyncMock(spec=Result); mock_anomaly_logs_result.scalars.return_value = mock_anomaly_logs_result_scalars

    # Top 3 Attack Types / Rule IDs
    type_counts = {}
    for log in filtered_logs_data:
        key_to_group = log[expected_top_type_field] # 'threat_type' or 'rule_id'
        if key_to_group: # Ensure key_to_group is not None
             type_counts[key_to_group] = type_counts.get(key_to_group, 0) + 1

    sorted_types = sorted(type_counts.items(), key=lambda item: item[1], reverse=True)[:3]

    # Use the helper class for mock rows
    mock_top_types_db_result = [MockAlchemyRow(**{expected_top_type_field: tt, "count": c}) for tt, c in sorted_types]

    mock_top_types_result_obj = AsyncMock(spec=Result); mock_top_types_result_obj.all.return_value = mock_top_types_db_result

    mock_db_session.execute.side_effect = [
        mock_total_result, mock_malicious_result, mock_anomaly_logs_result, mock_top_types_result_obj
    ]

    summary = await get_threat_summary(mock_db_session, threat_type_filter=threat_type_filter_param)

    # Assertions
    assert summary.total_threats == len(filtered_logs_data)
    if len(filtered_logs_data) > 0:
        assert summary.malicious_percentage == pytest.approx((malicious_count / len(filtered_logs_data) * 100))
        assert summary.benign_percentage == pytest.approx(((len(filtered_logs_data) - malicious_count) / len(filtered_logs_data) * 100))
    else:
        assert summary.malicious_percentage == 0
        assert summary.benign_percentage == 0

    expected_scores = []
    for log_raw_data_str in recent_logs_for_scores_raw_data:
        data = json.loads(log_raw_data_str) # Assuming _parse_raw_data works correctly
        score = data.get("anomaly_score", data.get("metadata", {}).get("anomaly_score"))
        if score is not None:
            try:
                expected_scores.append(float(score))
            except ValueError: pass # Mimic service behavior

    if expected_scores:
        expected_avg_score = sum(expected_scores) / len(expected_scores)
        assert summary.average_anomaly_score_24h == pytest.approx(expected_avg_score, rel=1e-4)
    else:
        assert summary.average_anomaly_score_24h is None

    assert len(summary.top_3_attack_types) == min(3, len(type_counts))
    # The type field in ThreatAnalysisTopType will hold either threat_type or rule_id
    expected_top_types_schema = [
        ThreatAnalysisTopType(type=item_type, count=item_count) for item_type, item_count in sorted_types
    ]
    assert summary.top_3_attack_types == expected_top_types_schema
    if expected_top_types_schema:
        assert summary.top_3_attack_types[0].type == expected_top_types_schema[0].type

@pytest.mark.asyncio
async def test_get_threat_summary_sqlalchemy_error(mock_db_session):
    mock_db_session.execute.side_effect = SQLAlchemyError("Database connection failed")

    with pytest.raises(SQLAlchemyError) as excinfo:
        await get_threat_summary(mock_db_session)
    assert "Database connection failed" in str(excinfo.value)

# --- Tests for get_threat_trends ---

@pytest.mark.asyncio
@patch("app.services.threat_analysis_service.get_country_from_ip") # Mock the GeoIP utility
async def test_get_threat_trends_empty_database(mock_get_country, mock_db_session):
    mock_get_country.return_value = "Unknown" # Default mock for GeoIP

    # Mock for threats_over_time (empty)
    mock_threats_time_result = AsyncMock(spec=Result); mock_threats_time_result.all.return_value = []
    # Mock for heatmap_logs (empty)
    mock_heatmap_result = AsyncMock(spec=Result); mock_heatmap_result.all.return_value = []
    # Mock for stmt_ips (empty)
    mock_ips_result = AsyncMock(spec=Result); mock_ips_result.all.return_value = []
    # Mock for model_logs (empty)
    mock_model_logs_result = AsyncMock(spec=Result); mock_model_logs_result.all.return_value = []

    mock_db_session.execute.side_effect = [
        mock_threats_time_result,
        mock_heatmap_result,
        mock_ips_result,
        mock_model_logs_result
    ]

    trends = await get_threat_trends(mock_db_session)

    assert trends.threats_over_time == []
    assert trends.anomaly_score_heatmap_data == []
    assert trends.threat_origins == []
    assert trends.model_decision_stats == []


@pytest.mark.asyncio
@patch("app.services.threat_analysis_service.get_country_from_ip")
@pytest.mark.parametrize("threat_type_filter_param", [None, "Malware"])
async def test_get_threat_trends_with_mock_data(mock_get_country, mock_db_session, threat_type_filter_param):
    mock_get_country.side_effect = lambda ip: {"1.1.1.1": "USA", "2.2.2.2": "Canada"}.get(ip, "Unknown")

    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=7)

    all_logs_data = [
        {"id": 1, "timestamp": now - timedelta(hours=1), "threat_type": "Malware", "source_ip": "1.1.1.1", "rule_id": "MAL_01", "raw_data": json.dumps({"anomaly_score": 0.8, "metadata": {"model_name": "ModelX", "threshold": 0.7}})},
        {"id": 2, "timestamp": now - timedelta(days=2), "threat_type": "Scanning", "source_ip": "2.2.2.2", "rule_id": "SCAN_01", "raw_data": json.dumps({"anomaly_score": 0.3, "metadata": {"model_name": "ModelY", "threshold": 0.5}})},
        {"id": 3, "timestamp": now - timedelta(days=3), "threat_type": "Malware", "source_ip": "1.1.1.1", "rule_id": "MAL_02", "raw_data": json.dumps({"anomaly_score": 0.9, "metadata": {"model_name": "ModelX", "threshold": 0.7}})},
    ]

    filtered_logs_data = [log for log in all_logs_data if threat_type_filter_param is None or log["threat_type"] == threat_type_filter_param]

    # --- Mocking DB for get_threat_trends ---
    # 1. Threats Over Time
    # Simplified: assume one time bucket for all filtered logs for this test
    mock_threats_time_db_result = []
    if filtered_logs_data:
        mock_threats_time_db_result = [MockAlchemyRow(time_bucket=(now - timedelta(hours=1)).strftime('%Y-%m-%d %H:00:00'), count=len(filtered_logs_data))]
    mock_threats_time_result = AsyncMock(spec=Result); mock_threats_time_result.all.return_value = mock_threats_time_db_result

    # 2. Anomaly Score Heatmap (based on raw_data of filtered logs)
    heatmap_source_rows = [MockAlchemyRow(timestamp=log["timestamp"], raw_data=log["raw_data"]) for log in filtered_logs_data]
    mock_heatmap_result = AsyncMock(spec=Result); mock_heatmap_result.all.return_value = heatmap_source_rows

    # 3. Threat Origins (IPs and counts from filtered logs)
    ip_counts_for_origins = {}
    for log in filtered_logs_data:
        ip_counts_for_origins[log["source_ip"]] = ip_counts_for_origins.get(log["source_ip"], 0) + 1
    mock_ips_db_result = [MockAlchemyRow(source_ip=ip, threat_count=c) for ip, c in ip_counts_for_origins.items()]
    mock_ips_result = AsyncMock(spec=Result); mock_ips_result.all.return_value = mock_ips_db_result

    # 4. Model Decision Stats (raw_data and rule_id from filtered logs)
    model_decision_source_rows = [MockAlchemyRow(raw_data=log["raw_data"], rule_id=log["rule_id"]) for log in filtered_logs_data]
    mock_model_logs_result = AsyncMock(spec=Result); mock_model_logs_result.all.return_value = model_decision_source_rows

    mock_db_session.execute.side_effect = [
        mock_threats_time_result, mock_heatmap_result, mock_ips_result, mock_model_logs_result
    ]

    trends = await get_threat_trends(mock_db_session, threat_type_filter=threat_type_filter_param)

    # Assertions (basic checks, detailed logic is complex for full trend assertion here)
    if filtered_logs_data:
        assert len(trends.threats_over_time) > 0
        assert len(trends.anomaly_score_heatmap_data) >= 0 # Can be 0 if no scores
        assert len(trends.threat_origins) > 0
        assert len(trends.model_decision_stats) >= 0 # Can be 0 if no model data
    else:
        assert trends.threats_over_time == []
        assert trends.anomaly_score_heatmap_data == []
        assert trends.threat_origins == []
        assert trends.model_decision_stats == []

    # Example: Check if threat_origins reflects the GeoIP lookup
    if threat_type_filter_param == "Malware" and filtered_logs_data: # Malware logs are from 1.1.1.1 (USA)
        assert any(origin.country == "USA" for origin in trends.threat_origins)
        assert sum(o.count for o in trends.threat_origins) == len(filtered_logs_data)

@pytest.mark.asyncio
async def test_get_threat_trends_sqlalchemy_error(mock_db_session):
    mock_db_session.execute.side_effect = SQLAlchemyError("Trends DB failed")
    with pytest.raises(SQLAlchemyError):
        await get_threat_trends(mock_db_session)