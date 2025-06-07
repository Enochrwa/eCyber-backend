import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock # AsyncMock for mocking async service functions

# Adjust these imports to match your project's actual structure
from app.main import app # Assuming your FastAPI app instance is here
from app.schemas.threat_analysis import (
    ThreatAnalysisSummary,
    ThreatAnalysisTopType,
    ThreatAnalysisTrends, # Added for trends endpoint
    ThreatAnalysisTrendPoint,
    ThreatAnalysisScoreHeatmapPoint,
    ThreatAnalysisOriginPoint,
    ThreatAnalysisModelDecisionPoint
)
# No need to import get_db directly for overriding if using app.dependency_overrides

client = TestClient(app)

# Path for patching service functions, adjust if your endpoint file imports services differently
SUMMARY_SERVICE_PATH = "app.api.endpoints.threat_analysis.threat_analysis_service.get_threat_summary"
TRENDS_SERVICE_PATH = "app.api.endpoints.threat_analysis.threat_analysis_service.get_threat_trends"

# --- Tests for GET /api/v1/threat-analysis/summary ---

def test_read_threat_summary_success():
    # Define the expected summary data that the mocked service will return
    expected_summary_data = {
        "total_threats": 100,
        "benign_percentage": 60.0,
        "malicious_percentage": 40.0,
        "average_anomaly_score_24h": 0.75,
        "retraining_last_occurred": "2023-10-26T10:00:00Z",
        "top_3_attack_types": [
            {"type": "Malware", "count": 50},
            {"type": "Phishing", "count": 30},
            {"type": "Scanning", "count": 20},
        ],
    }
    # Create a Pydantic model instance from the dictionary
    expected_summary = ThreatAnalysisSummary(**expected_summary_data)

    # Patch the service function `get_threat_summary`
    # The path to patch is where the function is *looked up*, not where it's defined.
    # If threat_analysis.py imports service functions like `from app.services import threat_analysis_service`,
    # then the path is 'app.api.endpoints.threat_analysis.threat_analysis_service.get_threat_summary'
    # Or, if it's `import app.services.threat_analysis_service as service_name`
    # then `app.api.endpoints.threat_analysis.service_name.get_threat_summary`
    with patch(SUMMARY_SERVICE_PATH, new_callable=AsyncMock) as mock_get_summary:
        mock_get_summary.return_value = expected_summary
        response = client.get("/api/v1/threat-analysis/summary")
        assert response.status_code == 200
        assert response.json() == expected_summary.model_dump(mode='json')
        mock_get_summary.assert_called_once_with(db=AsyncMock(), threat_type_filter=None) # AsyncMock for db due to Depends

def test_read_threat_summary_with_filter():
    expected_summary_data = { "total_threats": 50, "benign_percentage": 50.0, "malicious_percentage": 50.0, "average_anomaly_score_24h": 0.6, "retraining_last_occurred": "N/A", "top_3_attack_types": [{"type": "RULE_MAL_001", "count": 10}] }
    expected_summary = ThreatAnalysisSummary(**expected_summary_data)

    with patch(SUMMARY_SERVICE_PATH, new_callable=AsyncMock) as mock_get_summary:
        mock_get_summary.return_value = expected_summary
        response = client.get("/api/v1/threat-analysis/summary?threat_type=Malware")
        assert response.status_code == 200
        assert response.json() == expected_summary.model_dump(mode='json')
        # Check that the service was called with the filter
        # The db part of the call is complex to assert directly due to Depends, so check other args
        called_args = mock_get_summary.call_args[1] # Get kwargs
        assert called_args['threat_type_filter'] == "Malware"

def test_read_threat_summary_service_exception():
    with patch(SUMMARY_SERVICE_PATH, new_callable=AsyncMock) as mock_get_summary:
        mock_get_summary.side_effect = Exception("Service layer exploded")
        response = client.get("/api/v1/threat-analysis/summary")
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error while fetching summary"}

def test_read_threat_summary_simulated_sqlalchemy_error_from_service():
    from sqlalchemy.exc import SQLAlchemyError
    with patch(SUMMARY_SERVICE_PATH, new_callable=AsyncMock) as mock_get_summary:
        mock_get_summary.side_effect = SQLAlchemyError("Simulated DB error in service")
        response = client.get("/api/v1/threat-analysis/summary")
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error while fetching summary"}

# --- Tests for GET /api/v1/threat-analysis/trends ---

def test_read_threat_trends_success():
    expected_trends_data = {
        "threats_over_time": [{"time_bucket": "2023-01-01T10:00:00", "count": 10}],
        "anomaly_score_heatmap_data": [{"time_bucket": "2023-01-01", "score_range": "0.8-0.9", "count": 5}],
        "threat_origins": [{"country": "USA", "count": 100}],
        "model_decision_stats": [{"model_name": "ModelX", "above_threshold_count": 80, "below_threshold_count": 20}]
    }
    expected_trends = ThreatAnalysisTrends(**expected_trends_data)

    with patch(TRENDS_SERVICE_PATH, new_callable=AsyncMock) as mock_get_trends:
        mock_get_trends.return_value = expected_trends
        response = client.get("/api/v1/threat-analysis/trends")
        assert response.status_code == 200
        assert response.json() == expected_trends.model_dump(mode='json')
        mock_get_trends.assert_called_once_with(db=AsyncMock(), threat_type_filter=None)

def test_read_threat_trends_with_filter():
    expected_trends_data = { "threats_over_time": [], "anomaly_score_heatmap_data": [], "threat_origins": [], "model_decision_stats": [] } # simplified
    expected_trends = ThreatAnalysisTrends(**expected_trends_data)

    with patch(TRENDS_SERVICE_PATH, new_callable=AsyncMock) as mock_get_trends:
        mock_get_trends.return_value = expected_trends
        response = client.get("/api/v1/threat-analysis/trends?threat_type=Anomaly")
        assert response.status_code == 200
        assert response.json() == expected_trends.model_dump(mode='json')
        called_args = mock_get_trends.call_args[1]
        assert called_args['threat_type_filter'] == "Anomaly"

def test_read_threat_trends_service_exception():
    with patch(TRENDS_SERVICE_PATH, new_callable=AsyncMock) as mock_get_trends:
        mock_get_trends.side_effect = Exception("Trends service exploded")
        response = client.get("/api/v1/threat-analysis/trends")
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error while fetching trends"}

# Note on dependency override:
# If you were to use app.dependency_overrides for get_db for more complex scenarios:
# from app.dependencies import get_db # Or wherever your get_db is defined
# async def override_get_db():
#     db = AsyncMock() # Mocked session
#     try:
#         yield db
#     finally:
#         await db.close() # If your real get_db does this
# app.dependency_overrides[get_db] = override_get_db
# ... and then your tests would use this overridden dependency.
# For these specific tests, mocking the service layer directly is often cleaner.

# To run these tests:
# Ensure your PYTHONPATH is set up correctly if running pytest from the root.
# e.g., `PYTHONPATH=. pytest backend/app/tests`
# Or configure pytest paths in pyproject.toml or pytest.ini.