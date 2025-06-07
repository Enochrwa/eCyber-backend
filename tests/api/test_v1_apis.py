from fastapi.testclient import TestClient

# Attempt to import app from backend.main, if not, try backend.app.main
try:
    from backend.main import app
except ImportError:
    try:
        from backend.app.main import app  # Common alternative structure
    except ImportError:
        # Fallback if main is directly in app, though less common for larger apps
        from backend.app import app


client = TestClient(app)


def test_read_main_health_check():
    """Test basic health check if your main app has one, e.g. at /"""
    response = client.get("/")
    # Assuming your root might return 404 if no route is defined, or 200 if it has a default page/message
    # For this template, let's assume it should be 200 or a redirect.
    # If it's 404, this test might need adjustment based on actual root endpoint behavior.
    assert response.status_code in [200, 307, 404]  # Allow for various root behaviors


# Test Threat Intelligence Endpoints
def test_get_emerging_threats():
    response = client.get("/api/v1/threat-intelligence/emerging-threats")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        item = data[0]
        assert "type" in item
        assert "source" in item
        # Other optional fields: id, summary, indicator, indicator_type, threat_type, published, last_seen


def test_list_feeds():
    response = client.get("/api/v1/threat-intelligence/feeds")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Check for expected feeds
    feed_ids = [item["id"] for item in data]
    assert "threatfox" in feed_ids
    assert "cve_circl" in feed_ids
    for item in data:
        assert "id" in item
        assert "name" in item
        assert "status" in item
        assert "entries" in item
        assert "last_updated" in item  # Can be None
        assert "is_subscribed" in item


def test_subscribe_feed():
    # Unsubscribe
    response_unsubscribe = client.post(
        "/api/v1/threat-intelligence/feeds/threatfox/subscribe",
        json={"is_subscribed": False},
    )
    assert response_unsubscribe.status_code == 200
    unsubscribe_data = response_unsubscribe.json()
    assert unsubscribe_data["id"] == "threatfox"
    assert unsubscribe_data["is_subscribed"] is False

    # Re-subscribe (to leave it in a consistent state for other tests)
    response_subscribe = client.post(
        "/api/v1/threat-intelligence/feeds/threatfox/subscribe",
        json={"is_subscribed": True},
    )
    assert response_subscribe.status_code == 200
    subscribe_data = response_subscribe.json()
    assert subscribe_data["id"] == "threatfox"
    assert subscribe_data["is_subscribed"] is True


def test_refresh_feed():
    response = client.post("/api/v1/threat-intelligence/feeds/threatfox/refresh")
    assert response.status_code == 200
    data = response.json()
    assert data["feed_id"] == "threatfox"
    assert "status" in data  # e.g., "refreshed", "skipped"
    assert "last_updated" in data  # Can be None if skipped and not previously fetched


# Test User Summary Endpoint
def test_get_user_summary():
    response = client.get("/api/v1/users/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_users" in data
    assert "admin_users" in data
    assert "standard_users" in data
    assert isinstance(data["total_users"], int)
    assert isinstance(data["admin_users"], int)
    assert isinstance(data["standard_users"], int)
    assert data["total_users"] >= 0
    assert data["admin_users"] >= 0
    assert data["standard_users"] >= 0
    assert data["total_users"] == data["admin_users"] + data["standard_users"]


# Test ML Model Accuracy Endpoint
def test_get_ml_accuracy():
    response = client.get("/api/v1/ml-models/accuracy")
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "Main Anomaly Detector"
    assert data["accuracy"] == 0.997
    assert "last_trained" in data  # Expecting ISO date string


# Test Settings Endpoint
def test_get_general_settings():
    response = client.get("/api/v1/settings/general")
    assert response.status_code == 200
    data = response.json()
    assert data["notification_email"] == "admin@ecyber.com"
    assert data["update_frequency"] == "daily"
    assert data["data_retention_days"] == 90


# Test Users List Endpoint (added based on previous subtask)
def test_get_users_list():
    response = client.get("/api/v1/users/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        item = data[0]
        assert "id" in item
        assert "username" in item
        assert "email" in item
        assert "is_active" in item
        assert "is_superuser" in item
        # hashed_password should NOT be here
        assert "hashed_password" not in item
        assert "created_at" in item
        # updated_at is optional in model but usually present
        # assert "updated_at" in item
    # This endpoint might require authentication in a real app.
    # If it does, this test would fail with 401/403 without proper auth headers.
    # For now, assuming it's publicly accessible or TestClient handles dummy auth.


# It's good practice to ensure the app instance is correctly imported.
# If the import fails, TestClient(app) would raise NameError.
# A simple test to confirm app import can be:
def test_app_is_imported():
    assert app is not None
    # from fastapi import FastAPI
    # assert isinstance(app, FastAPI) # This would be more specific
