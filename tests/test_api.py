"""Tests for API endpoints."""
import pytest
from datetime import datetime


def test_health_endpoint(test_client):
    """Test health check endpoint."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


def test_ready_endpoint(test_client):
    """Test readiness endpoint."""
    response = test_client.get("/ready")
    # May fail if database is not available, which is ok for unit tests
    assert response.status_code in [200, 503]


def test_search_endpoint_requires_query(test_client):
    """Test search endpoint requires query."""
    response = test_client.post("/search", json={})
    assert response.status_code == 422  # Validation error


def test_predictions_active_endpoint(test_client):
    """Test active predictions endpoint."""
    response = test_client.get("/predictions/active")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_dashboard_overview_endpoint(test_client):
    """Test dashboard overview endpoint."""
    response = test_client.get("/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "active_incidents" in data
    assert "active_predictions" in data


def test_incidents_list_endpoint(test_client):
    """Test incidents list endpoint."""
    response = test_client.get("/incidents")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
