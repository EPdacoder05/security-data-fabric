"""Tests for data ingestion connectors."""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.ingestion import (
    DynatraceConnector,
    SplunkConnector,
    ServiceNowConnector,
    PagerDutyConnector,
    GitHubWebhookConnector,
)


@pytest.mark.asyncio
async def test_dynatrace_connector_initialization():
    """Test Dynatrace connector initialization."""
    connector = DynatraceConnector(
        url="https://test.dynatrace.com",
        api_token="test-token",
    )
    
    assert connector.name == "dynatrace"
    assert connector.url == "https://test.dynatrace.com"
    assert connector.api_token == "test-token"
    assert not connector.connected


@pytest.mark.asyncio
async def test_github_webhook_signature_verification():
    """Test GitHub webhook signature verification."""
    connector = GitHubWebhookConnector(webhook_secret="test-secret")
    
    payload = b'{"test": "data"}'
    # Valid signature
    import hmac
    import hashlib
    
    signature = "sha256=" + hmac.new(
        b"test-secret", payload, hashlib.sha256
    ).hexdigest()
    
    assert connector.verify_signature(payload, signature)
    
    # Invalid signature
    assert not connector.verify_signature(payload, "sha256=invalid")


@pytest.mark.asyncio
async def test_github_webhook_process_deployment(sample_github_webhook_payload):
    """Test GitHub webhook deployment processing."""
    connector = GitHubWebhookConnector()
    await connector.connect()
    
    events = await connector.fetch(
        event_type="deployment",
        payload=sample_github_webhook_payload,
    )
    
    assert len(events) == 1
    event = events[0]
    assert event["source"] == "github"
    assert event["raw_data"]["event_type"] == "deployment"
    assert event["raw_data"]["environment"] == "production"


def test_base_connector_rate_limiting():
    """Test base connector rate limiting."""
    from src.ingestion.base_connector import BaseConnector
    
    class TestConnector(BaseConnector):
        async def connect(self):
            return True
        
        async def disconnect(self):
            pass
        
        async def fetch(self, **kwargs):
            return []
        
        async def health_check(self):
            return True
    
    connector = TestConnector(name="test", rate_limit_per_minute=5)
    assert connector.rate_limit_per_minute == 5
    assert connector._request_times == []
