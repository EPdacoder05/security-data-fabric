"""
Test Bronze layer connectors.
Tests basic functionality of all data source connectors.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from src.bronze import (
    DynatraceConnector,
    SplunkConnector,
    ServiceNowConnector,
    PagerDutyConnector,
    GitHubConnector,
    ConnectorError,
    ConnectorAuthError,
    schema_registry,
    EventSource,
)


@pytest.fixture
def mock_httpx_client():
    """Mock httpx AsyncClient."""
    client = AsyncMock()
    return client


class TestDynatraceConnector:
    """Test Dynatrace connector."""
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test connector initialization."""
        connector = DynatraceConnector(
            base_url="https://example.live.dynatrace.com",
            api_token="dt_test_token_12345"
        )
        assert connector.name == "Dynatrace"
        assert connector.api_key == "dt_test_token_12345"
    
    def test_headers(self):
        """Test API headers generation."""
        connector = DynatraceConnector(
            base_url="https://example.live.dynatrace.com",
            api_token="dt_test_token"
        )
        headers = connector._get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Api-Token dt_test_token"
    
    @pytest.mark.asyncio
    async def test_transform_problem(self):
        """Test problem transformation."""
        connector = DynatraceConnector(
            base_url="https://example.live.dynatrace.com",
            api_token="dt_test_token"
        )
        
        problem = {
            "problemId": "P-123456",
            "startTime": 1705320000000,
            "severityLevel": "ERROR",
            "title": "High CPU usage",
            "displayId": "P-123",
            "status": "OPEN",
            "impactLevel": "SERVICE",
            "affectedEntities": [],
        }
        
        result = connector._transform_problem(problem)
        
        assert result["source"] == "dynatrace"
        assert result["source_type"] == "problem"
        assert result["event_id"] == "P-123456"
        assert result["severity"] == "ERROR"
        assert result["title"] == "High CPU usage"


class TestSplunkConnector:
    """Test Splunk connector."""
    
    @pytest.mark.asyncio
    async def test_initialization_with_token(self):
        """Test connector initialization with bearer token."""
        connector = SplunkConnector(
            base_url="https://splunk.example.com:8089",
            bearer_token="splunk_bearer_token_12345"
        )
        assert connector.name == "Splunk"
        assert connector.api_key == "splunk_bearer_token_12345"
    
    @pytest.mark.asyncio
    async def test_initialization_with_credentials(self):
        """Test connector initialization with username/password."""
        connector = SplunkConnector(
            base_url="https://splunk.example.com:8089",
            username="admin",
            password="changeme"
        )
        assert connector.username == "admin"
        assert connector.password == "changeme"
    
    def test_transform_event(self):
        """Test event transformation."""
        connector = SplunkConnector(
            base_url="https://splunk.example.com:8089",
            bearer_token="token"
        )
        
        event = {
            "_time": "2024-01-15T10:30:00Z",
            "_cd": "event_123",
            "severity": "high",
            "title": "Security Alert",
            "sourcetype": "security",
            "index": "main",
            "source": "firewall",
            "host": "fw-01",
            "_raw": "Security event detected",
        }
        
        result = connector._transform_event(event)
        
        assert result["source"] == "splunk"
        assert result["source_type"] == "security"
        assert result["severity"] == "HIGH"


class TestServiceNowConnector:
    """Test ServiceNow connector."""
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test connector initialization."""
        connector = ServiceNowConnector(
            instance="https://dev12345.service-now.com",
            username="admin",
            password="password"
        )
        assert connector.name == "ServiceNow"
        assert connector.username == "admin"
    
    def test_priority_mapping(self):
        """Test priority to severity mapping."""
        assert ServiceNowConnector._map_priority_to_severity("1") == "CRITICAL"
        assert ServiceNowConnector._map_priority_to_severity("2") == "HIGH"
        assert ServiceNowConnector._map_priority_to_severity("3") == "MEDIUM"
        assert ServiceNowConnector._map_priority_to_severity("4") == "LOW"
        assert ServiceNowConnector._map_priority_to_severity("5") == "INFO"
    
    def test_transform_incident(self):
        """Test incident transformation."""
        connector = ServiceNowConnector(
            instance="https://dev12345.service-now.com",
            username="admin",
            password="password"
        )
        
        incident = {
            "sys_id": "inc_123456",
            "sys_created_on": "2024-01-15 10:30:00",
            "short_description": "Database connection failed",
            "description": "Unable to connect to production database",
            "number": "INC0001234",
            "state": "2",
            "priority": "2",
            "urgency": "2",
            "impact": "2",
        }
        
        result = connector._transform_incident(incident)
        
        assert result["source"] == "servicenow"
        assert result["source_type"] == "incident"
        assert result["event_id"] == "inc_123456"
        assert result["severity"] == "HIGH"
        assert result["number"] == "INC0001234"


class TestPagerDutyConnector:
    """Test PagerDuty connector."""
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test connector initialization."""
        connector = PagerDutyConnector(
            api_key="pd_api_key_12345",
            from_email="alerts@example.com"
        )
        assert connector.name == "PagerDuty"
        assert connector.api_key == "pd_api_key_12345"
        assert connector.from_email == "alerts@example.com"
    
    def test_urgency_mapping(self):
        """Test urgency to severity mapping."""
        assert PagerDutyConnector._map_urgency_to_severity("high") == "HIGH"
        assert PagerDutyConnector._map_urgency_to_severity("low") == "LOW"
    
    def test_transform_incident(self):
        """Test incident transformation."""
        connector = PagerDutyConnector(api_key="pd_key")
        
        incident = {
            "id": "PD123",
            "created_at": "2024-01-15T10:30:00Z",
            "urgency": "high",
            "title": "Database down",
            "description": "Production database is unreachable",
            "status": "triggered",
            "incident_number": 12345,
            "service": {"name": "Database Service"},
        }
        
        result = connector._transform_incident(incident)
        
        assert result["source"] == "pagerduty"
        assert result["source_type"] == "incident"
        assert result["event_id"] == "PD123"
        assert result["severity"] == "HIGH"
        assert result["status"] == "triggered"


class TestGitHubConnector:
    """Test GitHub connector."""
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test connector initialization."""
        connector = GitHubConnector(
            token="ghp_test_token_12345",
            owner="example-org",
            repo="example-repo"
        )
        assert connector.name == "GitHub"
        assert connector.api_key == "ghp_test_token_12345"
        assert connector.owner == "example-org"
        assert connector.repo == "example-repo"
    
    def test_deployment_state_mapping(self):
        """Test deployment state to severity mapping."""
        assert GitHubConnector._map_deployment_state_to_severity("error") == "HIGH"
        assert GitHubConnector._map_deployment_state_to_severity("failure") == "HIGH"
        assert GitHubConnector._map_deployment_state_to_severity("success") == "INFO"
    
    def test_transform_release(self):
        """Test release transformation."""
        connector = GitHubConnector(token="token", owner="org", repo="repo")
        
        release = {
            "id": 123456,
            "published_at": "2024-01-15T10:30:00Z",
            "name": "v1.2.3",
            "tag_name": "v1.2.3",
            "body": "Bug fixes and improvements",
            "draft": False,
            "prerelease": False,
            "author": {"login": "release-bot"},
        }
        
        result = connector._transform_release(release)
        
        assert result["source"] == "github"
        assert result["source_type"] == "release"
        assert result["severity"] == "INFO"
        assert result["tag_name"] == "v1.2.3"


class TestSchemaRegistry:
    """Test schema registry."""
    
    def test_list_sources(self):
        """Test listing registered sources."""
        sources = schema_registry.list_sources()
        assert "dynatrace" in sources
        assert "splunk" in sources
        assert "servicenow" in sources
        assert "pagerduty" in sources
        assert "github" in sources
    
    def test_validate_dynatrace_event(self):
        """Test Dynatrace event validation."""
        event = {
            "source": "dynatrace",
            "source_type": "problem",
            "event_id": "P-123456",
            "timestamp": "2024-01-15T10:30:00Z",
            "severity": "HIGH",
            "title": "Test problem",
            "description": "Test description",
            "raw_data": {},
            "ingested_at": "2024-01-15T10:30:05Z",
        }
        
        is_valid, validated, error = schema_registry.validate_event(event)
        
        assert is_valid is True
        assert validated is not None
        assert error is None
    
    def test_validate_invalid_event(self):
        """Test validation of invalid event."""
        event = {
            "source": "dynatrace",
            # Missing required fields
        }
        
        is_valid, validated, error = schema_registry.validate_event(event)
        
        assert is_valid is False
        assert validated is None
        assert error is not None
    
    def test_validate_batch(self):
        """Test batch validation."""
        events = [
            {
                "source": "dynatrace",
                "source_type": "problem",
                "event_id": "P-1",
                "timestamp": "2024-01-15T10:30:00Z",
                "severity": "HIGH",
                "title": "Event 1",
                "description": "",
                "raw_data": {},
                "ingested_at": "2024-01-15T10:30:05Z",
            },
            {
                "source": "splunk",
                "source_type": "alert",
                "event_id": "S-1",
                "timestamp": "2024-01-15T10:31:00Z",
                "severity": "MEDIUM",
                "title": "Event 2",
                "description": "",
                "raw_data": {},
                "ingested_at": "2024-01-15T10:31:05Z",
            },
        ]
        
        valid, errors = schema_registry.validate_batch(events)
        
        assert len(valid) == 2
        assert len(errors) == 0
    
    def test_get_schema_info(self):
        """Test getting schema information."""
        info = schema_registry.get_schema_info(EventSource.DYNATRACE)
        
        assert info["source"] == "dynatrace"
        assert "versions" in info
        assert "1.0" in info["versions"]
    
    def test_get_json_schema(self):
        """Test getting JSON schema."""
        json_schema = schema_registry.get_json_schema(EventSource.SPLUNK)
        
        assert json_schema is not None
        assert "properties" in json_schema
        assert "required" in json_schema
