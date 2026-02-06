"""
Unit tests for the EventNormalizer.
Tests normalization of events from various sources to UnifiedEvent schema.
"""
import pytest
from datetime import datetime, timezone
from typing import Dict, Any

from src.silver.normalizer import EventNormalizer, NormalizerError
from src.silver.unified_schema import (
    UnifiedEvent,
    EventSeverity,
    EventType,
    MetricEvent,
    IncidentEvent,
    DeployEvent,
)


class TestEventNormalizer:
    """Test suite for EventNormalizer."""
    
    @pytest.fixture
    def normalizer(self):
        """Create a normalizer instance."""
        return EventNormalizer()
    
    @pytest.fixture
    def dynatrace_problem(self) -> Dict[str, Any]:
        """Sample Dynatrace problem event."""
        return {
            "source": "dynatrace",
            "source_type": "problem",
            "event_id": "PROB-12345",
            "timestamp": "2024-01-15T14:05:00Z",
            "severity": "ERROR",
            "title": "CPU usage spike detected",
            "description": "PROB-12345",
            "status": "OPEN",
            "impact_level": "APPLICATION",
            "root_cause_entity": {
                "entityId": {"id": "HOST-ABCD1234", "type": "HOST"},
                "name": "web-server-01",
            },
            "management_zones": [{"name": "production"}],
            "raw_data": {"problemId": "PROB-12345"},
        }
    
    @pytest.fixture
    def splunk_event(self) -> Dict[str, Any]:
        """Sample Splunk event."""
        return {
            "source": "splunk",
            "source_type": "notable",
            "event_id": "evt-abc123",
            "timestamp": "2024-01-15T14:10:00Z",
            "severity": "HIGH",
            "title": "Suspicious authentication attempt",
            "description": "Multiple failed login attempts detected",
            "host": "auth-server-01",
            "index": "security",
            "fields": {
                "user": "admin",
                "source_ip": "10.0.0.1",
            },
            "raw_data": {},
        }
    
    @pytest.fixture
    def servicenow_incident(self) -> Dict[str, Any]:
        """Sample ServiceNow incident."""
        return {
            "source": "servicenow",
            "number": "INC0012345",
            "timestamp": "2024-01-15T14:15:00Z",
            "priority": "1",
            "state": "2",
            "short_description": "Database connection pool exhausted",
            "description": "Production database unable to accept new connections",
            "assigned_to": "dba-team@example.com",
            "business_service": "payment-service",
            "category": "database",
            "urgency": "1",
            "impact": "1",
            "raw_data": {},
        }
    
    @pytest.fixture
    def pagerduty_incident(self) -> Dict[str, Any]:
        """Sample PagerDuty incident."""
        return {
            "source": "pagerduty",
            "id": "PD-12345",
            "incident_number": "12345",
            "timestamp": "2024-01-15T14:20:00Z",
            "title": "High error rate on API Gateway",
            "description": "Error rate exceeded 5% threshold",
            "status": "triggered",
            "urgency": "high",
            "service": {
                "id": "PSVC123",
                "summary": "api-gateway",
            },
            "assignments": [
                {
                    "assignee": {
                        "summary": "engineer@example.com",
                        "email": "engineer@example.com",
                    }
                }
            ],
            "escalation_policy": {"summary": "Platform Team Escalation"},
            "raw_data": {},
        }
    
    @pytest.fixture
    def github_deployment(self) -> Dict[str, Any]:
        """Sample GitHub deployment event."""
        return {
            "source": "github",
            "source_type": "deployment",
            "deployment_id": "deploy-789",
            "timestamp": "2024-01-15T14:00:00Z",
            "repository": "auth-service",
            "repository_id": "repo-123",
            "ref": "v2.4.1",
            "version": "v2.4.1",
            "previous_version": "v2.4.0",
            "sha": "abc123def456",
            "environment": "production",
            "creator": "deploy-bot",
            "description": "Deploy auth-service v2.4.1",
            "raw_data": {},
        }
    
    @pytest.mark.asyncio
    async def test_normalize_dynatrace_problem(self, normalizer, dynatrace_problem):
        """Test normalization of Dynatrace problem."""
        event = await normalizer.normalize(dynatrace_problem)
        
        assert event is not None
        assert isinstance(event, UnifiedEvent)
        assert event.source == "dynatrace"
        assert event.source_id == "PROB-12345"
        assert event.event_type == EventType.METRIC
        assert event.severity == EventSeverity.CRITICAL
        assert event.entity_id == "HOST-ABCD1234"
        assert event.entity_type == "host"
        assert event.entity_name == "web-server-01"
        assert event.title == "CPU usage spike detected"
        assert "production" in event.tags.get("management_zones", "")
    
    @pytest.mark.asyncio
    async def test_normalize_splunk_event(self, normalizer, splunk_event):
        """Test normalization of Splunk event."""
        event = await normalizer.normalize(splunk_event)
        
        assert event is not None
        assert event.source == "splunk"
        assert event.severity == EventSeverity.CRITICAL
        assert event.event_type == EventType.INCIDENT
        assert event.entity_name == "auth-server-01"
        assert event.title == "Suspicious authentication attempt"
        assert "user" in event.tags
    
    @pytest.mark.asyncio
    async def test_normalize_servicenow_incident(self, normalizer, servicenow_incident):
        """Test normalization of ServiceNow incident."""
        event = await normalizer.normalize(servicenow_incident)
        
        assert event is not None
        assert isinstance(event, IncidentEvent)
        assert event.source == "servicenow"
        assert event.event_type == EventType.INCIDENT
        assert event.severity == EventSeverity.CRITICAL  # Priority 1
        assert event.incident_id == "INC0012345"
        assert event.state == "open"
        assert event.priority == "P1"
        assert "payment-service" in event.affected_services
    
    @pytest.mark.asyncio
    async def test_normalize_pagerduty_incident(self, normalizer, pagerduty_incident):
        """Test normalization of PagerDuty incident."""
        event = await normalizer.normalize(pagerduty_incident)
        
        assert event is not None
        assert isinstance(event, IncidentEvent)
        assert event.source == "pagerduty"
        assert event.event_type == EventType.INCIDENT
        assert event.severity == EventSeverity.CRITICAL  # High urgency
        assert event.state == "open"
        assert event.assigned_to == "engineer@example.com"
        assert "api-gateway" in event.affected_services
    
    @pytest.mark.asyncio
    async def test_normalize_github_deployment(self, normalizer, github_deployment):
        """Test normalization of GitHub deployment."""
        event = await normalizer.normalize(github_deployment)
        
        assert event is not None
        assert isinstance(event, DeployEvent)
        assert event.source == "github"
        assert event.event_type == EventType.DEPLOY
        assert event.severity == EventSeverity.INFO
        assert event.service == "auth-service"
        assert event.version == "v2.4.1"
        assert event.previous_version == "v2.4.0"
        assert event.commit_sha == "abc123def456"
        assert event.deployer == "deploy-bot"
    
    @pytest.mark.asyncio
    async def test_timestamp_normalization(self, normalizer):
        """Test various timestamp formats are normalized to UTC."""
        test_cases = [
            "2024-01-15T14:05:00Z",
            "2024-01-15T14:05:00+00:00",
            "2024-01-15T09:05:00-05:00",  # EST
            1705328700,  # Unix timestamp
        ]
        
        for ts in test_cases:
            event_data = {
                "source": "test",
                "timestamp": ts,
                "title": "Test",
                "severity": "INFO",
            }
            event = await normalizer.normalize(event_data)
            
            assert event is not None
            assert event.timestamp.tzinfo == timezone.utc
    
    @pytest.mark.asyncio
    async def test_severity_mapping_dynatrace(self, normalizer):
        """Test Dynatrace severity mapping."""
        severity_tests = [
            ("INFO", EventSeverity.INFO),
            ("AVAILABILITY", EventSeverity.WARNING),
            ("ERROR", EventSeverity.CRITICAL),
            ("SLOWDOWN", EventSeverity.WARNING),
        ]
        
        for source_sev, expected_sev in severity_tests:
            event_data = {
                "source": "dynatrace",
                "source_type": "event",
                "timestamp": "2024-01-15T14:00:00Z",
                "severity": source_sev,
                "title": "Test",
            }
            event = await normalizer.normalize(event_data)
            assert event.severity == expected_sev
    
    @pytest.mark.asyncio
    async def test_severity_mapping_splunk(self, normalizer):
        """Test Splunk severity mapping."""
        severity_tests = [
            ("LOW", EventSeverity.INFO),
            ("MEDIUM", EventSeverity.WARNING),
            ("HIGH", EventSeverity.CRITICAL),
            ("CRITICAL", EventSeverity.CRITICAL),
        ]
        
        for source_sev, expected_sev in severity_tests:
            event_data = {
                "source": "splunk",
                "timestamp": "2024-01-15T14:00:00Z",
                "severity": source_sev,
                "title": "Test",
            }
            event = await normalizer.normalize(event_data)
            assert event.severity == expected_sev
    
    @pytest.mark.asyncio
    async def test_severity_mapping_servicenow(self, normalizer):
        """Test ServiceNow priority to severity mapping."""
        priority_tests = [
            ("1", EventSeverity.CRITICAL),  # P1
            ("2", EventSeverity.WARNING),    # P2
            ("3", EventSeverity.INFO),       # P3
        ]
        
        for priority, expected_sev in priority_tests:
            event_data = {
                "source": "servicenow",
                "timestamp": "2024-01-15T14:00:00Z",
                "priority": priority,
                "state": "1",
                "short_description": "Test",
                "number": "INC001",
            }
            event = await normalizer.normalize(event_data)
            assert event.severity == expected_sev
    
    @pytest.mark.asyncio
    async def test_unknown_source_fallback(self, normalizer):
        """Test fallback for unknown sources."""
        event_data = {
            "source": "unknown-system",
            "timestamp": "2024-01-15T14:00:00Z",
            "severity": "WARNING",
            "title": "Unknown event",
            "event_type": "alert",
        }
        event = await normalizer.normalize(event_data)
        
        assert event is not None
        assert event.source == "unknown-system"
        assert event.severity == EventSeverity.WARNING
        assert event.event_type == EventType.ALERT
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, normalizer):
        """Test statistics are tracked correctly."""
        events = [
            {"source": "dynatrace", "timestamp": "2024-01-15T14:00:00Z", "title": "Test 1", "severity": "INFO"},
            {"source": "splunk", "timestamp": "2024-01-15T14:00:00Z", "title": "Test 2", "severity": "INFO"},
            {"source": "dynatrace", "timestamp": "2024-01-15T14:00:00Z", "title": "Test 3", "severity": "INFO"},
        ]
        
        for event_data in events:
            await normalizer.normalize(event_data)
        
        stats = normalizer.get_stats()
        assert stats["normalized"] == 3
        assert stats["failed"] == 0
        assert stats["by_source"]["dynatrace"] == 2
        assert stats["by_source"]["splunk"] == 1
    
    @pytest.mark.asyncio
    async def test_malformed_event_handling(self, normalizer):
        """Test handling of malformed events."""
        malformed_events = [
            {},  # Empty
            {"source": "test"},  # Missing required fields
            {"timestamp": "invalid"},  # Invalid timestamp
        ]
        
        for event_data in malformed_events:
            event = await normalizer.normalize(event_data)
            # Should handle gracefully, might return None or generic event
            # The key is not to raise unhandled exceptions
    
    @pytest.mark.asyncio
    async def test_entity_extraction_dynatrace(self, normalizer):
        """Test entity information extraction from Dynatrace."""
        event_data = {
            "source": "dynatrace",
            "source_type": "event",
            "timestamp": "2024-01-15T14:00:00Z",
            "severity": "INFO",
            "title": "Test",
            "entity_id": "SERVICE-123ABC",
            "entity_name": "auth-service",
        }
        
        event = await normalizer.normalize(event_data)
        assert event.entity_id == "SERVICE-123ABC"
        assert event.entity_type == "service"
        assert event.entity_name == "auth-service"
    
    @pytest.mark.asyncio
    async def test_reset_stats(self, normalizer):
        """Test statistics reset."""
        event_data = {
            "source": "test",
            "timestamp": "2024-01-15T14:00:00Z",
            "title": "Test",
            "severity": "INFO",
        }
        await normalizer.normalize(event_data)
        
        assert normalizer.get_stats()["normalized"] == 1
        
        normalizer.reset_stats()
        assert normalizer.get_stats()["normalized"] == 0
        assert normalizer.get_stats()["by_source"] == {}
