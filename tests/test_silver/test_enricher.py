"""
Unit tests for the EventEnricher.
Tests enrichment logic including ownership, infrastructure context, and SLA calculations.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch

from src.silver.enricher import (
    EventEnricher,
    OwnershipRegistry,
    InfrastructureRegistry,
    SLACalculator,
)
from src.silver.unified_schema import UnifiedEvent, EventSeverity, EventType


class TestOwnershipRegistry:
    """Test suite for OwnershipRegistry."""
    
    def test_get_team_for_service(self):
        """Test getting team for a service."""
        team = OwnershipRegistry.get_team_for_service("auth-service")
        assert team == "platform"
        
        team = OwnershipRegistry.get_team_for_service("payment-service")
        assert team == "payments"
        
        team = OwnershipRegistry.get_team_for_service("unknown-service")
        assert team is None
    
    def test_get_team_contacts(self):
        """Test getting team contact information."""
        contacts = OwnershipRegistry.get_team_contacts("platform")
        assert "slack" in contacts
        assert "email" in contacts
        assert contacts["slack"] == "#team-platform"


class TestInfrastructureRegistry:
    """Test suite for InfrastructureRegistry."""
    
    def test_get_infrastructure_context_for_host(self):
        """Test getting infrastructure context for a host."""
        context = InfrastructureRegistry.get_infrastructure_context(
            "host", "web-server-01"
        )
        assert context["cluster"] == "prod-cluster-1"
        assert context["region"] == "us-east-1"
        assert context["environment"] == "production"
    
    def test_get_infrastructure_context_for_service(self):
        """Test getting infrastructure context for a service."""
        context = InfrastructureRegistry.get_infrastructure_context(
            "service", "auth-service"
        )
        assert context["cluster"] == "prod-cluster-1"
        assert context["region"] == "us-east-1"
    
    def test_get_infrastructure_context_unknown(self):
        """Test getting context for unknown entity."""
        context = InfrastructureRegistry.get_infrastructure_context(
            "host", "unknown-host"
        )
        assert context == {}


class TestSLACalculator:
    """Test suite for SLACalculator."""
    
    def test_calculate_impact_critical_incident(self):
        """Test SLA impact calculation for critical incident."""
        impact = SLACalculator.calculate_impact(
            "auth-service",
            EventSeverity.CRITICAL,
            EventType.INCIDENT,
        )
        
        assert impact["has_sla"] is True
        assert impact["impacts_sla"] is True
        assert "sla_targets" in impact
        assert impact["sla_targets"]["availability"] == 99.99
    
    def test_calculate_impact_info_event(self):
        """Test SLA impact for info-level event."""
        impact = SLACalculator.calculate_impact(
            "auth-service",
            EventSeverity.INFO,
            EventType.LOG,
        )
        
        assert impact["has_sla"] is True
        assert impact["impacts_sla"] is False
    
    def test_calculate_impact_unknown_service(self):
        """Test SLA impact for unknown service."""
        impact = SLACalculator.calculate_impact(
            "unknown-service",
            EventSeverity.CRITICAL,
            EventType.INCIDENT,
        )
        
        assert impact["has_sla"] is False


class TestEventEnricher:
    """Test suite for EventEnricher."""
    
    @pytest.fixture
    def enricher(self):
        """Create an enricher instance without database session."""
        return EventEnricher(db_session=None)
    
    @pytest.fixture
    def enricher_with_db(self):
        """Create an enricher instance with mock database session."""
        mock_session = AsyncMock()
        return EventEnricher(db_session=mock_session)
    
    @pytest.fixture
    def sample_event(self) -> UnifiedEvent:
        """Create a sample event."""
        return UnifiedEvent(
            source="dynatrace",
            source_id="PROB-12345",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-ABCD1234",
            entity_type="host",
            entity_name="web-server-01",
            title="CPU usage spike detected",
            description="CPU usage increased from 45% to 89%",
        )
    
    @pytest.mark.asyncio
    async def test_enrich_adds_ownership(self, enricher, sample_event):
        """Test that enrichment adds ownership information."""
        sample_event.service_name = "auth-service"
        enriched = await enricher.enrich(sample_event)
        
        assert enriched.team == "platform"
        assert "team_contacts" in enriched.metadata
        assert enriched.metadata["team_contacts"]["slack"] == "#team-platform"
        assert enricher.stats.ownership_added == 1
    
    @pytest.mark.asyncio
    async def test_enrich_adds_infrastructure_context(self, enricher, sample_event):
        """Test that enrichment adds infrastructure context."""
        enriched = await enricher.enrich(sample_event)
        
        assert enriched.environment == "production"
        assert enriched.region == "us-east-1"
        assert "cluster" in enriched.tags
        assert enriched.tags["cluster"] == "prod-cluster-1"
        assert enricher.stats.infrastructure_added == 1
    
    @pytest.mark.asyncio
    async def test_enrich_calculates_sla_impact(self, enricher):
        """Test SLA impact calculation."""
        event = UnifiedEvent(
            source="servicenow",
            event_type=EventType.INCIDENT,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            service_name="auth-service",
            title="Service outage",
        )
        
        enriched = await enricher.enrich(event)
        
        assert "sla_impact" in enriched.metadata
        assert enriched.metadata["sla_impact"]["has_sla"] is True
        assert enriched.metadata["sla_impact"]["impacts_sla"] is True
        assert enricher.stats.sla_calculated == 1
    
    @pytest.mark.asyncio
    async def test_enrich_enhances_severity_for_critical_service(self, enricher):
        """Test severity enhancement for critical production services."""
        event = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.WARNING,  # Initially warning
            entity_type="host",
            entity_name="web-server-01",  # Maps to production
            service_name="auth-service",  # Critical service
            title="Elevated CPU usage",
        )
        
        enriched = await enricher.enrich(event)
        
        # Severity should be upgraded for critical prod service
        assert enriched.severity == EventSeverity.CRITICAL
        assert "severity_enhanced" in enriched.metadata
        assert enriched.metadata["severity_enhanced"]["original"] == "warning"
        assert enricher.stats.severity_enhanced == 1
    
    @pytest.mark.asyncio
    async def test_infer_service_name_from_entity(self, enricher):
        """Test service name inference from entity."""
        event = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            entity_type="service",
            entity_name="payment-service",
            title="Service metric",
        )
        
        enriched = await enricher.enrich(event)
        
        assert enriched.service_name == "payment-service"
        assert enriched.team == "payments"
    
    @pytest.mark.asyncio
    async def test_infer_service_name_from_title(self, enricher):
        """Test service name inference from title."""
        event = UnifiedEvent(
            source="splunk",
            event_type=EventType.ALERT,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.WARNING,
            title="Alert from auth-service: high latency",
        )
        
        enriched = await enricher.enrich(event)
        
        # Should infer service name from title
        assert enriched.service_name == "auth-service"
        assert enriched.team == "platform"
    
    @pytest.mark.asyncio
    async def test_enrich_batch(self, enricher):
        """Test batch enrichment."""
        events = [
            UnifiedEvent(
                source="test",
                event_type=EventType.ALERT,
                timestamp=datetime.now(timezone.utc),
                severity=EventSeverity.INFO,
                entity_type="host",
                entity_name="web-server-01",
                title=f"Test event {i}",
            )
            for i in range(5)
        ]
        
        enriched = await enricher.enrich_batch(events)
        
        assert len(enriched) == 5
        assert all(e.environment == "production" for e in enriched)
        assert enricher.stats.total_enriched == 5
    
    @pytest.mark.asyncio
    async def test_enrichment_handles_missing_data_gracefully(self, enricher):
        """Test enrichment handles events with minimal data."""
        event = UnifiedEvent(
            source="unknown",
            event_type=EventType.LOG,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            title="Minimal event",
            # No entity, service, or other optional fields
        )
        
        # Should not raise exceptions
        enriched = await enricher.enrich(event)
        
        assert enriched is not None
        assert enriched.title == "Minimal event"
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, enricher):
        """Test statistics tracking."""
        event = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_type="host",
            entity_name="web-server-01",
            service_name="auth-service",
            title="Test",
        )
        
        await enricher.enrich(event)
        
        stats = enricher.get_stats()
        assert stats["total_enriched"] == 1
        assert stats["infrastructure_added"] == 1
        assert stats["ownership_added"] == 1
        assert stats["sla_calculated"] == 1
        assert stats["success_rate"] == 1.0
    
    @pytest.mark.asyncio
    async def test_reset_stats(self, enricher):
        """Test statistics reset."""
        event = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            title="Test",
        )
        await enricher.enrich(event)
        
        assert enricher.stats.total_enriched == 1
        
        enricher.reset_stats()
        assert enricher.stats.total_enriched == 0
    
    @pytest.mark.asyncio
    async def test_enrichment_with_existing_metadata(self, enricher):
        """Test enrichment preserves existing metadata."""
        event = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            title="Test",
            metadata={"existing_key": "existing_value"},
        )
        
        enriched = await enricher.enrich(event)
        
        # Should preserve existing metadata
        assert "existing_key" in enriched.metadata
        assert enriched.metadata["existing_key"] == "existing_value"
    
    @pytest.mark.asyncio
    async def test_enrichment_with_existing_tags(self, enricher, sample_event):
        """Test enrichment preserves existing tags."""
        sample_event.tags = {"custom_tag": "custom_value"}
        
        enriched = await enricher.enrich(sample_event)
        
        # Should preserve existing tags
        assert "custom_tag" in enriched.tags
        assert enriched.tags["custom_tag"] == "custom_value"
        # Should also add new tags
        assert "cluster" in enriched.tags
    
    @pytest.mark.asyncio
    async def test_no_severity_enhancement_for_non_critical_services(self, enricher):
        """Test that severity is not enhanced for non-critical services."""
        event = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.WARNING,
            service_name="non-critical-service",
            environment="development",
            title="Test",
        )
        
        enriched = await enricher.enrich(event)
        
        # Severity should not be upgraded
        assert enriched.severity == EventSeverity.WARNING
        assert enricher.stats.severity_enhanced == 0
    
    @pytest.mark.asyncio
    async def test_severity_enhancement_for_repeated_issues(self, enricher):
        """Test severity enhancement based on event repetition."""
        event = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            entity_id="test-entity",
            title="Repeated issue",
            metadata={
                "recent_events": {
                    "count": 10,  # Many recent events
                    "lookback_hours": 1,
                }
            },
        )
        
        enriched = await enricher.enrich(event)
        
        # Severity should be upgraded due to repetition
        assert enriched.severity == EventSeverity.WARNING
        assert "severity_enhanced" in enriched.metadata
        assert "Repeated issues" in enriched.metadata["severity_enhanced"]["reason"]
