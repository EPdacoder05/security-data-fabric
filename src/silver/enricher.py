"""
Event enricher for Silver layer.
Adds contextual information to normalized events:
- Ownership metadata (service -> team mapping)
- Infrastructure context (host -> cluster -> region)
- Historical context (recent incidents)
- Severity enhancement
- SLA impact calculation
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
import logging
from dataclasses import dataclass, field

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.silver.unified_schema import UnifiedEvent, EventSeverity, EventType
from src.config.settings import settings

logger = logging.getLogger(__name__)


# Constants for enrichment logic
REPEATED_ISSUE_THRESHOLD = 5  # Number of events within time window to trigger severity upgrade


@dataclass
class EnrichmentStats:
    """Statistics for enrichment operations."""
    total_enriched: int = 0
    ownership_added: int = 0
    infrastructure_added: int = 0
    historical_context_added: int = 0
    severity_enhanced: int = 0
    sla_calculated: int = 0
    enrichment_failures: int = 0


class OwnershipRegistry:
    """
    Registry for service ownership mapping.
    In production, this would query a CMDB or service catalog.
    """
    
    # Example mappings - would come from database/config
    SERVICE_TEAMS = {
        "auth-service": "platform",
        "api-gateway": "platform",
        "payment-service": "payments",
        "user-service": "identity",
        "notification-service": "communications",
        "analytics-service": "data",
    }
    
    TEAM_CONTACTS = {
        "platform": {"slack": "#team-platform", "email": "platform@example.com"},
        "payments": {"slack": "#team-payments", "email": "payments@example.com"},
        "identity": {"slack": "#team-identity", "email": "identity@example.com"},
        "communications": {"slack": "#team-comms", "email": "comms@example.com"},
        "data": {"slack": "#team-data", "email": "data@example.com"},
    }
    
    @classmethod
    def get_team_for_service(cls, service_name: Optional[str]) -> Optional[str]:
        """Get owning team for a service."""
        if not service_name:
            return None
        return cls.SERVICE_TEAMS.get(service_name.lower())
    
    @classmethod
    def get_team_contacts(cls, team: str) -> Dict[str, str]:
        """Get contact information for a team."""
        return cls.TEAM_CONTACTS.get(team, {})


class InfrastructureRegistry:
    """
    Registry for infrastructure topology.
    In production, this would query a CMDB or cloud provider APIs.
    """
    
    # Example mappings - would come from database/cloud APIs
    HOST_MAPPINGS = {
        "web-server-01": {
            "cluster": "prod-cluster-1",
            "region": "us-east-1",
            "environment": "production",
            "zone": "us-east-1a",
        },
        "web-server-02": {
            "cluster": "prod-cluster-1",
            "region": "us-east-1",
            "environment": "production",
            "zone": "us-east-1b",
        },
        "db-primary-01": {
            "cluster": "prod-db-cluster",
            "region": "us-east-1",
            "environment": "production",
            "zone": "us-east-1a",
        },
    }
    
    SERVICE_MAPPINGS = {
        "auth-service": {
            "cluster": "prod-cluster-1",
            "region": "us-east-1",
            "environment": "production",
        },
        "payment-service": {
            "cluster": "prod-cluster-2",
            "region": "us-west-2",
            "environment": "production",
        },
    }
    
    @classmethod
    def get_infrastructure_context(
        cls, entity_type: Optional[str], entity_name: Optional[str]
    ) -> Dict[str, str]:
        """Get infrastructure context for an entity."""
        if not entity_type or not entity_name:
            return {}
        
        if entity_type == "host":
            return cls.HOST_MAPPINGS.get(entity_name, {})
        elif entity_type in ["service", "application"]:
            return cls.SERVICE_MAPPINGS.get(entity_name, {})
        
        return {}


class SLACalculator:
    """
    Calculator for SLA impact.
    In production, this would use actual SLA definitions and tracking.
    """
    
    # SLA definitions
    SERVICE_SLAS = {
        "auth-service": {"availability": 99.99, "response_time_p99": 100},
        "payment-service": {"availability": 99.999, "response_time_p99": 50},
        "api-gateway": {"availability": 99.95, "response_time_p99": 200},
    }
    
    @classmethod
    def calculate_impact(
        cls,
        service_name: Optional[str],
        severity: EventSeverity,
        event_type: EventType,
    ) -> Dict[str, Any]:
        """
        Calculate SLA impact for an event.
        
        Args:
            service_name: Name of the affected service
            severity: Event severity
            event_type: Event type
            
        Returns:
            Dictionary with SLA impact information
        """
        if not service_name or service_name not in cls.SERVICE_SLAS:
            return {"has_sla": False}
        
        sla = cls.SERVICE_SLAS[service_name]
        
        # Determine if event impacts SLA
        impacts_sla = False
        impact_reason = []
        
        if event_type == EventType.INCIDENT:
            if severity in [EventSeverity.CRITICAL, EventSeverity.EXTREME]:
                impacts_sla = True
                impact_reason.append("critical incident affects availability")
        elif event_type == EventType.METRIC:
            if severity in [EventSeverity.CRITICAL, EventSeverity.EXTREME]:
                impacts_sla = True
                impact_reason.append("metric threshold breach may affect SLA")
        
        return {
            "has_sla": True,
            "impacts_sla": impacts_sla,
            "sla_targets": sla,
            "impact_reason": "; ".join(impact_reason) if impact_reason else None,
        }


class EventEnricher:
    """
    Enriches normalized events with contextual information.
    Uses async database queries and external registries.
    """
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        """
        Initialize the enricher.
        
        Args:
            db_session: Optional database session for historical queries
        """
        self.db_session = db_session
        self.stats = EnrichmentStats()
        
        logger.info("Event enricher initialized")
    
    async def enrich(self, event: UnifiedEvent) -> UnifiedEvent:
        """
        Enrich an event with contextual information.
        
        Args:
            event: UnifiedEvent to enrich
            
        Returns:
            Enriched UnifiedEvent
        """
        try:
            # Add ownership metadata
            await self._add_ownership(event)
            
            # Add infrastructure context
            await self._add_infrastructure_context(event)
            
            # Add historical context
            if self.db_session:
                await self._add_historical_context(event)
            
            # Enhance severity based on patterns
            await self._enhance_severity(event)
            
            # Calculate SLA impact
            await self._calculate_sla_impact(event)
            
            self.stats.total_enriched += 1
            
        except Exception as e:
            logger.error(f"Failed to enrich event: {e}", exc_info=True)
            self.stats.enrichment_failures += 1
        
        return event
    
    async def enrich_batch(self, events: List[UnifiedEvent]) -> List[UnifiedEvent]:
        """
        Enrich a batch of events.
        
        Args:
            events: List of UnifiedEvents
            
        Returns:
            List of enriched events
        """
        enriched = []
        for event in events:
            enriched.append(await self.enrich(event))
        
        logger.info(f"Enriched {len(enriched)} events")
        return enriched
    
    async def _add_ownership(self, event: UnifiedEvent):
        """Add ownership metadata to event."""
        # Try to determine service name if not present
        if not event.service_name:
            event.service_name = self._infer_service_name(event)
        
        # Get team from service
        if event.service_name and not event.team:
            team = OwnershipRegistry.get_team_for_service(event.service_name)
            if team:
                event.team = team
                self.stats.ownership_added += 1
                
                # Add team contacts to metadata
                contacts = OwnershipRegistry.get_team_contacts(team)
                if contacts:
                    if not event.metadata:
                        event.metadata = {}
                    event.metadata["team_contacts"] = contacts
    
    async def _add_infrastructure_context(self, event: UnifiedEvent):
        """Add infrastructure topology context to event."""
        # Get infrastructure context
        context = InfrastructureRegistry.get_infrastructure_context(
            event.entity_type, event.entity_name
        )
        
        if context:
            # Add to event fields
            if not event.environment and "environment" in context:
                event.environment = context["environment"]
            
            if not event.region and "region" in context:
                event.region = context["region"]
            
            # Add additional context to tags
            if not event.tags:
                event.tags = {}
            
            for key in ["cluster", "zone"]:
                if key in context:
                    event.tags[key] = context[key]
            
            self.stats.infrastructure_added += 1
    
    async def _add_historical_context(self, event: UnifiedEvent):
        """
        Add historical context by querying recent events.
        
        Args:
            event: Event to enrich
        """
        if not self.db_session:
            return
        
        try:
            # Import here to avoid circular dependencies
            from src.database.models import NormalizedEvent
            
            # Query recent events for the same entity
            lookback = datetime.now(timezone.utc) - timedelta(
                hours=settings.timeline_lookback_hours
            )
            
            stmt = (
                select(NormalizedEvent)
                .where(
                    and_(
                        NormalizedEvent.entity_id == event.entity_id,
                        NormalizedEvent.timestamp >= lookback,
                    )
                )
                .order_by(desc(NormalizedEvent.timestamp))
                .limit(10)
            )
            
            result = await self.db_session.execute(stmt)
            recent_events = result.scalars().all()
            
            if recent_events:
                # Count by severity
                severity_counts = {}
                for evt in recent_events:
                    severity_counts[evt.severity.value] = (
                        severity_counts.get(evt.severity.value, 0) + 1
                    )
                
                # Add to metadata
                if not event.metadata:
                    event.metadata = {}
                
                event.metadata["recent_events"] = {
                    "count": len(recent_events),
                    "lookback_hours": settings.timeline_lookback_hours,
                    "severity_distribution": severity_counts,
                }
                
                self.stats.historical_context_added += 1
        
        except Exception as e:
            logger.warning(f"Failed to add historical context: {e}")
    
    async def _enhance_severity(self, event: UnifiedEvent):
        """
        Enhance severity based on context and patterns.
        
        Args:
            event: Event to enhance
        """
        original_severity = event.severity
        
        # Upgrade severity for production critical services
        if (
            event.environment == "production"
            and event.service_name in ["auth-service", "payment-service"]
            and event.severity == EventSeverity.WARNING
        ):
            event.severity = EventSeverity.CRITICAL
            if not event.metadata:
                event.metadata = {}
            event.metadata["severity_enhanced"] = {
                "original": original_severity.value,
                "reason": "Critical service in production",
            }
            self.stats.severity_enhanced += 1
        
        # Upgrade severity for repeated issues
        if event.metadata and "recent_events" in event.metadata:
            recent = event.metadata["recent_events"]
            if recent.get("count", 0) >= REPEATED_ISSUE_THRESHOLD:
                if event.severity == EventSeverity.INFO:
                    event.severity = EventSeverity.WARNING
                elif event.severity == EventSeverity.WARNING:
                    event.severity = EventSeverity.CRITICAL
                
                event.metadata["severity_enhanced"] = {
                    "original": original_severity.value,
                    "reason": f"Repeated issues ({recent['count']} in {recent['lookback_hours']}h)",
                }
                self.stats.severity_enhanced += 1
    
    async def _calculate_sla_impact(self, event: UnifiedEvent):
        """
        Calculate SLA impact for the event.
        
        Args:
            event: Event to calculate impact for
        """
        impact = SLACalculator.calculate_impact(
            event.service_name,
            event.severity,
            event.event_type,
        )
        
        if impact.get("has_sla"):
            if not event.metadata:
                event.metadata = {}
            event.metadata["sla_impact"] = impact
            self.stats.sla_calculated += 1
    
    def _infer_service_name(self, event: UnifiedEvent) -> Optional[str]:
        """
        Infer service name from event data.
        
        Args:
            event: Event to analyze
            
        Returns:
            Inferred service name or None
        """
        # Check entity name
        if event.entity_type in ["service", "application"]:
            return event.entity_name
        
        # Check tags
        if event.tags:
            if "service" in event.tags:
                return event.tags["service"]
            if "app" in event.tags:
                return event.tags["app"]
        
        # Check metadata
        if event.metadata:
            if "service" in event.metadata:
                return event.metadata["service"]
        
        # Try to extract from title
        for service in OwnershipRegistry.SERVICE_TEAMS.keys():
            if service in event.title.lower():
                return service
        
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get enrichment statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_enriched": self.stats.total_enriched,
            "ownership_added": self.stats.ownership_added,
            "infrastructure_added": self.stats.infrastructure_added,
            "historical_context_added": self.stats.historical_context_added,
            "severity_enhanced": self.stats.severity_enhanced,
            "sla_calculated": self.stats.sla_calculated,
            "enrichment_failures": self.stats.enrichment_failures,
            "success_rate": (
                (self.stats.total_enriched - self.stats.enrichment_failures)
                / self.stats.total_enriched
                if self.stats.total_enriched > 0
                else 1.0
            ),
        }
    
    def reset_stats(self):
        """Reset statistics."""
        self.stats = EnrichmentStats()
