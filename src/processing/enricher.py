"""Event enrichment with additional context."""
from typing import Dict, Any, List
from datetime import datetime

from src.processing.schema import NormalizedEventSchema, EnrichedEventSchema
from src.observability import get_logger

logger = get_logger(__name__)


class EventEnricher:
    """Enrich normalized events with additional context."""

    def __init__(self) -> None:
        """Initialize enricher."""
        self.service_tags = {}  # Could be loaded from config/database
        self.asset_registry = {}  # Could be loaded from CMDB

    def enrich(self, event: NormalizedEventSchema) -> EnrichedEventSchema:
        """Enrich normalized event.
        
        Args:
            event: Normalized event
            
        Returns:
            Enriched event
        """
        tags = self._generate_tags(event)
        risk_score = self._calculate_risk_score(event)

        enriched = EnrichedEventSchema(
            normalized_event_id=event.id,
            risk_score=risk_score,
            tags=tags,
            correlations=[],
            root_cause_analysis=None,
            incident_id=None,
        )

        logger.debug(
            f"Enriched event: {event.title}",
            extra={"risk_score": risk_score, "tags": tags},
        )

        return enriched

    def _generate_tags(self, event: NormalizedEventSchema) -> List[str]:
        """Generate tags for event classification.
        
        Args:
            event: Normalized event
            
        Returns:
            List of tags
        """
        tags = []

        # Source tag
        tags.append(f"source:{event.source}")

        # Event type tag
        tags.append(f"type:{event.event_type}")

        # Severity tag
        severity_labels = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
        tags.append(f"severity:{severity_labels.get(event.severity, 'unknown')}")

        # Source-specific tags
        if event.source == "dynatrace":
            tags.extend(self._tag_dynatrace(event))
        elif event.source == "splunk":
            tags.extend(self._tag_splunk(event))
        elif event.source == "servicenow":
            tags.extend(self._tag_servicenow(event))
        elif event.source == "pagerduty":
            tags.extend(self._tag_pagerduty(event))
        elif event.source == "github":
            tags.extend(self._tag_github(event))

        # Infrastructure tags (if available in metadata)
        if "host" in event.metadata:
            tags.append(f"host:{event.metadata['host']}")
        if "service" in event.metadata:
            tags.append(f"service:{event.metadata['service']}")
        if "environment" in event.metadata:
            tags.append(f"env:{event.metadata['environment']}")

        return list(set(tags))  # Remove duplicates

    def _tag_dynatrace(self, event: NormalizedEventSchema) -> List[str]:
        """Generate Dynatrace-specific tags."""
        tags = []
        if event.event_type == "metric":
            metric_id = event.metadata.get("metric_id", "")
            if "cpu" in metric_id.lower():
                tags.append("resource:cpu")
            elif "mem" in metric_id.lower() or "memory" in metric_id.lower():
                tags.append("resource:memory")
            elif "disk" in metric_id.lower():
                tags.append("resource:disk")
            elif "net" in metric_id.lower() or "network" in metric_id.lower():
                tags.append("resource:network")
        elif event.event_type == "incident":
            tags.append("incident")
            if event.metadata.get("root_cause"):
                tags.append("has_root_cause")
        return tags

    def _tag_splunk(self, event: NormalizedEventSchema) -> List[str]:
        """Generate Splunk-specific tags."""
        tags = []
        if sourcetype := event.metadata.get("sourcetype"):
            tags.append(f"sourcetype:{sourcetype}")
        return tags

    def _tag_servicenow(self, event: NormalizedEventSchema) -> List[str]:
        """Generate ServiceNow-specific tags."""
        tags = []
        if category := event.metadata.get("category"):
            tags.append(f"category:{category}")
        if state := event.metadata.get("state"):
            tags.append(f"state:{state}")
        tags.append("incident")
        return tags

    def _tag_pagerduty(self, event: NormalizedEventSchema) -> List[str]:
        """Generate PagerDuty-specific tags."""
        tags = []
        if urgency := event.metadata.get("urgency"):
            tags.append(f"urgency:{urgency}")
        if status := event.metadata.get("status"):
            tags.append(f"status:{status}")
        tags.append("incident")
        tags.append("alert")
        return tags

    def _tag_github(self, event: NormalizedEventSchema) -> List[str]:
        """Generate GitHub-specific tags."""
        tags = []
        tags.append("devops")
        if event.event_type == "deployment":
            tags.append("deployment")
            if env := event.metadata.get("environment"):
                tags.append(f"deploy_env:{env}")
        elif event.event_type == "push":
            tags.append("code_change")
        elif event.event_type == "pr_merge":
            tags.append("code_change")
            tags.append("pr_merge")
        return tags

    def _calculate_risk_score(self, event: NormalizedEventSchema) -> float:
        """Calculate risk score for event.
        
        Risk score is 0-100 based on multiple factors.
        
        Args:
            event: Normalized event
            
        Returns:
            Risk score (0-100)
        """
        # Base score from severity
        severity_scores = {1: 10, 2: 25, 3: 50, 4: 75, 5: 95}
        base_score = severity_scores.get(event.severity, 50)

        # Adjust based on event type
        if event.event_type == "incident":
            base_score += 10
        elif event.event_type == "metric":
            base_score -= 10

        # Adjust based on source
        source_multipliers = {
            "pagerduty": 1.2,  # PagerDuty incidents are already escalated
            "servicenow": 1.1,  # ServiceNow incidents are tracked
            "dynatrace": 1.0,
            "splunk": 0.9,
            "github": 0.7,  # GitHub events are typically lower risk
        }
        multiplier = source_multipliers.get(event.source, 1.0)
        
        risk_score = min(base_score * multiplier, 100)
        
        return round(risk_score, 2)
