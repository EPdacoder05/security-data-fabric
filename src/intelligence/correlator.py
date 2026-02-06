"""Cross-source event correlation engine."""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from src.processing.schema import NormalizedEventSchema
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


@dataclass
class CorrelationResult:
    """Result of event correlation."""

    primary_event_id: str
    correlated_event_id: str
    correlation_type: str
    confidence: float
    time_delta_seconds: float
    metadata: Dict[str, Any]


class EventCorrelator:
    """Correlates events across different sources."""

    def __init__(self, correlation_window_minutes: Optional[int] = None) -> None:
        """Initialize correlator.

        Args:
            correlation_window_minutes: Time window for correlation (defaults to settings)
        """
        self.correlation_window_minutes = (
            correlation_window_minutes or settings.correlation_window_minutes
        )
        logger.info(
            f"Initialized correlator with {self.correlation_window_minutes}min window"
        )

    def correlate_events(
        self, events: List[NormalizedEventSchema]
    ) -> List[CorrelationResult]:
        """Correlate events across sources.

        Args:
            events: List of normalized events to correlate

        Returns:
            List of correlation results
        """
        if not events:
            return []

        correlations = []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Correlate each event with subsequent events in the time window
        for i, event in enumerate(sorted_events):
            for j in range(i + 1, len(sorted_events)):
                next_event = sorted_events[j]

                # Check if within correlation window
                time_delta = (next_event.timestamp - event.timestamp).total_seconds()
                if time_delta > self.correlation_window_minutes * 60:
                    break  # No point checking further events

                # Try different correlation patterns
                correlation = self._correlate_pair(event, next_event, time_delta)
                if correlation:
                    correlations.append(correlation)

        logger.info(
            f"Found {len(correlations)} correlations from {len(events)} events",
            extra={"event_count": len(events), "correlation_count": len(correlations)},
        )

        return correlations

    def _correlate_pair(
        self,
        event1: NormalizedEventSchema,
        event2: NormalizedEventSchema,
        time_delta_seconds: float,
    ) -> Optional[CorrelationResult]:
        """Correlate a pair of events.

        Args:
            event1: First event (earlier)
            event2: Second event (later)
            time_delta_seconds: Time difference in seconds

        Returns:
            Correlation result if correlated, None otherwise
        """
        # Deploy -> Metric Spike
        if correlation := self._correlate_deploy_to_metric(
            event1, event2, time_delta_seconds
        ):
            return correlation

        # Metric Spike -> Incident
        if correlation := self._correlate_metric_to_incident(
            event1, event2, time_delta_seconds
        ):
            return correlation

        # Config Change -> Service Degradation
        if correlation := self._correlate_config_to_degradation(
            event1, event2, time_delta_seconds
        ):
            return correlation

        # Deployment -> Incident (direct)
        if correlation := self._correlate_deploy_to_incident(
            event1, event2, time_delta_seconds
        ):
            return correlation

        return None

    def _correlate_deploy_to_metric(
        self,
        event1: NormalizedEventSchema,
        event2: NormalizedEventSchema,
        time_delta_seconds: float,
    ) -> Optional[CorrelationResult]:
        """Correlate deployment to metric spike.

        Args:
            event1: Potential deployment event
            event2: Potential metric event
            time_delta_seconds: Time difference

        Returns:
            Correlation if found
        """
        # Check if event1 is deployment and event2 is metric spike
        if event1.event_type != "deployment" or event2.event_type != "metric":
            return None

        # Check for same service
        service1 = event1.metadata.get("service") or event1.metadata.get("repository")
        service2 = event2.metadata.get("service") or event2.metadata.get("entity_id")

        if not service1 or not service2:
            return None

        # Simple matching: check if service names match or one contains the other
        if not self._services_match(service1, service2):
            return None

        # Check if metric shows anomaly/spike
        z_score = event2.metadata.get("z_score", 0)
        if abs(z_score) < 2.0:  # Only consider significant anomalies
            return None

        # Calculate confidence based on time proximity and severity
        confidence = self._calculate_correlation_confidence(
            time_delta_seconds=time_delta_seconds,
            max_time_delta=self.correlation_window_minutes * 60,
            severity1=event1.severity,
            severity2=event2.severity,
            additional_factors={"z_score": abs(z_score)},
        )

        return CorrelationResult(
            primary_event_id=str(event1.id),
            correlated_event_id=str(event2.id),
            correlation_type="deploy_to_metric",
            confidence=confidence,
            time_delta_seconds=time_delta_seconds,
            metadata={
                "service": service1,
                "deployment": event1.metadata.get("version"),
                "metric": event2.metadata.get("metric_id"),
                "z_score": z_score,
            },
        )

    def _correlate_metric_to_incident(
        self,
        event1: NormalizedEventSchema,
        event2: NormalizedEventSchema,
        time_delta_seconds: float,
    ) -> Optional[CorrelationResult]:
        """Correlate metric spike to incident.

        Args:
            event1: Potential metric event
            event2: Potential incident event
            time_delta_seconds: Time difference

        Returns:
            Correlation if found
        """
        # Check if event1 is metric and event2 is incident
        if event1.event_type != "metric" or event2.event_type != "incident":
            return None

        # Check for same service/entity
        entity1 = event1.metadata.get("service") or event1.metadata.get("entity_id")
        entity2 = event2.metadata.get("service") or event2.metadata.get("affected_entity")

        if not entity1 or not entity2:
            return None

        if not self._services_match(entity1, entity2):
            return None

        # Check if metric shows significant anomaly
        z_score = event1.metadata.get("z_score", 0)
        if abs(z_score) < 2.5:  # Higher threshold for incident correlation
            return None

        # Calculate confidence
        confidence = self._calculate_correlation_confidence(
            time_delta_seconds=time_delta_seconds,
            max_time_delta=self.correlation_window_minutes * 60,
            severity1=event1.severity,
            severity2=event2.severity,
            additional_factors={"z_score": abs(z_score), "incident_correlation": True},
        )

        return CorrelationResult(
            primary_event_id=str(event1.id),
            correlated_event_id=str(event2.id),
            correlation_type="metric_to_incident",
            confidence=confidence,
            time_delta_seconds=time_delta_seconds,
            metadata={
                "entity": entity1,
                "metric": event1.metadata.get("metric_id"),
                "z_score": z_score,
                "incident_source": event2.source,
            },
        )

    def _correlate_config_to_degradation(
        self,
        event1: NormalizedEventSchema,
        event2: NormalizedEventSchema,
        time_delta_seconds: float,
    ) -> Optional[CorrelationResult]:
        """Correlate config change to service degradation.

        Args:
            event1: Potential config change event
            event2: Potential degradation event
            time_delta_seconds: Time difference

        Returns:
            Correlation if found
        """
        # Check if event1 is config change
        config_types = ["config_change", "push", "pr_merge"]
        if event1.event_type not in config_types:
            return None

        # Check if event2 is degradation indicator
        degradation_types = ["metric", "incident", "alert"]
        if event2.event_type not in degradation_types:
            return None

        # For metrics, check if showing degradation
        if event2.event_type == "metric":
            z_score = event2.metadata.get("z_score", 0)
            if z_score < 2.0:  # Only negative spikes indicate degradation
                return None

        # Check for service/repository match
        service1 = event1.metadata.get("service") or event1.metadata.get("repository")
        service2 = event2.metadata.get("service") or event2.metadata.get("entity_id")

        if service1 and service2 and not self._services_match(service1, service2):
            return None

        # Calculate confidence
        confidence = self._calculate_correlation_confidence(
            time_delta_seconds=time_delta_seconds,
            max_time_delta=self.correlation_window_minutes * 60,
            severity1=event1.severity,
            severity2=event2.severity,
            additional_factors={"config_change": True},
        )

        return CorrelationResult(
            primary_event_id=str(event1.id),
            correlated_event_id=str(event2.id),
            correlation_type="config_to_degradation",
            confidence=confidence,
            time_delta_seconds=time_delta_seconds,
            metadata={
                "change_type": event1.event_type,
                "degradation_type": event2.event_type,
                "service": service1 or service2,
            },
        )

    def _correlate_deploy_to_incident(
        self,
        event1: NormalizedEventSchema,
        event2: NormalizedEventSchema,
        time_delta_seconds: float,
    ) -> Optional[CorrelationResult]:
        """Correlate deployment directly to incident.

        Args:
            event1: Potential deployment event
            event2: Potential incident event
            time_delta_seconds: Time difference

        Returns:
            Correlation if found
        """
        if event1.event_type != "deployment" or event2.event_type != "incident":
            return None

        # Check for service match
        service1 = event1.metadata.get("service") or event1.metadata.get("repository")
        service2 = event2.metadata.get("service") or event2.metadata.get("affected_entity")

        if service1 and service2 and not self._services_match(service1, service2):
            return None

        # Calculate confidence
        confidence = self._calculate_correlation_confidence(
            time_delta_seconds=time_delta_seconds,
            max_time_delta=self.correlation_window_minutes * 60,
            severity1=event1.severity,
            severity2=event2.severity,
            additional_factors={"direct_incident": True},
        )

        return CorrelationResult(
            primary_event_id=str(event1.id),
            correlated_event_id=str(event2.id),
            correlation_type="deploy_to_incident",
            confidence=confidence,
            time_delta_seconds=time_delta_seconds,
            metadata={
                "service": service1 or service2,
                "deployment": event1.metadata.get("version"),
                "incident_source": event2.source,
            },
        )

    def _services_match(self, service1: str, service2: str) -> bool:
        """Check if two service names match.

        Args:
            service1: First service name
            service2: Second service name

        Returns:
            True if services match
        """
        s1 = service1.lower().replace("-", "_").replace(" ", "_")
        s2 = service2.lower().replace("-", "_").replace(" ", "_")

        # Exact match
        if s1 == s2:
            return True

        # One contains the other
        if s1 in s2 or s2 in s1:
            return True

        return False

    def _calculate_correlation_confidence(
        self,
        time_delta_seconds: float,
        max_time_delta: float,
        severity1: int,
        severity2: int,
        additional_factors: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Calculate correlation confidence score.

        Args:
            time_delta_seconds: Time difference between events
            max_time_delta: Maximum time delta for correlation
            severity1: Severity of first event
            severity2: Severity of second event
            additional_factors: Additional factors to consider

        Returns:
            Confidence score (0-1)
        """
        # Time proximity factor (closer = higher confidence)
        time_factor = 1.0 - (time_delta_seconds / max_time_delta)
        time_factor = max(0.3, time_factor)  # Minimum 0.3

        # Severity factor (higher severity = higher confidence)
        severity_factor = (severity1 + severity2) / 10.0  # Max 1.0

        # Base confidence
        confidence = (time_factor * 0.6) + (severity_factor * 0.4)

        # Apply additional factors
        if additional_factors:
            if z_score := additional_factors.get("z_score"):
                # Higher z-score increases confidence
                z_bonus = min(z_score / 10.0, 0.2)  # Max 0.2 bonus
                confidence = min(confidence + z_bonus, 1.0)

            if additional_factors.get("incident_correlation"):
                # Incident correlations get slight boost
                confidence = min(confidence * 1.1, 1.0)

            if additional_factors.get("direct_incident"):
                # Direct incident correlations get boost
                confidence = min(confidence * 1.15, 1.0)

        return round(confidence, 3)
