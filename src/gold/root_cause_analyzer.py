"""
Root cause analysis engine.
Analyzes correlated events to identify probable root causes of incidents.
"""
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
from uuid import UUID

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import NormalizedEvent, Correlation, Incident
from src.silver.unified_schema import EventType, EventSeverity
from src.gold.correlator import EventCorrelator, CorrelationMatch
from src.config.settings import settings

logger = logging.getLogger(__name__)


class RootCauseType(str, Enum):
    """Types of root causes."""
    DEPLOYMENT = "deployment"
    CONFIG_CHANGE = "config_change"
    INFRASTRUCTURE = "infrastructure"
    DEPENDENCY = "dependency"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass
class RootCauseCandidate:
    """A candidate root cause."""
    event_id: UUID
    event_type: str
    cause_type: RootCauseType
    confidence: float
    timestamp: datetime
    title: str
    description: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    supporting_events: List[UUID] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "cause_type": self.cause_type,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "supporting_events": [str(eid) for eid in self.supporting_events],
        }


@dataclass
class RootCauseAnalysis:
    """Complete root cause analysis results."""
    incident_id: Optional[UUID] = None
    primary_cause: Optional[RootCauseCandidate] = None
    alternative_causes: List[RootCauseCandidate] = field(default_factory=list)
    contributing_factors: List[RootCauseCandidate] = field(default_factory=list)
    dependency_chain: List[str] = field(default_factory=list)
    explanation: str = ""
    confidence: float = 0.0
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "primary_cause": self.primary_cause.to_dict() if self.primary_cause else None,
            "alternative_causes": [c.to_dict() for c in self.alternative_causes],
            "contributing_factors": [c.to_dict() for c in self.contributing_factors],
            "dependency_chain": self.dependency_chain,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "analyzed_at": self.analyzed_at.isoformat(),
        }


class RootCauseAnalyzer:
    """
    Analyzes correlated events to identify probable root causes.
    Uses multiple analysis strategies to determine what caused an incident.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.correlator = EventCorrelator(session)
        
        # Weights for different evidence types
        self.evidence_weights = {
            "deploy_before_incident": 0.8,
            "config_change_before_incident": 0.7,
            "resource_exhaustion": 0.6,
            "dependency_failure": 0.5,
            "temporal_proximity": 0.3,
        }
    
    async def analyze_incident(
        self,
        incident_id: UUID,
        lookback_minutes: Optional[int] = None
    ) -> RootCauseAnalysis:
        """
        Perform root cause analysis for an incident.
        
        Args:
            incident_id: Incident ID to analyze
            lookback_minutes: How far back to look for causes
        
        Returns:
            Root cause analysis results
        """
        # Fetch incident
        incident = await self._fetch_incident(incident_id)
        if not incident:
            logger.warning(f"Incident not found: {incident_id}")
            return RootCauseAnalysis()
        
        # Get correlated events
        correlations = await self._fetch_correlations_for_incident(incident_id)
        event_ids = set()
        
        for corr in correlations:
            if corr.event_ids:
                event_ids.update([UUID(eid) for eid in corr.event_ids])
        
        if not event_ids:
            logger.warning(f"No correlated events found for incident {incident_id}")
            return RootCauseAnalysis(incident_id=incident_id)
        
        # Fetch all events
        events = await self._fetch_events(list(event_ids))
        
        # Run analysis
        analysis = await self._analyze_events(
            incident,
            events,
            correlations
        )
        analysis.incident_id = incident_id
        
        logger.info(
            f"Root cause analysis for incident {incident_id}: "
            f"Primary cause confidence={analysis.confidence:.2f}"
        )
        
        return analysis
    
    async def analyze_events(
        self,
        event_ids: List[UUID],
        incident_timestamp: Optional[datetime] = None
    ) -> RootCauseAnalysis:
        """
        Analyze a list of events to find root cause.
        
        Args:
            event_ids: Events to analyze
            incident_timestamp: When incident occurred (default: now)
        
        Returns:
            Root cause analysis results
        """
        if not event_ids:
            return RootCauseAnalysis()
        
        # Fetch events
        events = await self._fetch_events(event_ids)
        if not events:
            return RootCauseAnalysis()
        
        # Get correlations
        correlations = await self.correlator.correlate_events(event_ids)
        
        # Use latest event timestamp if not provided
        if not incident_timestamp:
            incident_timestamp = max(e.timestamp for e in events)
        
        # Create pseudo-incident for analysis
        pseudo_incident = type('Incident', (), {
            'detected_at': incident_timestamp,
            'severity': EventSeverity.CRITICAL,
            'service_name': events[0].service_name if events else None,
        })()
        
        return await self._analyze_events(pseudo_incident, events, correlations)
    
    async def _analyze_events(
        self,
        incident: Any,
        events: List[NormalizedEvent],
        correlations: List[Any]
    ) -> RootCauseAnalysis:
        """
        Core analysis logic.
        """
        analysis = RootCauseAnalysis()
        candidates: List[RootCauseCandidate] = []
        
        # Sort events by timestamp
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        
        # Find events before incident
        events_before = [
            e for e in events_sorted
            if e.timestamp < incident.detected_at
        ]
        
        # Strategy 1: Deployment correlation
        deploy_candidates = self._analyze_deployments(
            events_before,
            incident.detected_at
        )
        candidates.extend(deploy_candidates)
        
        # Strategy 2: Config changes
        config_candidates = self._analyze_config_changes(
            events_before,
            incident.detected_at
        )
        candidates.extend(config_candidates)
        
        # Strategy 3: Resource exhaustion
        resource_candidates = self._analyze_resource_exhaustion(
            events_before,
            incident
        )
        candidates.extend(resource_candidates)
        
        # Strategy 4: Dependency failures
        dependency_candidates = self._analyze_dependencies(
            events_before,
            incident
        )
        candidates.extend(dependency_candidates)
        
        # Strategy 5: Causal chains from correlations
        causal_candidates = self._analyze_causal_chains(
            correlations,
            incident.detected_at
        )
        candidates.extend(causal_candidates)
        
        # Rank candidates by confidence
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        
        # Set primary cause and alternatives
        if candidates:
            analysis.primary_cause = candidates[0]
            analysis.alternative_causes = candidates[1:4]  # Top 3 alternatives
            analysis.confidence = candidates[0].confidence
            
            # Extract contributing factors (lower confidence items)
            analysis.contributing_factors = [
                c for c in candidates[4:]
                if c.confidence >= 0.3
            ]
        
        # Build dependency chain
        analysis.dependency_chain = self._build_dependency_chain(
            events_sorted,
            analysis.primary_cause
        )
        
        # Generate explanation
        analysis.explanation = self._generate_explanation(analysis, incident)
        
        return analysis
    
    def _analyze_deployments(
        self,
        events: List[NormalizedEvent],
        incident_time: datetime
    ) -> List[RootCauseCandidate]:
        """
        Analyze deployment events as potential root causes.
        Deployments shortly before incidents are highly suspicious.
        """
        candidates = []
        
        deploy_events = [e for e in events if e.event_type == EventType.DEPLOY]
        
        for deploy in deploy_events:
            time_diff = (incident_time - deploy.timestamp).total_seconds() / 60
            
            # Deployments within correlation window are candidates
            if time_diff <= settings.correlation_time_window_minutes:
                # Confidence based on temporal proximity
                confidence = max(
                    0.5,
                    self.evidence_weights["deploy_before_incident"] * (
                        1.0 - (time_diff / settings.correlation_time_window_minutes)
                    )
                )
                
                evidence = [
                    f"Deployment occurred {time_diff:.1f} minutes before incident",
                ]
                
                # Extract deployment details
                version = deploy.metadata_json.get("version", "unknown")
                service = deploy.metadata_json.get("service") or deploy.service_name
                
                if service:
                    evidence.append(f"Deployed service: {service}")
                
                if version:
                    evidence.append(f"Version: {version}")
                
                candidates.append(RootCauseCandidate(
                    event_id=deploy.id,
                    event_type=deploy.event_type,
                    cause_type=RootCauseType.DEPLOYMENT,
                    confidence=round(confidence, 2),
                    timestamp=deploy.timestamp,
                    title=deploy.title,
                    description=deploy.description,
                    evidence=evidence,
                ))
        
        return candidates
    
    def _analyze_config_changes(
        self,
        events: List[NormalizedEvent],
        incident_time: datetime
    ) -> List[RootCauseCandidate]:
        """
        Analyze configuration change events.
        """
        candidates = []
        
        change_events = [e for e in events if e.event_type == EventType.CHANGE]
        
        for change in change_events:
            time_diff = (incident_time - change.timestamp).total_seconds() / 60
            
            if time_diff <= settings.correlation_time_window_minutes:
                confidence = max(
                    0.4,
                    self.evidence_weights["config_change_before_incident"] * (
                        1.0 - (time_diff / settings.correlation_time_window_minutes)
                    )
                )
                
                evidence = [
                    f"Config change occurred {time_diff:.1f} minutes before incident",
                ]
                
                candidates.append(RootCauseCandidate(
                    event_id=change.id,
                    event_type=change.event_type,
                    cause_type=RootCauseType.CONFIG_CHANGE,
                    confidence=round(confidence, 2),
                    timestamp=change.timestamp,
                    title=change.title,
                    description=change.description,
                    evidence=evidence,
                ))
        
        return candidates
    
    def _analyze_resource_exhaustion(
        self,
        events: List[NormalizedEvent],
        incident: Any
    ) -> List[RootCauseCandidate]:
        """
        Analyze resource exhaustion (CPU, memory, disk).
        """
        candidates = []
        
        metric_events = [e for e in events if e.event_type == EventType.METRIC]
        
        # Look for critical metrics
        resource_patterns = [
            "cpu",
            "memory",
            "disk",
            "connection",
            "thread",
        ]
        
        for metric in metric_events:
            metric_name = metric.metadata_json.get("metric_name", "").lower()
            
            # Check if it's a resource metric
            is_resource_metric = any(
                pattern in metric_name
                for pattern in resource_patterns
            )
            
            if is_resource_metric and metric.severity in [
                EventSeverity.CRITICAL,
                EventSeverity.EXTREME
            ]:
                time_diff = (incident.detected_at - metric.timestamp).total_seconds() / 60
                
                if time_diff <= settings.correlation_time_window_minutes:
                    confidence = self.evidence_weights["resource_exhaustion"]
                    
                    evidence = [
                        f"Resource issue detected {time_diff:.1f} minutes before incident",
                    ]
                    
                    # Add metric details
                    current_value = metric.metadata_json.get("current_value")
                    z_score = metric.metadata_json.get("z_score")
                    
                    if current_value is not None:
                        evidence.append(f"Value: {current_value}")
                    
                    if z_score is not None:
                        evidence.append(f"Anomaly Z-score: {z_score:.2f}")
                    
                    candidates.append(RootCauseCandidate(
                        event_id=metric.id,
                        event_type=metric.event_type,
                        cause_type=RootCauseType.RESOURCE_EXHAUSTION,
                        confidence=round(confidence, 2),
                        timestamp=metric.timestamp,
                        title=metric.title,
                        description=metric.description,
                        evidence=evidence,
                    ))
        
        return candidates
    
    def _analyze_dependencies(
        self,
        events: List[NormalizedEvent],
        incident: Any
    ) -> List[RootCauseCandidate]:
        """
        Analyze dependency failures.
        """
        candidates = []
        
        # Look for incidents/alerts in other services
        for event in events:
            if event.event_type in [EventType.INCIDENT, EventType.ALERT]:
                # Check if it's a different service
                if (event.service_name and incident.service_name and
                    event.service_name != incident.service_name):
                    
                    time_diff = (incident.detected_at - event.timestamp).total_seconds() / 60
                    
                    if time_diff <= settings.correlation_time_window_minutes:
                        confidence = self.evidence_weights["dependency_failure"]
                        
                        evidence = [
                            f"Dependency failure in {event.service_name}",
                            f"Occurred {time_diff:.1f} minutes before incident",
                        ]
                        
                        candidates.append(RootCauseCandidate(
                            event_id=event.id,
                            event_type=event.event_type,
                            cause_type=RootCauseType.DEPENDENCY,
                            confidence=round(confidence, 2),
                            timestamp=event.timestamp,
                            title=event.title,
                            description=event.description,
                            evidence=evidence,
                        ))
        
        return candidates
    
    def _analyze_causal_chains(
        self,
        correlations: List[Any],
        incident_time: datetime
    ) -> List[RootCauseCandidate]:
        """
        Analyze causal chains from correlations.
        The first event in a causal chain is likely the root cause.
        """
        candidates = []
        
        for corr in correlations:
            if hasattr(corr, 'correlation_type') and corr.correlation_type == "causal":
                if corr.causal_chain and len(corr.causal_chain) >= 2:
                    # First event in chain is potential root cause
                    first_event = corr.causal_chain[0]
                    event_id = UUID(first_event["event_id"])
                    
                    # Use correlation confidence
                    confidence = corr.confidence_score if hasattr(corr, 'confidence_score') else 0.6
                    
                    evidence = [
                        f"First event in causal chain of {len(corr.causal_chain)} events",
                        f"Chain: {' → '.join([e['type'] for e in corr.causal_chain])}",
                    ]
                    
                    candidates.append(RootCauseCandidate(
                        event_id=event_id,
                        event_type=first_event["type"],
                        cause_type=self._infer_cause_type(first_event["type"]),
                        confidence=round(confidence, 2),
                        timestamp=datetime.fromisoformat(first_event["timestamp"]),
                        title=first_event["title"],
                        evidence=evidence,
                        supporting_events=[
                            UUID(e["event_id"]) for e in corr.causal_chain[1:]
                        ],
                    ))
        
        return candidates
    
    def _infer_cause_type(self, event_type: str) -> RootCauseType:
        """Infer root cause type from event type."""
        if event_type == EventType.DEPLOY:
            return RootCauseType.DEPLOYMENT
        elif event_type == EventType.CHANGE:
            return RootCauseType.CONFIG_CHANGE
        elif event_type == EventType.METRIC:
            return RootCauseType.RESOURCE_EXHAUSTION
        else:
            return RootCauseType.UNKNOWN
    
    def _build_dependency_chain(
        self,
        events: List[NormalizedEvent],
        primary_cause: Optional[RootCauseCandidate]
    ) -> List[str]:
        """
        Build dependency chain showing how the failure propagated.
        """
        if not primary_cause:
            return []
        
        chain = []
        
        # Start with primary cause service
        if primary_cause:
            # Get event details
            cause_events = [e for e in events if e.id == primary_cause.event_id]
            if cause_events:
                cause_event = cause_events[0]
                if cause_event.service_name:
                    chain.append(cause_event.service_name)
        
        # Find affected services in chronological order
        events_after_cause = sorted(
            [e for e in events if e.timestamp > primary_cause.timestamp],
            key=lambda e: e.timestamp
        )
        
        for event in events_after_cause:
            if event.service_name and event.service_name not in chain:
                chain.append(event.service_name)
        
        return chain
    
    def _generate_explanation(
        self,
        analysis: RootCauseAnalysis,
        incident: Any
    ) -> str:
        """
        Generate human-readable explanation of root cause.
        """
        if not analysis.primary_cause:
            return "Unable to determine root cause with sufficient confidence."
        
        cause = analysis.primary_cause
        time_diff = (incident.detected_at - cause.timestamp).total_seconds() / 60
        
        # Build explanation based on cause type
        explanations = {
            RootCauseType.DEPLOYMENT: (
                f"Incident likely caused by deployment '{cause.title}' "
                f"that occurred {time_diff:.1f} minutes earlier. "
            ),
            RootCauseType.CONFIG_CHANGE: (
                f"Incident likely caused by configuration change '{cause.title}' "
                f"that occurred {time_diff:.1f} minutes earlier. "
            ),
            RootCauseType.RESOURCE_EXHAUSTION: (
                f"Incident likely caused by resource exhaustion: {cause.title}. "
            ),
            RootCauseType.DEPENDENCY: (
                f"Incident likely caused by dependency failure: {cause.title}. "
            ),
            RootCauseType.UNKNOWN: (
                f"Incident may be related to event: {cause.title}. "
            ),
        }
        
        explanation = explanations.get(
            cause.cause_type,
            f"Incident may be related to: {cause.title}. "
        )
        
        # Add confidence
        explanation += f"Confidence: {cause.confidence:.0%}. "
        
        # Add dependency chain if available
        if len(analysis.dependency_chain) > 1:
            explanation += (
                f"Failure propagated through: "
                f"{' → '.join(analysis.dependency_chain)}. "
            )
        
        # Add alternative causes if confidence is not high
        if cause.confidence < 0.8 and analysis.alternative_causes:
            alt = analysis.alternative_causes[0]
            explanation += (
                f"Alternative possibility: {alt.cause_type} "
                f"({alt.confidence:.0%} confidence)."
            )
        
        return explanation
    
    async def _fetch_incident(self, incident_id: UUID) -> Optional[Incident]:
        """Fetch incident by ID."""
        result = await self.session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        return result.scalar_one_or_none()
    
    async def _fetch_correlations_for_incident(
        self,
        incident_id: UUID
    ) -> List[Correlation]:
        """Fetch correlations for incident."""
        result = await self.session.execute(
            select(Correlation).where(Correlation.incident_id == incident_id)
        )
        return list(result.scalars().all())
    
    async def _fetch_events(self, event_ids: List[UUID]) -> List[NormalizedEvent]:
        """Fetch events by IDs."""
        result = await self.session.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.id.in_(event_ids))
            .order_by(NormalizedEvent.timestamp)
        )
        return list(result.scalars().all())
