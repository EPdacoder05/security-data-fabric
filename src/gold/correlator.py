"""
Cross-source event correlation engine.
Correlates events across different sources using:
- Time-based correlation (events within N minutes)
- Entity-based correlation (same service/host)
- Causal correlation (deploy → metric spike → incident)
"""
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import NormalizedEvent, Correlation
from src.silver.unified_schema import EventType
from src.config.settings import settings

logger = logging.getLogger(__name__)


class CorrelationType(str, Enum):
    """Types of correlations."""
    TIME_BASED = "time_based"
    ENTITY_BASED = "entity_based"
    CAUSAL = "causal"
    SERVICE_BASED = "service_based"


@dataclass
class CorrelationMatch:
    """A single correlation match."""
    event_ids: List[UUID]
    correlation_type: CorrelationType
    confidence: float
    time_window_seconds: Optional[int] = None
    entity_id: Optional[str] = None
    service_name: Optional[str] = None
    summary: Optional[str] = None
    causal_chain: Optional[List[Dict[str, Any]]] = None


@dataclass
class CorrelationGraph:
    """Graph representation of correlated events."""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    clusters: List[List[UUID]] = field(default_factory=list)


@dataclass
class CorrelationStats:
    """Statistics for correlation operations."""
    total_events_analyzed: int = 0
    correlations_found: int = 0
    time_based: int = 0
    entity_based: int = 0
    causal: int = 0
    service_based: int = 0
    avg_confidence: float = 0.0


class EventCorrelator:
    """
    Cross-source event correlation engine.
    Identifies relationships between events from different sources.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.time_window = timedelta(minutes=settings.correlation_time_window_minutes)
        
        # Causal patterns: type A → type B (within time window)
        self.causal_patterns = [
            (EventType.DEPLOY, EventType.METRIC),
            (EventType.DEPLOY, EventType.INCIDENT),
            (EventType.METRIC, EventType.INCIDENT),
            (EventType.CHANGE, EventType.METRIC),
            (EventType.CHANGE, EventType.INCIDENT),
        ]
    
    async def correlate_events(
        self,
        event_ids: List[UUID],
        correlation_types: Optional[List[CorrelationType]] = None
    ) -> List[CorrelationMatch]:
        """
        Find correlations for a list of events.
        
        Args:
            event_ids: Event IDs to correlate
            correlation_types: Types of correlations to find (default: all)
        
        Returns:
            List of correlation matches
        """
        if not event_ids:
            return []
        
        if correlation_types is None:
            correlation_types = list(CorrelationType)
        
        # Fetch events from database
        events = await self._fetch_events(event_ids)
        if not events:
            logger.warning(f"No events found for IDs: {event_ids}")
            return []
        
        correlations = []
        
        # Run different correlation strategies
        if CorrelationType.TIME_BASED in correlation_types:
            time_corr = await self._find_time_based_correlations(events)
            correlations.extend(time_corr)
        
        if CorrelationType.ENTITY_BASED in correlation_types:
            entity_corr = await self._find_entity_based_correlations(events)
            correlations.extend(entity_corr)
        
        if CorrelationType.SERVICE_BASED in correlation_types:
            service_corr = await self._find_service_based_correlations(events)
            correlations.extend(service_corr)
        
        if CorrelationType.CAUSAL in correlation_types:
            causal_corr = await self._find_causal_correlations(events)
            correlations.extend(causal_corr)
        
        # Deduplicate and sort by confidence
        correlations = self._deduplicate_correlations(correlations)
        correlations.sort(key=lambda x: x.confidence, reverse=True)
        
        logger.info(f"Found {len(correlations)} correlations for {len(events)} events")
        return correlations
    
    async def correlate_around_event(
        self,
        event_id: UUID,
        lookback_minutes: Optional[int] = None,
        lookahead_minutes: Optional[int] = None
    ) -> List[CorrelationMatch]:
        """
        Find all events correlated with a specific event in a time window.
        
        Args:
            event_id: Central event ID
            lookback_minutes: Minutes to look back (default: correlation window)
            lookahead_minutes: Minutes to look ahead (default: correlation window)
        
        Returns:
            List of correlation matches
        """
        # Fetch central event
        central_event = await self._fetch_event(event_id)
        if not central_event:
            logger.warning(f"Event not found: {event_id}")
            return []
        
        lookback = timedelta(minutes=lookback_minutes or settings.correlation_time_window_minutes)
        lookahead = timedelta(minutes=lookahead_minutes or settings.correlation_time_window_minutes)
        
        # Find events in time window
        start_time = central_event.timestamp - lookback
        end_time = central_event.timestamp + lookahead
        
        nearby_events = await self._fetch_events_in_timerange(start_time, end_time)
        all_events = [central_event] + [e for e in nearby_events if e.id != event_id]
        
        # Correlate all events
        return await self.correlate_events([e.id for e in all_events])
    
    async def build_correlation_graph(
        self,
        correlations: List[CorrelationMatch]
    ) -> CorrelationGraph:
        """
        Build a graph representation of correlated events.
        
        Args:
            correlations: List of correlation matches
        
        Returns:
            Correlation graph with nodes and edges
        """
        graph = CorrelationGraph()
        event_ids = set()
        
        # Collect all event IDs
        for corr in correlations:
            event_ids.update(corr.event_ids)
        
        # Fetch event details for nodes
        events = await self._fetch_events(list(event_ids))
        event_map = {str(e.id): e for e in events}
        
        # Build nodes
        for event in events:
            graph.nodes.append({
                "id": str(event.id),
                "type": event.event_type,
                "source": event.source,
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity,
                "title": event.title,
                "entity_id": event.entity_id,
                "service_name": event.service_name,
            })
        
        # Build edges
        for corr in correlations:
            if len(corr.event_ids) >= 2:
                for i in range(len(corr.event_ids) - 1):
                    graph.edges.append({
                        "source": str(corr.event_ids[i]),
                        "target": str(corr.event_ids[i + 1]),
                        "type": corr.correlation_type,
                        "confidence": corr.confidence,
                    })
        
        # Find connected components (clusters)
        graph.clusters = self._find_clusters(correlations)
        
        logger.info(
            f"Built correlation graph: {len(graph.nodes)} nodes, "
            f"{len(graph.edges)} edges, {len(graph.clusters)} clusters"
        )
        return graph
    
    async def save_correlation(
        self,
        match: CorrelationMatch,
        incident_id: Optional[UUID] = None
    ) -> Correlation:
        """
        Save a correlation to the database.
        
        Args:
            match: Correlation match to save
            incident_id: Optional incident ID
        
        Returns:
            Saved correlation model
        """
        correlation = Correlation(
            incident_id=incident_id,
            event_ids=[str(eid) for eid in match.event_ids],
            correlation_type=match.correlation_type,
            confidence_score=match.confidence,
            time_window_seconds=match.time_window_seconds,
            summary=match.summary,
            causal_chain=match.causal_chain,
        )
        
        self.session.add(correlation)
        await self.session.flush()
        
        logger.debug(f"Saved correlation {correlation.id} with {len(match.event_ids)} events")
        return correlation
    
    async def _fetch_event(self, event_id: UUID) -> Optional[NormalizedEvent]:
        """Fetch a single event by ID."""
        result = await self.session.execute(
            select(NormalizedEvent).where(NormalizedEvent.id == event_id)
        )
        return result.scalar_one_or_none()
    
    async def _fetch_events(self, event_ids: List[UUID]) -> List[NormalizedEvent]:
        """Fetch multiple events by ID."""
        result = await self.session.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.id.in_(event_ids))
            .order_by(NormalizedEvent.timestamp)
        )
        return list(result.scalars().all())
    
    async def _fetch_events_in_timerange(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[NormalizedEvent]:
        """Fetch events within a time range."""
        result = await self.session.execute(
            select(NormalizedEvent)
            .where(
                and_(
                    NormalizedEvent.timestamp >= start_time,
                    NormalizedEvent.timestamp <= end_time
                )
            )
            .order_by(NormalizedEvent.timestamp)
            .limit(1000)  # Safety limit
        )
        return list(result.scalars().all())
    
    async def _find_time_based_correlations(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationMatch]:
        """
        Find events that occur close together in time.
        """
        correlations = []
        
        for i, event1 in enumerate(events):
            correlated_ids = [event1.id]
            
            for event2 in events[i + 1:]:
                time_diff = abs((event2.timestamp - event1.timestamp).total_seconds())
                
                if time_diff <= self.time_window.total_seconds():
                    correlated_ids.append(event2.id)
            
            if len(correlated_ids) >= 2:
                # Confidence based on temporal proximity
                avg_time_diff = self._calculate_avg_time_diff(
                    [e for e in events if e.id in correlated_ids]
                )
                confidence = max(0.3, 1.0 - (avg_time_diff / self.time_window.total_seconds()))
                
                correlations.append(CorrelationMatch(
                    event_ids=correlated_ids,
                    correlation_type=CorrelationType.TIME_BASED,
                    confidence=round(confidence, 2),
                    time_window_seconds=int(self.time_window.total_seconds()),
                    summary=f"{len(correlated_ids)} events within {settings.correlation_time_window_minutes} minutes"
                ))
        
        return correlations
    
    async def _find_entity_based_correlations(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationMatch]:
        """
        Find events affecting the same entity (host, service, pod).
        """
        correlations = []
        entity_groups: Dict[str, List[NormalizedEvent]] = {}
        
        # Group by entity_id
        for event in events:
            if event.entity_id:
                if event.entity_id not in entity_groups:
                    entity_groups[event.entity_id] = []
                entity_groups[event.entity_id].append(event)
        
        # Create correlations for each entity
        for entity_id, entity_events in entity_groups.items():
            if len(entity_events) >= 2:
                # Higher confidence if events are from different sources
                sources = set(e.source for e in entity_events)
                confidence = min(0.9, 0.5 + (len(sources) * 0.1))
                
                correlations.append(CorrelationMatch(
                    event_ids=[e.id for e in entity_events],
                    correlation_type=CorrelationType.ENTITY_BASED,
                    confidence=round(confidence, 2),
                    entity_id=entity_id,
                    summary=f"{len(entity_events)} events on entity {entity_id} from {len(sources)} sources"
                ))
        
        return correlations
    
    async def _find_service_based_correlations(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationMatch]:
        """
        Find events affecting the same service.
        """
        correlations = []
        service_groups: Dict[str, List[NormalizedEvent]] = {}
        
        # Group by service_name
        for event in events:
            if event.service_name:
                if event.service_name not in service_groups:
                    service_groups[event.service_name] = []
                service_groups[event.service_name].append(event)
        
        # Create correlations for each service
        for service_name, service_events in service_groups.items():
            if len(service_events) >= 2:
                # Higher confidence if events span time window
                time_span = (
                    max(e.timestamp for e in service_events) -
                    min(e.timestamp for e in service_events)
                ).total_seconds()
                
                if time_span <= self.time_window.total_seconds():
                    confidence = 0.7
                else:
                    confidence = 0.5
                
                correlations.append(CorrelationMatch(
                    event_ids=[e.id for e in service_events],
                    correlation_type=CorrelationType.SERVICE_BASED,
                    confidence=round(confidence, 2),
                    service_name=service_name,
                    summary=f"{len(service_events)} events affecting {service_name}"
                ))
        
        return correlations
    
    async def _find_causal_correlations(
        self,
        events: List[NormalizedEvent]
    ) -> List[CorrelationMatch]:
        """
        Find causal relationships (e.g., deploy → metric spike → incident).
        """
        correlations = []
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        
        # Look for causal patterns
        for cause_type, effect_type in self.causal_patterns:
            cause_events = [e for e in events_sorted if e.event_type == cause_type]
            effect_events = [e for e in events_sorted if e.event_type == effect_type]
            
            for cause in cause_events:
                causal_chain = [cause]
                
                for effect in effect_events:
                    # Effect must come after cause, within time window
                    time_diff = (effect.timestamp - cause.timestamp).total_seconds()
                    
                    if 0 < time_diff <= self.time_window.total_seconds():
                        # Check if they share entity or service
                        entity_match = (
                            cause.entity_id and effect.entity_id and
                            cause.entity_id == effect.entity_id
                        )
                        service_match = (
                            cause.service_name and effect.service_name and
                            cause.service_name == effect.service_name
                        )
                        
                        if entity_match or service_match:
                            causal_chain.append(effect)
                
                if len(causal_chain) >= 2:
                    # Confidence based on chain length and time proximity
                    confidence = min(0.95, 0.6 + (len(causal_chain) * 0.1))
                    
                    chain_description = [
                        {
                            "event_id": str(e.id),
                            "type": e.event_type,
                            "timestamp": e.timestamp.isoformat(),
                            "title": e.title,
                        }
                        for e in causal_chain
                    ]
                    
                    correlations.append(CorrelationMatch(
                        event_ids=[e.id for e in causal_chain],
                        correlation_type=CorrelationType.CAUSAL,
                        confidence=round(confidence, 2),
                        time_window_seconds=int(self.time_window.total_seconds()),
                        causal_chain=chain_description,
                        summary=f"Causal chain: {cause_type} → {effect_type}"
                    ))
        
        return correlations
    
    def _calculate_avg_time_diff(self, events: List[NormalizedEvent]) -> float:
        """Calculate average time difference between consecutive events."""
        if len(events) < 2:
            return 0.0
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        diffs = [
            (sorted_events[i + 1].timestamp - sorted_events[i].timestamp).total_seconds()
            for i in range(len(sorted_events) - 1)
        ]
        
        return sum(diffs) / len(diffs) if diffs else 0.0
    
    def _deduplicate_correlations(
        self,
        correlations: List[CorrelationMatch]
    ) -> List[CorrelationMatch]:
        """Remove duplicate correlations with same event sets."""
        seen_sets: Set[frozenset] = set()
        unique_correlations = []
        
        for corr in correlations:
            event_set = frozenset(corr.event_ids)
            if event_set not in seen_sets:
                seen_sets.add(event_set)
                unique_correlations.append(corr)
        
        return unique_correlations
    
    def _find_clusters(
        self,
        correlations: List[CorrelationMatch]
    ) -> List[List[UUID]]:
        """
        Find connected components (clusters) in correlation graph.
        Uses Union-Find algorithm.
        """
        # Build parent map for Union-Find
        parent: Dict[UUID, UUID] = {}
        
        def find(x: UUID) -> UUID:
            if x not in parent:
                parent[x] = x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x: UUID, y: UUID):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Union all events in each correlation
        for corr in correlations:
            if len(corr.event_ids) >= 2:
                for i in range(len(corr.event_ids) - 1):
                    union(corr.event_ids[i], corr.event_ids[i + 1])
        
        # Group by root parent
        clusters_map: Dict[UUID, List[UUID]] = {}
        for event_id in parent.keys():
            root = find(event_id)
            if root not in clusters_map:
                clusters_map[root] = []
            clusters_map[root].append(event_id)
        
        return list(clusters_map.values())


async def calculate_correlation_stats(
    correlations: List[CorrelationMatch],
    total_events: int
) -> CorrelationStats:
    """
    Calculate statistics for correlation operations.
    
    Args:
        correlations: List of correlation matches
        total_events: Total events analyzed
    
    Returns:
        Correlation statistics
    """
    stats = CorrelationStats(total_events_analyzed=total_events)
    
    if not correlations:
        return stats
    
    stats.correlations_found = len(correlations)
    
    # Count by type
    type_counts = {
        CorrelationType.TIME_BASED: 0,
        CorrelationType.ENTITY_BASED: 0,
        CorrelationType.CAUSAL: 0,
        CorrelationType.SERVICE_BASED: 0,
    }
    
    total_confidence = 0.0
    for corr in correlations:
        type_counts[corr.correlation_type] += 1
        total_confidence += corr.confidence
    
    stats.time_based = type_counts[CorrelationType.TIME_BASED]
    stats.entity_based = type_counts[CorrelationType.ENTITY_BASED]
    stats.causal = type_counts[CorrelationType.CAUSAL]
    stats.service_based = type_counts[CorrelationType.SERVICE_BASED]
    stats.avg_confidence = round(total_confidence / len(correlations), 2)
    
    return stats
