"""
Incident timeline reconstruction.
Builds chronological timelines from correlated events across multiple sources.
"""
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import NormalizedEvent, Correlation, Incident
from src.silver.unified_schema import EventType, EventSeverity
from src.config.settings import settings

logger = logging.getLogger(__name__)


class TimelineFormat(str, Enum):
    """Timeline output formats."""
    TEXT = "text"
    JSON = "json"
    HTML = "html"


@dataclass
class TimelineEntry:
    """Single entry in a timeline."""
    timestamp: datetime
    event_id: UUID
    event_type: str
    source: str
    severity: str
    title: str
    description: Optional[str] = None
    entity_id: Optional[str] = None
    entity_name: Optional[str] = None
    service_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "service_name": self.service_name,
            "metadata": self.metadata,
        }


@dataclass
class TimelineGap:
    """Represents a gap in timeline data."""
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    missing_sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "duration_human": self._format_duration(),
            "missing_sources": self.missing_sources,
        }
    
    def _format_duration(self) -> str:
        """Format duration in human-readable form."""
        minutes = int(self.duration_seconds / 60)
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        remaining_minutes = minutes % 60
        return f"{hours}h {remaining_minutes}m"


@dataclass
class Timeline:
    """Complete incident timeline."""
    incident_id: Optional[UUID] = None
    start_time: datetime = None
    end_time: datetime = None
    entries: List[TimelineEntry] = field(default_factory=list)
    gaps: List[TimelineGap] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    total_events: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (
                (self.end_time - self.start_time).total_seconds()
                if self.start_time and self.end_time else 0
            ),
            "total_events": self.total_events,
            "sources": self.sources,
            "entries": [e.to_dict() for e in self.entries],
            "gaps": [g.to_dict() for g in self.gaps],
        }


class TimelineBuilder:
    """
    Builds chronological timelines from correlated events.
    Supports multiple event sources, gap detection, and various output formats.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.lookback_hours = settings.timeline_lookback_hours
    
    async def build_timeline_for_incident(
        self,
        incident_id: UUID,
        include_predictions: bool = True
    ) -> Timeline:
        """
        Build timeline for a specific incident.
        
        Args:
            incident_id: Incident ID
            include_predictions: Include ML predictions in timeline
        
        Returns:
            Complete timeline
        """
        # Fetch incident
        incident = await self._fetch_incident(incident_id)
        if not incident:
            logger.warning(f"Incident not found: {incident_id}")
            return Timeline()
        
        # Fetch correlated events
        correlations = await self._fetch_correlations_for_incident(incident_id)
        event_ids = set()
        
        for corr in correlations:
            if corr.event_ids:
                event_ids.update([UUID(eid) for eid in corr.event_ids])
        
        # Build timeline from events
        timeline = await self.build_timeline_from_events(list(event_ids))
        timeline.incident_id = incident_id
        
        # Add incident markers
        timeline = self._add_incident_markers(timeline, incident)
        
        logger.info(
            f"Built timeline for incident {incident_id}: "
            f"{len(timeline.entries)} entries from {len(timeline.sources)} sources"
        )
        
        return timeline
    
    async def build_timeline_from_events(
        self,
        event_ids: List[UUID]
    ) -> Timeline:
        """
        Build timeline from a list of event IDs.
        
        Args:
            event_ids: Event IDs to include
        
        Returns:
            Complete timeline
        """
        if not event_ids:
            return Timeline()
        
        # Fetch events
        events = await self._fetch_events(event_ids)
        if not events:
            logger.warning("No events found for timeline")
            return Timeline()
        
        # Build timeline entries
        entries = []
        sources = set()
        
        for event in events:
            entry = TimelineEntry(
                timestamp=event.timestamp,
                event_id=event.id,
                event_type=event.event_type,
                source=event.source,
                severity=event.severity.value if hasattr(event.severity, 'value') else event.severity,
                title=event.title,
                description=event.description,
                entity_id=event.entity_id,
                entity_name=event.entity_name,
                service_name=event.service_name,
                metadata=self._extract_event_metadata(event),
            )
            entries.append(entry)
            sources.add(event.source)
        
        # Sort by timestamp
        entries.sort(key=lambda e: e.timestamp)
        
        # Create timeline
        timeline = Timeline(
            start_time=entries[0].timestamp if entries else None,
            end_time=entries[-1].timestamp if entries else None,
            entries=entries,
            sources=sorted(list(sources)),
            total_events=len(entries),
        )
        
        # Detect gaps
        timeline.gaps = self._detect_gaps(entries)
        
        return timeline
    
    async def build_timeline_around_time(
        self,
        center_time: datetime,
        lookback_minutes: Optional[int] = None,
        lookahead_minutes: Optional[int] = None,
        service_name: Optional[str] = None,
        entity_id: Optional[str] = None
    ) -> Timeline:
        """
        Build timeline centered around a specific time.
        
        Args:
            center_time: Central timestamp
            lookback_minutes: Minutes before center
            lookahead_minutes: Minutes after center
            service_name: Filter by service name
            entity_id: Filter by entity ID
        
        Returns:
            Complete timeline
        """
        lookback = timedelta(minutes=lookback_minutes or 30)
        lookahead = timedelta(minutes=lookahead_minutes or 30)
        
        start_time = center_time - lookback
        end_time = center_time + lookahead
        
        # Fetch events in time window
        events = await self._fetch_events_in_timerange(
            start_time,
            end_time,
            service_name=service_name,
            entity_id=entity_id
        )
        
        return await self.build_timeline_from_events([e.id for e in events])
    
    def format_timeline(
        self,
        timeline: Timeline,
        format: TimelineFormat = TimelineFormat.TEXT,
        include_metadata: bool = False
    ) -> str:
        """
        Format timeline for output.
        
        Args:
            timeline: Timeline to format
            format: Output format
            include_metadata: Include detailed metadata
        
        Returns:
            Formatted timeline string
        """
        if format == TimelineFormat.TEXT:
            return self._format_text(timeline, include_metadata)
        elif format == TimelineFormat.JSON:
            import json
            return json.dumps(timeline.to_dict(), indent=2)
        elif format == TimelineFormat.HTML:
            return self._format_html(timeline, include_metadata)
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def _format_text(self, timeline: Timeline, include_metadata: bool) -> str:
        """
        Format timeline as text.
        Example:
        14:00 - Deploy auth-service v2.4.1 (GitHub)
        14:05 - CPU spike 45%→89% Z=4.92 (Dynatrace)
        14:08 - INC0012345 created (ServiceNow)
        """
        lines = []
        
        # Header
        if timeline.start_time and timeline.end_time:
            duration = (timeline.end_time - timeline.start_time).total_seconds() / 60
            lines.append(f"Timeline: {len(timeline.entries)} events over {duration:.0f} minutes")
            lines.append(f"Sources: {', '.join(timeline.sources)}")
            lines.append("")
        
        # Entries
        for entry in timeline.entries:
            time_str = entry.timestamp.strftime("%H:%M:%S")
            severity_marker = self._severity_to_marker(entry.severity)
            
            # Build entry line
            parts = [time_str, severity_marker]
            
            # Add title with metadata
            title_parts = [entry.title]
            
            # Add specific metadata based on event type
            if entry.event_type == EventType.DEPLOY:
                if entry.metadata.get("version"):
                    title_parts.append(f"v{entry.metadata['version']}")
            elif entry.event_type == EventType.METRIC:
                if entry.metadata.get("z_score"):
                    title_parts.append(f"Z={entry.metadata['z_score']:.2f}")
            elif entry.event_type == EventType.INCIDENT:
                if entry.metadata.get("incident_id"):
                    title_parts.append(entry.metadata["incident_id"])
            
            parts.append(" ".join(title_parts))
            parts.append(f"({entry.source})")
            
            lines.append(" ".join(parts))
            
            # Add description if requested
            if include_metadata and entry.description:
                lines.append(f"  └─ {entry.description}")
        
        # Gaps
        if timeline.gaps:
            lines.append("")
            lines.append(f"Detected {len(timeline.gaps)} data gap(s):")
            for gap in timeline.gaps:
                lines.append(
                    f"  • {gap.start_time.strftime('%H:%M:%S')} - "
                    f"{gap.end_time.strftime('%H:%M:%S')} "
                    f"({gap._format_duration()})"
                )
        
        return "\n".join(lines)
    
    def _format_html(self, timeline: Timeline, include_metadata: bool) -> str:
        """Format timeline as HTML."""
        lines = ['<div class="timeline">']
        
        # Header
        lines.append('<div class="timeline-header">')
        lines.append(f'<h3>Timeline: {len(timeline.entries)} events</h3>')
        if timeline.start_time and timeline.end_time:
            lines.append(
                f'<p>Duration: {(timeline.end_time - timeline.start_time).total_seconds() / 60:.0f} minutes</p>'
            )
        lines.append(f'<p>Sources: {", ".join(timeline.sources)}</p>')
        lines.append('</div>')
        
        # Entries
        lines.append('<ul class="timeline-entries">')
        for entry in timeline.entries:
            severity_class = f"severity-{entry.severity}"
            time_str = entry.timestamp.strftime("%H:%M:%S")
            
            lines.append(f'<li class="{severity_class}">')
            lines.append(f'<span class="time">{time_str}</span>')
            lines.append(f'<span class="title">{entry.title}</span>')
            lines.append(f'<span class="source">({entry.source})</span>')
            
            if include_metadata and entry.description:
                lines.append(f'<p class="description">{entry.description}</p>')
            
            lines.append('</li>')
        
        lines.append('</ul>')
        lines.append('</div>')
        
        return "\n".join(lines)
    
    def _severity_to_marker(self, severity: str) -> str:
        """Convert severity to visual marker."""
        severity_lower = severity.lower()
        markers = {
            "info": "ℹ️",
            "warning": "⚠️",
            "critical": "🔴",
            "extreme": "💥",
        }
        return markers.get(severity_lower, "•")
    
    def _detect_gaps(
        self,
        entries: List[TimelineEntry],
        gap_threshold_minutes: int = 5
    ) -> List[TimelineGap]:
        """
        Detect gaps in timeline data.
        A gap is a period with no events exceeding threshold.
        """
        if len(entries) < 2:
            return []
        
        gaps = []
        gap_threshold = timedelta(minutes=gap_threshold_minutes)
        
        for i in range(len(entries) - 1):
            current = entries[i]
            next_entry = entries[i + 1]
            
            time_diff = next_entry.timestamp - current.timestamp
            
            if time_diff > gap_threshold:
                gaps.append(TimelineGap(
                    start_time=current.timestamp,
                    end_time=next_entry.timestamp,
                    duration_seconds=time_diff.total_seconds(),
                ))
        
        return gaps
    
    def _add_incident_markers(
        self,
        timeline: Timeline,
        incident: Incident
    ) -> Timeline:
        """Add incident lifecycle markers to timeline."""
        markers = []
        
        # Incident created
        if incident.detected_at:
            markers.append(TimelineEntry(
                timestamp=incident.detected_at,
                event_id=incident.id,
                event_type="incident_lifecycle",
                source="incident",
                severity=incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
                title=f"Incident {incident.incident_number} created",
                description=incident.title,
                service_name=incident.service_name,
                metadata={"state": "created"},
            ))
        
        # Incident acknowledged
        if incident.acknowledged_at:
            markers.append(TimelineEntry(
                timestamp=incident.acknowledged_at,
                event_id=incident.id,
                event_type="incident_lifecycle",
                source="incident",
                severity="info",
                title=f"Incident {incident.incident_number} acknowledged",
                service_name=incident.service_name,
                metadata={"state": "acknowledged"},
            ))
        
        # Incident resolved
        if incident.resolved_at:
            markers.append(TimelineEntry(
                timestamp=incident.resolved_at,
                event_id=incident.id,
                event_type="incident_lifecycle",
                source="incident",
                severity="info",
                title=f"Incident {incident.incident_number} resolved",
                description=incident.root_cause,
                service_name=incident.service_name,
                metadata={"state": "resolved"},
            ))
        
        # Add markers to timeline
        timeline.entries.extend(markers)
        timeline.entries.sort(key=lambda e: e.timestamp)
        timeline.total_events = len(timeline.entries)
        
        return timeline
    
    def _extract_event_metadata(self, event: NormalizedEvent) -> Dict[str, Any]:
        """Extract relevant metadata from event."""
        metadata = {}
        
        # Include event-specific metadata
        if event.metadata_json:
            # Deploy events
            if event.event_type == EventType.DEPLOY:
                for key in ["version", "previous_version", "deployer", "commit_sha"]:
                    if key in event.metadata_json:
                        metadata[key] = event.metadata_json[key]
            
            # Metric events
            elif event.event_type == EventType.METRIC:
                for key in ["metric_name", "current_value", "baseline_value", "z_score"]:
                    if key in event.metadata_json:
                        metadata[key] = event.metadata_json[key]
            
            # Incident events
            elif event.event_type == EventType.INCIDENT:
                for key in ["incident_id", "state", "priority", "assigned_to"]:
                    if key in event.metadata_json:
                        metadata[key] = event.metadata_json[key]
            
            # Alert events
            elif event.event_type == EventType.ALERT:
                for key in ["alert_type", "confidence", "eta_minutes"]:
                    if key in event.metadata_json:
                        metadata[key] = event.metadata_json[key]
        
        return metadata
    
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
        """Fetch all correlations for an incident."""
        result = await self.session.execute(
            select(Correlation).where(Correlation.incident_id == incident_id)
        )
        return list(result.scalars().all())
    
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
        end_time: datetime,
        service_name: Optional[str] = None,
        entity_id: Optional[str] = None
    ) -> List[NormalizedEvent]:
        """Fetch events within a time range with optional filters."""
        query = select(NormalizedEvent).where(
            and_(
                NormalizedEvent.timestamp >= start_time,
                NormalizedEvent.timestamp <= end_time
            )
        )
        
        if service_name:
            query = query.where(NormalizedEvent.service_name == service_name)
        
        if entity_id:
            query = query.where(NormalizedEvent.entity_id == entity_id)
        
        query = query.order_by(NormalizedEvent.timestamp).limit(1000)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
