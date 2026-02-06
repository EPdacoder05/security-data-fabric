"""Builds incident timelines from correlated events."""
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import UUID

from src.processing.schema import (
    NormalizedEventSchema,
    PredictionSchema,
    IncidentTimelineSchema,
    TimelineEntry,
)
from src.intelligence.correlator import CorrelationResult
from src.observability import get_logger

logger = get_logger(__name__)


class TimelineBuilder:
    """Builds incident timelines from events and correlations."""

    def __init__(self) -> None:
        """Initialize timeline builder."""
        logger.info("Initialized timeline builder")

    def build_timeline(
        self,
        incident_id: str,
        events: List[NormalizedEventSchema],
        correlations: Optional[List[CorrelationResult]] = None,
        predictions: Optional[List[PredictionSchema]] = None,
        title: Optional[str] = None,
        root_cause: Optional[Dict[str, Any]] = None,
        impact: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> IncidentTimelineSchema:
        """Build incident timeline from events.

        Args:
            incident_id: Unique incident identifier
            events: List of events related to incident
            correlations: Optional list of correlations
            predictions: Optional list of ML predictions
            title: Optional custom title (generated if not provided)
            root_cause: Optional root cause analysis
            impact: Optional impact description
            resolution: Optional resolution details

        Returns:
            Incident timeline
        """
        if not events:
            raise ValueError("Cannot build timeline without events")

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Build timeline entries
        timeline_entries = []
        for event in sorted_events:
            entry = self._create_timeline_entry(event)
            timeline_entries.append(entry.model_dump())

        # Add predictions to timeline
        if predictions:
            for prediction in predictions:
                entry = self._create_prediction_entry(prediction)
                timeline_entries.append(entry)

        # Sort all entries by timestamp
        timeline_entries.sort(key=lambda e: e["timestamp"])

        # Generate title if not provided
        if not title:
            title = self._generate_title(sorted_events)

        # Determine incident timeframe
        start_time = sorted_events[0].timestamp
        end_time = None
        if resolution:
            # Use last event time if resolved
            end_time = sorted_events[-1].timestamp

        timeline = IncidentTimelineSchema(
            incident_id=incident_id,
            title=title,
            start_time=start_time,
            end_time=end_time,
            events=timeline_entries,
            root_cause=root_cause,
            impact=impact,
            resolution=resolution,
        )

        logger.info(
            f"Built timeline for incident {incident_id}",
            extra={
                "incident_id": incident_id,
                "event_count": len(events),
                "entry_count": len(timeline_entries),
            },
        )

        return timeline

    def format_timeline(self, timeline: IncidentTimelineSchema) -> str:
        """Format timeline as human-readable text.

        Args:
            timeline: Incident timeline

        Returns:
            Formatted timeline string
        """
        lines = []

        # Header
        lines.append(f"Incident Timeline: {timeline.title}")
        lines.append(f"Incident ID: {timeline.incident_id}")
        lines.append(f"Start Time: {self._format_timestamp(timeline.start_time)}")
        if timeline.end_time:
            lines.append(f"End Time: {self._format_timestamp(timeline.end_time)}")
            duration = (timeline.end_time - timeline.start_time).total_seconds() / 60
            lines.append(f"Duration: {duration:.1f} minutes")
        lines.append("")

        # Timeline entries
        lines.append("Timeline:")
        lines.append("-" * 80)

        for entry in timeline.events:
            timestamp = entry["timestamp"]
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

            time_str = timestamp.strftime("%H:%M")
            description = entry["description"]
            source = entry.get("source", "Unknown")

            # Format entry based on type
            line = f"{time_str} - {description} ({source})"
            lines.append(line)

        # Root cause
        if timeline.root_cause:
            lines.append("")
            lines.append("Root Cause Analysis:")
            lines.append("-" * 80)
            probable_cause = timeline.root_cause.get("probable_cause")
            confidence = timeline.root_cause.get("confidence", 0)
            if probable_cause:
                lines.append(f"Probable Cause: {probable_cause} (confidence: {confidence:.0%})")

        # Impact
        if timeline.impact:
            lines.append("")
            lines.append("Impact:")
            lines.append("-" * 80)
            lines.append(timeline.impact)

        # Resolution
        if timeline.resolution:
            lines.append("")
            lines.append("Resolution:")
            lines.append("-" * 80)
            lines.append(timeline.resolution)

        return "\n".join(lines)

    def _create_timeline_entry(
        self, event: NormalizedEventSchema
    ) -> TimelineEntry:
        """Create timeline entry from event.

        Args:
            event: Normalized event

        Returns:
            Timeline entry
        """
        # Format description based on event type
        description = self._format_event_description(event)

        return TimelineEntry(
            timestamp=event.timestamp,
            event_type=event.event_type,
            source=event.source,
            description=description,
            severity=event.severity,
            metadata=event.metadata,
        )

    def _create_prediction_entry(
        self, prediction: PredictionSchema
    ) -> Dict[str, Any]:
        """Create timeline entry from prediction.

        Args:
            prediction: ML prediction

        Returns:
            Timeline entry dict
        """
        # Format prediction description
        if prediction.time_to_breach:
            description = (
                f"Predicted {prediction.target_metric} exhaustion in "
                f"{prediction.time_to_breach} min (ML)"
            )
        else:
            description = (
                f"Predicted {prediction.target_metric}: "
                f"{prediction.predicted_value:.2f} (ML)"
            )

        # Use current timestamp for prediction entry
        # In production, this would be the prediction creation time
        return {
            "timestamp": datetime.utcnow(),
            "event_type": "prediction",
            "source": "ML Engine",
            "description": description,
            "severity": prediction.severity,
            "metadata": prediction.details,
        }

    def _format_event_description(self, event: NormalizedEventSchema) -> str:
        """Format event description for timeline.

        Args:
            event: Normalized event

        Returns:
            Formatted description
        """
        if event.event_type == "deployment":
            service = event.metadata.get("service") or event.metadata.get("repository", "service")
            version = event.metadata.get("version", "unknown")
            return f"Deploy {service} {version}"

        elif event.event_type == "metric":
            metric_id = event.metadata.get("metric_id", "metric")
            prev_value = event.metadata.get("previous_value")
            current_value = event.metadata.get("current_value")
            z_score = event.metadata.get("z_score")

            # Shorten metric ID for readability
            metric_name = metric_id.split(".")[-1] if "." in metric_id else metric_id

            if prev_value is not None and current_value is not None:
                if z_score is not None:
                    return (
                        f"{metric_name.upper()} spike "
                        f"{prev_value:.1f}% → {current_value:.1f}% "
                        f"Z={z_score:.2f}"
                    )
                else:
                    return (
                        f"{metric_name.upper()} change "
                        f"{prev_value:.1f} → {current_value:.1f}"
                    )
            else:
                return f"{metric_name.upper()} anomaly detected"

        elif event.event_type == "incident":
            incident_num = event.metadata.get("incident_number", "")
            ticket_id = event.metadata.get("ticket_id", "")
            identifier = incident_num or ticket_id or event.metadata.get("id", "")

            if event.source == "servicenow":
                return f"ServiceNow ticket {identifier} created"
            elif event.source == "pagerduty":
                return f"PagerDuty incident {identifier} triggered"
            else:
                return f"Incident {identifier} reported"

        elif event.event_type == "alert":
            alert_name = event.metadata.get("alert_name", event.title)
            return f"Alert: {alert_name}"

        elif event.event_type in ["push", "pr_merge"]:
            repo = event.metadata.get("repository", "repository")
            author = event.metadata.get("author", "")
            if author:
                return f"Code change by {author} in {repo}"
            else:
                return f"Code change in {repo}"

        elif event.event_type == "config_change":
            what = event.metadata.get("change_type", "configuration")
            return f"Configuration change: {what}"

        else:
            # Default: use event title
            return event.title

    def _generate_title(self, events: List[NormalizedEventSchema]) -> str:
        """Generate incident title from events.

        Args:
            events: List of events

        Returns:
            Generated title
        """
        # Find highest severity event
        highest_severity_event = max(events, key=lambda e: e.severity)

        # Find service if available
        service = None
        for event in events:
            if svc := event.metadata.get("service"):
                service = svc
                break
            if repo := event.metadata.get("repository"):
                service = repo
                break

        # Build title
        severity_labels = {
            1: "Info",
            2: "Low Severity",
            3: "Medium Severity",
            4: "High Severity",
            5: "Critical",
        }
        severity_label = severity_labels.get(highest_severity_event.severity, "")

        if service:
            title = f"{severity_label} Incident: {service}"
        else:
            title = f"{severity_label} Incident"

        # Add event type context
        event_types = set(e.event_type for e in events)
        if "deployment" in event_types:
            title += " (Post-Deployment)"
        elif "metric" in event_types:
            title += " (Performance)"

        return title

    def _format_timestamp(self, dt: datetime) -> str:
        """Format timestamp for display.

        Args:
            dt: Datetime object

        Returns:
            Formatted timestamp
        """
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
