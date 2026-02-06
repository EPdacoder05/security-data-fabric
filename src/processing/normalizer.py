"""Event normalization across different data sources."""
from typing import Dict, Any
from datetime import datetime
import hashlib
import json

from src.processing.schema import NormalizedEventSchema
from src.observability import get_logger

logger = get_logger(__name__)


class EventNormalizer:
    """Normalize events from different sources to a unified schema."""

    def __init__(self) -> None:
        """Initialize normalizer."""
        self.severity_mappings = {
            "dynatrace": {
                "AVAILABILITY": 5,
                "ERROR": 4,
                "SLOWDOWN": 3,
                "RESOURCE": 3,
                "CUSTOM": 2,
                "INFO": 1,
            },
            "splunk": {
                "critical": 5,
                "high": 4,
                "medium": 3,
                "low": 2,
                "info": 1,
            },
            "servicenow": {
                "1": 5,  # Critical
                "2": 4,  # High
                "3": 3,  # Medium
                "4": 2,  # Low
                "5": 1,  # Planning
            },
            "pagerduty": {
                "triggered": 5,
                "acknowledged": 4,
                "resolved": 1,
            },
            "github": {
                "deployment": 2,
                "push": 1,
                "pr_merge": 1,
            },
        }

    def normalize(self, source: str, raw_data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize raw event to standard schema.
        
        Args:
            source: Source name
            raw_data: Raw event data
            
        Returns:
            Normalized event
        """
        if source == "dynatrace":
            return self._normalize_dynatrace(raw_data)
        elif source == "splunk":
            return self._normalize_splunk(raw_data)
        elif source == "servicenow":
            return self._normalize_servicenow(raw_data)
        elif source == "pagerduty":
            return self._normalize_pagerduty(raw_data)
        elif source == "github":
            return self._normalize_github(raw_data)
        else:
            return self._normalize_generic(source, raw_data)

    def _normalize_dynatrace(self, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize Dynatrace event."""
        # Check if it's a metric or problem
        if "metric_id" in data:
            # Metric event
            return NormalizedEventSchema(
                event_type="metric",
                timestamp=data.get("timestamp", datetime.utcnow()),
                source="dynatrace",
                severity=2,  # Metrics are typically low severity unless anomalous
                title=f"Metric: {data.get('metric_id', 'unknown')}",
                description=f"Value: {data.get('value', 'N/A')} {data.get('unit', '')}",
                metadata={
                    "metric_id": data.get("metric_id"),
                    "value": data.get("value"),
                    "unit": data.get("unit"),
                    "dimensions": data.get("dimensions", {}),
                },
            )
        else:
            # Problem event
            severity_str = data.get("severityLevel", "INFO")
            severity = self.severity_mappings["dynatrace"].get(severity_str, 3)
            
            return NormalizedEventSchema(
                event_type="incident",
                timestamp=datetime.fromtimestamp(data.get("startTime", 0) / 1000),
                source="dynatrace",
                severity=severity,
                title=data.get("title", "Dynatrace Problem"),
                description=data.get("impactAnalysis", {}).get("description", ""),
                metadata={
                    "problem_id": data.get("problemId"),
                    "status": data.get("status"),
                    "affected_entities": data.get("affectedEntities", []),
                    "root_cause": data.get("rootCauseEntity"),
                },
            )

    def _normalize_splunk(self, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize Splunk event."""
        severity_str = data.get("severity", data.get("level", "info")).lower()
        severity = self.severity_mappings["splunk"].get(severity_str, 2)

        return NormalizedEventSchema(
            event_type=data.get("sourcetype", "log"),
            timestamp=datetime.fromtimestamp(float(data.get("_time", 0)))
            if "_time" in data
            else datetime.utcnow(),
            source="splunk",
            severity=severity,
            title=data.get("_raw", "")[:500] if "_raw" in data else "Splunk Event",
            description=data.get("_raw", ""),
            metadata={
                "host": data.get("host"),
                "source": data.get("source"),
                "sourcetype": data.get("sourcetype"),
                "index": data.get("index"),
            },
        )

    def _normalize_servicenow(self, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize ServiceNow event."""
        impact = str(data.get("impact", "3"))
        severity = self.severity_mappings["servicenow"].get(impact, 3)

        return NormalizedEventSchema(
            event_type="incident",
            timestamp=datetime.fromisoformat(data.get("sys_created_on", "").replace(" ", "T"))
            if data.get("sys_created_on")
            else datetime.utcnow(),
            source="servicenow",
            severity=severity,
            title=data.get("short_description", data.get("number", "ServiceNow Incident")),
            description=data.get("description", ""),
            metadata={
                "number": data.get("number"),
                "state": data.get("state"),
                "priority": data.get("priority"),
                "category": data.get("category"),
                "assignment_group": data.get("assignment_group"),
                "assigned_to": data.get("assigned_to"),
            },
        )

    def _normalize_pagerduty(self, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize PagerDuty event."""
        status = data.get("status", "triggered")
        severity = self.severity_mappings["pagerduty"].get(status, 4)

        return NormalizedEventSchema(
            event_type="incident",
            timestamp=datetime.fromisoformat(data.get("created_at", "").replace("Z", "+00:00"))
            if data.get("created_at")
            else datetime.utcnow(),
            source="pagerduty",
            severity=severity,
            title=data.get("title", data.get("summary", "PagerDuty Incident")),
            description=data.get("description", ""),
            metadata={
                "incident_number": data.get("incident_number"),
                "status": status,
                "urgency": data.get("urgency"),
                "service": data.get("service", {}).get("summary"),
                "escalation_policy": data.get("escalation_policy", {}).get("summary"),
            },
        )

    def _normalize_github(self, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize GitHub event."""
        event_type = data.get("event_type", "unknown")
        severity = self.severity_mappings["github"].get(event_type, 1)

        title = f"GitHub {event_type}: {data.get('repository', 'unknown')}"
        if event_type == "deployment":
            title = f"Deployment to {data.get('environment', 'unknown')}: {data.get('repository')}"
        elif event_type == "push":
            title = f"Push to {data.get('ref', 'unknown')}: {data.get('repository')}"
        elif event_type == "pr_merge":
            title = f"PR #{data.get('pr_number')} merged: {data.get('title', '')}"

        return NormalizedEventSchema(
            event_type=event_type,
            timestamp=data.get("timestamp", datetime.utcnow()),
            source="github",
            severity=severity,
            title=title,
            description=data.get("description", ""),
            metadata=data,
        )

    def _normalize_generic(self, source: str, data: Dict[str, Any]) -> NormalizedEventSchema:
        """Normalize generic event."""
        return NormalizedEventSchema(
            event_type=data.get("type", "unknown"),
            timestamp=datetime.utcnow(),
            source=source,
            severity=3,
            title=str(data.get("title", data.get("message", "Generic Event")))[:500],
            description=str(data.get("description", "")),
            metadata=data,
        )

    @staticmethod
    def compute_content_hash(event: NormalizedEventSchema) -> str:
        """Compute content hash for deduplication.
        
        Args:
            event: Normalized event
            
        Returns:
            SHA-256 hash of event content
        """
        # Create a canonical representation for hashing
        content = {
            "source": event.source,
            "event_type": event.event_type,
            "title": event.title,
            "severity": event.severity,
        }
        
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
