"""
Event normalizer for Silver layer.
Converts raw events from Bronze sources to unified UnifiedEvent schema.
Handles: Dynatrace, Splunk, ServiceNow, PagerDuty, GitHub formats.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import logging
from dateutil import parser as dateutil_parser

from src.silver.unified_schema import (
    UnifiedEvent,
    EventSeverity,
    EventType,
    MetricEvent,
    IncidentEvent,
    DeployEvent,
    AlertEvent,
)

logger = logging.getLogger(__name__)


class NormalizerError(Exception):
    """Exception raised during normalization."""
    pass


class EventNormalizer:
    """
    Normalizes raw events from various sources to unified schema.
    Maps source-specific fields to UnifiedEvent structure.
    """
    
    # Severity mapping: source severity -> standard EventSeverity
    SEVERITY_MAPPINGS = {
        "dynatrace": {
            "INFO": EventSeverity.INFO,
            "AVAILABILITY": EventSeverity.WARNING,
            "ERROR": EventSeverity.CRITICAL,
            "SLOWDOWN": EventSeverity.WARNING,
            "RESOURCE_CONTENTION": EventSeverity.WARNING,
            "CUSTOM_ALERT": EventSeverity.WARNING,
            "MONITORING_UNAVAILABLE": EventSeverity.CRITICAL,
        },
        "splunk": {
            "INFO": EventSeverity.INFO,
            "LOW": EventSeverity.INFO,
            "MEDIUM": EventSeverity.WARNING,
            "HIGH": EventSeverity.CRITICAL,
            "CRITICAL": EventSeverity.CRITICAL,
            "EXTREME": EventSeverity.EXTREME,
        },
        "servicenow": {
            "3": EventSeverity.INFO,  # P3
            "2": EventSeverity.WARNING,  # P2
            "1": EventSeverity.CRITICAL,  # P1
            "0": EventSeverity.EXTREME,  # P0
            "P4": EventSeverity.INFO,
            "P3": EventSeverity.INFO,
            "P2": EventSeverity.WARNING,
            "P1": EventSeverity.CRITICAL,
            "P0": EventSeverity.EXTREME,
        },
        "pagerduty": {
            "INFO": EventSeverity.INFO,
            "WARNING": EventSeverity.WARNING,
            "ERROR": EventSeverity.CRITICAL,
            "CRITICAL": EventSeverity.CRITICAL,
        },
        "github": {
            "INFO": EventSeverity.INFO,
            "LOW": EventSeverity.INFO,
            "MEDIUM": EventSeverity.WARNING,
            "HIGH": EventSeverity.CRITICAL,
            "CRITICAL": EventSeverity.EXTREME,
        },
    }
    
    def __init__(self):
        """Initialize the normalizer."""
        self.stats = {
            "normalized": 0,
            "failed": 0,
            "by_source": {},
        }
    
    async def normalize(self, raw_event: Dict[str, Any]) -> Optional[UnifiedEvent]:
        """
        Normalize a raw event to UnifiedEvent.
        
        Args:
            raw_event: Raw event dictionary from Bronze layer
            
        Returns:
            UnifiedEvent instance or None if normalization fails
        """
        source = raw_event.get("source", "unknown").lower()
        
        try:
            # Route to appropriate normalizer based on source
            if source == "dynatrace":
                event = self._normalize_dynatrace(raw_event)
            elif source == "splunk":
                event = self._normalize_splunk(raw_event)
            elif source == "servicenow":
                event = self._normalize_servicenow(raw_event)
            elif source == "pagerduty":
                event = self._normalize_pagerduty(raw_event)
            elif source == "github":
                event = self._normalize_github(raw_event)
            else:
                logger.warning(f"Unknown source: {source}")
                event = self._normalize_generic(raw_event)
            
            self.stats["normalized"] += 1
            self.stats["by_source"][source] = self.stats["by_source"].get(source, 0) + 1
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to normalize event from {source}: {e}", exc_info=True)
            self.stats["failed"] += 1
            return None
    
    def _normalize_dynatrace(self, raw: Dict[str, Any]) -> UnifiedEvent:
        """Normalize Dynatrace event."""
        source_type = raw.get("source_type", "event")
        raw_data = raw.get("raw_data", {})
        
        # Determine event type
        if source_type == "problem":
            event_type = EventType.METRIC
        else:
            event_type = EventType.ALERT
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # Map severity
        severity_str = raw.get("severity", "INFO").upper()
        severity = self._map_severity("dynatrace", severity_str)
        
        # Extract entity information
        entity_id = None
        entity_type = None
        entity_name = None
        
        if source_type == "problem":
            root_cause = raw.get("root_cause_entity", {})
            entity_id = root_cause.get("entityId", {}).get("id")
            entity_type_raw = root_cause.get("entityId", {}).get("type")
            entity_type = entity_type_raw.lower() if entity_type_raw else None
            entity_name = root_cause.get("name")
        else:
            entity_id = raw.get("entity_id")
            entity_name = raw.get("entity_name")
            entity_type = self._extract_dynatrace_entity_type(entity_id)
        
        # Build base event
        event_data = {
            "source": "dynatrace",
            "source_id": raw.get("event_id"),
            "event_type": event_type,
            "timestamp": timestamp,
            "severity": severity,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "title": raw.get("title", "Dynatrace Event"),
            "description": raw.get("description", ""),
            "tags": self._extract_dynatrace_tags(raw),
            "metadata": {
                "source_type": source_type,
                "status": raw.get("status"),
                "impact_level": raw.get("impact_level"),
                "management_zones": raw.get("management_zones", []),
            },
        }
        
        # Create appropriate event type
        if source_type == "problem" and event_type == EventType.METRIC:
            # Try to create MetricEvent if we have metric info
            evidence = raw_data.get("evidenceDetails", {})
            if evidence:
                return MetricEvent(
                    **event_data,
                    metric_name=evidence.get("displayName", "unknown"),
                    current_value=0.0,  # Dynatrace doesn't always provide this
                    is_anomaly=True,
                )
        
        return UnifiedEvent(**event_data)
    
    def _normalize_splunk(self, raw: Dict[str, Any]) -> UnifiedEvent:
        """Normalize Splunk event."""
        fields = raw.get("fields", {})
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # Map severity
        severity_str = raw.get("severity", "INFO").upper()
        severity = self._map_severity("splunk", severity_str)
        
        # Determine event type
        source_type = raw.get("source_type", "").lower()
        if "incident" in source_type or "notable" in source_type:
            event_type = EventType.INCIDENT
        elif "metric" in source_type:
            event_type = EventType.METRIC
        else:
            event_type = EventType.LOG
        
        # Extract entity
        entity_id = fields.get("entity_id") or fields.get("host_id")
        entity_name = raw.get("host") or fields.get("hostname")
        entity_type = "host" if entity_name else None
        
        return UnifiedEvent(
            source="splunk",
            source_id=raw.get("event_id"),
            event_type=event_type,
            timestamp=timestamp,
            severity=severity,
            entity_id=entity_id,
            entity_type=entity_type,
            entity_name=entity_name,
            title=raw.get("title", "Splunk Event"),
            description=raw.get("description", ""),
            tags={
                "index": raw.get("index", ""),
                "source_type": raw.get("source_type", ""),
                **fields,
            },
            metadata={
                "source_name": raw.get("source_name"),
                "raw": raw.get("raw", "")[:1000],  # Truncate raw
            },
        )
    
    def _normalize_servicenow(self, raw: Dict[str, Any]) -> IncidentEvent:
        """Normalize ServiceNow incident."""
        raw_data = raw.get("raw_data", {})
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # Map severity (priority in ServiceNow)
        priority = raw.get("priority", "3")
        severity = self._map_severity("servicenow", str(priority))
        
        # Map state
        state_map = {
            "1": "open",
            "2": "open",  # In Progress
            "3": "open",  # On Hold
            "6": "resolved",
            "7": "closed",
        }
        state = state_map.get(str(raw.get("state", "1")), "open")
        
        # Parse resolved timestamp
        resolved_at = None
        if raw.get("resolved_at"):
            resolved_at = self._parse_timestamp(raw.get("resolved_at"))
        
        return IncidentEvent(
            source="servicenow",
            source_id=raw.get("number"),
            event_type=EventType.INCIDENT,
            timestamp=timestamp,
            severity=severity,
            entity_id=raw.get("cmdb_ci"),
            entity_type="configuration_item",
            entity_name=raw.get("cmdb_ci_name"),
            title=raw.get("short_description", "ServiceNow Incident"),
            description=raw.get("description", ""),
            incident_id=raw.get("number", ""),
            state=state,
            priority=f"P{priority}",
            assigned_to=raw.get("assigned_to"),
            affected_services=[raw.get("business_service")] if raw.get("business_service") else [],
            resolution=raw.get("close_notes"),
            resolved_at=resolved_at,
            tags={
                k: v for k, v in {
                    "category": raw.get("category"),
                    "subcategory": raw.get("subcategory"),
                    "urgency": str(raw.get("urgency")) if raw.get("urgency") else None,
                    "impact": str(raw.get("impact")) if raw.get("impact") else None,
                }.items() if v is not None
            },
            metadata={
                "caller": raw.get("caller_id"),
                "opened_by": raw.get("opened_by"),
            },
        )
    
    def _normalize_pagerduty(self, raw: Dict[str, Any]) -> IncidentEvent:
        """Normalize PagerDuty incident."""
        raw_data = raw.get("raw_data", {})
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # Map urgency to severity
        urgency = raw.get("urgency", "low").upper()
        severity_map = {
            "LOW": EventSeverity.INFO,
            "HIGH": EventSeverity.CRITICAL,
        }
        severity = severity_map.get(urgency, EventSeverity.WARNING)
        
        # Map status to state
        status = raw.get("status", "triggered").lower()
        state_map = {
            "triggered": "open",
            "acknowledged": "open",
            "resolved": "resolved",
        }
        state = state_map.get(status, "open")
        
        # Parse resolved timestamp
        resolved_at = None
        if raw.get("resolved_at"):
            resolved_at = self._parse_timestamp(raw.get("resolved_at"))
        
        # Extract affected services
        service = raw.get("service", {})
        affected_services = [service.get("summary", "")] if service else []
        
        return IncidentEvent(
            source="pagerduty",
            source_id=raw.get("id"),
            event_type=EventType.INCIDENT,
            timestamp=timestamp,
            severity=severity,
            entity_id=service.get("id") if service else None,
            entity_type="service",
            entity_name=service.get("summary") if service else None,
            title=raw.get("title", "PagerDuty Incident"),
            description=raw.get("description", ""),
            incident_id=raw.get("incident_number", ""),
            state=state,
            priority=f"P1" if urgency == "HIGH" else "P3",
            assigned_to=self._extract_pagerduty_assignee(raw),
            affected_services=affected_services,
            resolved_at=resolved_at,
            tags={
                "urgency": urgency.lower(),
                "escalation_policy": raw.get("escalation_policy", {}).get("summary", ""),
            },
            metadata={
                "acknowledgements": raw.get("acknowledgements", []),
                "alert_counts": raw.get("alert_counts", {}),
            },
        )
    
    def _normalize_github(self, raw: Dict[str, Any]) -> DeployEvent:
        """Normalize GitHub deployment event."""
        raw_data = raw.get("raw_data", {})
        source_type = raw.get("source_type", "deployment")
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # GitHub events are typically info level
        severity = EventSeverity.INFO
        
        # Deployment-specific fields
        service = raw.get("repository", raw.get("service", "unknown"))
        version = raw.get("ref", raw.get("version", "unknown"))
        
        return DeployEvent(
            source="github",
            source_id=raw.get("deployment_id", raw.get("event_id")),
            event_type=EventType.DEPLOY,
            timestamp=timestamp,
            severity=severity,
            entity_id=raw.get("repository_id"),
            entity_type="repository",
            entity_name=raw.get("repository"),
            title=raw.get("description", f"Deployment: {service}"),
            description=raw.get("description", ""),
            service=service,
            version=version,
            previous_version=raw.get("previous_version"),
            deployer=raw.get("creator", raw.get("sender", {}).get("login")),
            commit_sha=raw.get("sha"),
            pull_request=raw.get("pull_request"),
            deployment_id=raw.get("deployment_id"),
            rollback=raw.get("task") == "rollback",
            tags={
                k: v for k, v in {
                    "environment": raw.get("environment", "production"),
                    "task": raw.get("task"),
                }.items() if v is not None
            },
            metadata={
                "workflow": raw.get("workflow"),
                "ref": raw.get("ref"),
            },
        )
    
    def _normalize_generic(self, raw: Dict[str, Any]) -> UnifiedEvent:
        """Fallback normalizer for unknown sources."""
        timestamp = self._parse_timestamp(raw.get("timestamp"))
        
        # Try to parse severity
        severity_str = str(raw.get("severity", "INFO")).upper()
        severity = EventSeverity.INFO
        for s in EventSeverity:
            if s.value.upper() == severity_str:
                severity = s
                break
        
        # Try to determine event type
        event_type_str = raw.get("event_type", "alert").lower()
        event_type = EventType.ALERT
        for et in EventType:
            if et.value == event_type_str:
                event_type = et
                break
        
        return UnifiedEvent(
            source=raw.get("source", "unknown"),
            source_id=raw.get("event_id"),
            event_type=event_type,
            timestamp=timestamp,
            severity=severity,
            entity_id=raw.get("entity_id"),
            entity_type=raw.get("entity_type"),
            entity_name=raw.get("entity_name"),
            title=raw.get("title", "Unknown Event"),
            description=raw.get("description", ""),
            tags=raw.get("tags", {}),
            metadata={"raw": raw},
        )
    
    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """
        Parse timestamp to UTC datetime.
        
        Args:
            timestamp: String, datetime, or timestamp value
            
        Returns:
            UTC datetime object
        """
        if isinstance(timestamp, datetime):
            dt = timestamp
        elif isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            try:
                dt = dateutil_parser.parse(timestamp)
            except (ValueError, TypeError) as e:
                logger.warning(f"Failed to parse timestamp: {timestamp}, error: {e}")
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)
        
        # Ensure UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        return dt
    
    def _map_severity(self, source: str, severity_str: str) -> EventSeverity:
        """
        Map source-specific severity to standard EventSeverity.
        
        Args:
            source: Source system name
            severity_str: Source-specific severity string
            
        Returns:
            Standard EventSeverity
        """
        mappings = self.SEVERITY_MAPPINGS.get(source, {})
        severity_upper = severity_str.upper()
        
        # Try exact match
        if severity_upper in mappings:
            return mappings[severity_upper]
        
        # Try partial match
        for key, value in mappings.items():
            if key in severity_upper or severity_upper in key:
                return value
        
        # Default based on keywords
        if any(word in severity_upper for word in ["CRITICAL", "FATAL", "SEVERE"]):
            return EventSeverity.CRITICAL
        elif any(word in severity_upper for word in ["WARN", "MEDIUM"]):
            return EventSeverity.WARNING
        elif any(word in severity_upper for word in ["INFO", "LOW", "DEBUG"]):
            return EventSeverity.INFO
        
        return EventSeverity.INFO
    
    def _extract_dynatrace_entity_type(self, entity_id: Optional[str]) -> Optional[str]:
        """Extract entity type from Dynatrace entity ID."""
        if not entity_id:
            return None
        
        # Dynatrace entity IDs follow pattern: TYPE-HASH
        parts = entity_id.split("-", 1)
        if len(parts) > 1:
            type_prefix = parts[0].lower()
            type_map = {
                "host": "host",
                "process": "process",
                "service": "service",
                "application": "application",
                "pg": "process_group",
            }
            return type_map.get(type_prefix, type_prefix)
        
        return None
    
    def _extract_dynatrace_tags(self, raw: Dict[str, Any]) -> Dict[str, str]:
        """Extract tags from Dynatrace event."""
        tags = {}
        
        # Add management zones
        zones = raw.get("management_zones", [])
        if zones:
            tags["management_zones"] = ",".join([z.get("name", "") for z in zones])
        
        # Add impact level
        if raw.get("impact_level"):
            tags["impact_level"] = raw["impact_level"]
        
        return tags
    
    def _extract_pagerduty_assignee(self, raw: Dict[str, Any]) -> Optional[str]:
        """Extract assignee from PagerDuty incident."""
        assignments = raw.get("assignments", [])
        if assignments:
            assignee = assignments[0].get("assignee", {})
            return assignee.get("summary", assignee.get("email"))
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get normalization statistics."""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics."""
        self.stats = {
            "normalized": 0,
            "failed": 0,
            "by_source": {},
        }
