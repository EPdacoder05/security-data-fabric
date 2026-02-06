"""
Schema registry and validation for Bronze layer events.
Manages raw event schemas with versioning and Pydantic validation.
"""
from typing import Dict, List, Any, Optional, Type
from datetime import datetime
from enum import Enum
import logging
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class EventSeverity(str, Enum):
    """Event severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventSource(str, Enum):
    """Supported event sources."""
    DYNATRACE = "dynatrace"
    SPLUNK = "splunk"
    SERVICENOW = "servicenow"
    PAGERDUTY = "pagerduty"
    GITHUB = "github"
    CUSTOM = "custom"


class BronzeEventBase(BaseModel):
    """Base schema for all Bronze layer events."""
    
    source: EventSource = Field(..., description="Source system identifier")
    source_type: str = Field(..., description="Specific event type from source")
    event_id: str = Field(..., description="Unique event identifier from source")
    timestamp: str = Field(..., description="Event timestamp (ISO 8601)")
    severity: EventSeverity = Field(..., description="Event severity level")
    title: str = Field(..., description="Event title or summary")
    description: str = Field(default="", description="Detailed event description")
    raw_data: Dict[str, Any] = Field(..., description="Original raw event data")
    ingested_at: str = Field(..., description="Ingestion timestamp (ISO 8601)")
    
    @field_validator("timestamp", "ingested_at")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate timestamp format."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError(f"Invalid timestamp format: {v}")
    
    class Config:
        """Pydantic config."""
        use_enum_values = True
        json_schema_extra = {
            "example": {
                "source": "dynatrace",
                "source_type": "problem",
                "event_id": "P-123456",
                "timestamp": "2024-01-15T10:30:00Z",
                "severity": "HIGH",
                "title": "High CPU usage detected",
                "description": "CPU usage exceeded 90% threshold",
                "raw_data": {},
                "ingested_at": "2024-01-15T10:30:05Z",
            }
        }


class DynatraceEventSchema(BronzeEventBase):
    """Schema for Dynatrace events."""
    
    source: EventSource = Field(default=EventSource.DYNATRACE, frozen=True)
    impact_level: Optional[str] = Field(default=None, description="Problem impact level")
    affected_entities: List[Dict[str, Any]] = Field(default_factory=list, description="Affected entities")
    root_cause_entity: Optional[Dict[str, Any]] = Field(default=None, description="Root cause entity")
    management_zones: List[Dict[str, Any]] = Field(default_factory=list, description="Management zones")


class SplunkEventSchema(BronzeEventBase):
    """Schema for Splunk events."""
    
    source: EventSource = Field(default=EventSource.SPLUNK, frozen=True)
    index: str = Field(default="", description="Splunk index")
    source_name: str = Field(default="", description="Splunk source")
    host: str = Field(default="", description="Event host")
    raw: str = Field(default="", description="Raw event text")
    fields: Dict[str, Any] = Field(default_factory=dict, description="Extracted fields")


class ServiceNowEventSchema(BronzeEventBase):
    """Schema for ServiceNow events."""
    
    source: EventSource = Field(default=EventSource.SERVICENOW, frozen=True)
    number: str = Field(default="", description="Ticket/record number")
    state: str = Field(default="", description="Record state")
    priority: str = Field(default="", description="Priority")
    assigned_to: str = Field(default="", description="Assigned user")
    assignment_group: str = Field(default="", description="Assigned group")


class PagerDutyEventSchema(BronzeEventBase):
    """Schema for PagerDuty events."""
    
    source: EventSource = Field(default=EventSource.PAGERDUTY, frozen=True)
    status: str = Field(default="", description="Incident status")
    urgency: str = Field(default="", description="Incident urgency")
    service: Dict[str, Any] = Field(default_factory=dict, description="Service information")
    escalation_policy: Dict[str, Any] = Field(default_factory=dict, description="Escalation policy")
    assignments: List[Dict[str, Any]] = Field(default_factory=list, description="Incident assignments")


class GitHubEventSchema(BronzeEventBase):
    """Schema for GitHub events."""
    
    source: EventSource = Field(default=EventSource.GITHUB, frozen=True)
    html_url: str = Field(default="", description="GitHub URL")
    actor: Optional[Dict[str, Any]] = Field(default=None, description="Event actor/user")


class SchemaRegistry:
    """
    Registry for managing and validating Bronze event schemas.
    Provides schema versioning and validation capabilities.
    """
    
    def __init__(self):
        """Initialize schema registry."""
        self._schemas: Dict[str, Dict[str, Type[BaseModel]]] = {}
        self._register_default_schemas()
        logger.info("Schema registry initialized")
    
    def _register_default_schemas(self):
        """Register default schemas for supported sources."""
        self.register_schema(EventSource.DYNATRACE, DynatraceEventSchema, version="1.0")
        self.register_schema(EventSource.SPLUNK, SplunkEventSchema, version="1.0")
        self.register_schema(EventSource.SERVICENOW, ServiceNowEventSchema, version="1.0")
        self.register_schema(EventSource.PAGERDUTY, PagerDutyEventSchema, version="1.0")
        self.register_schema(EventSource.GITHUB, GitHubEventSchema, version="1.0")
    
    def register_schema(
        self,
        source: EventSource,
        schema: Type[BaseModel],
        version: str = "1.0"
    ):
        """
        Register a schema for a data source.
        
        Args:
            source: Data source identifier
            schema: Pydantic model class for validation
            version: Schema version
        """
        source_str = source if isinstance(source, str) else source.value
        
        if source_str not in self._schemas:
            self._schemas[source_str] = {}
        
        self._schemas[source_str][version] = schema
        logger.info(f"Registered schema for {source_str} v{version}")
    
    def get_schema(
        self,
        source: EventSource,
        version: str = "1.0"
    ) -> Optional[Type[BaseModel]]:
        """
        Get schema for a data source.
        
        Args:
            source: Data source identifier
            version: Schema version
        
        Returns:
            Pydantic model class or None if not found
        """
        source_str = source if isinstance(source, str) else source.value
        return self._schemas.get(source_str, {}).get(version)
    
    def validate_event(
        self,
        event: Dict[str, Any],
        source: Optional[EventSource] = None,
        version: str = "1.0",
        strict: bool = False
    ) -> tuple[bool, Optional[BaseModel], Optional[str]]:
        """
        Validate an event against its schema.
        
        Args:
            event: Event data to validate
            source: Data source (if None, extracted from event)
            version: Schema version
            strict: If True, raise exception on validation failure
        
        Returns:
            Tuple of (is_valid, validated_model, error_message)
        """
        try:
            # Extract source from event if not provided
            if source is None:
                source_str = event.get("source")
                if not source_str:
                    return False, None, "Missing 'source' field in event"
                source = EventSource(source_str)
            
            # Get schema
            schema = self.get_schema(source, version)
            if not schema:
                return False, None, f"No schema found for {source} v{version}"
            
            # Validate
            validated = schema(**event)
            return True, validated, None
        
        except Exception as e:
            error_msg = f"Validation error: {str(e)}"
            logger.error(error_msg)
            
            if strict:
                raise
            
            return False, None, error_msg
    
    def validate_batch(
        self,
        events: List[Dict[str, Any]],
        version: str = "1.0",
        strict: bool = False
    ) -> tuple[List[BaseModel], List[tuple[int, str]]]:
        """
        Validate a batch of events.
        
        Args:
            events: List of events to validate
            version: Schema version
            strict: If True, raise exception on first validation failure
        
        Returns:
            Tuple of (valid_events, errors)
            where errors is a list of (index, error_message) tuples
        """
        valid_events = []
        errors = []
        
        for idx, event in enumerate(events):
            is_valid, validated, error = self.validate_event(
                event,
                version=version,
                strict=strict
            )
            
            if is_valid and validated:
                valid_events.append(validated)
            else:
                errors.append((idx, error or "Unknown error"))
        
        logger.info(
            f"Validated {len(events)} events: "
            f"{len(valid_events)} valid, {len(errors)} invalid"
        )
        
        return valid_events, errors
    
    def get_schema_info(self, source: EventSource) -> Dict[str, Any]:
        """
        Get schema information for a source.
        
        Args:
            source: Data source identifier
        
        Returns:
            Dictionary with schema information
        """
        source_str = source if isinstance(source, str) else source.value
        versions = list(self._schemas.get(source_str, {}).keys())
        
        return {
            "source": source_str,
            "versions": versions,
            "latest_version": versions[-1] if versions else None,
        }
    
    def list_sources(self) -> List[str]:
        """
        List all registered sources.
        
        Returns:
            List of source identifiers
        """
        return list(self._schemas.keys())
    
    def get_json_schema(
        self,
        source: EventSource,
        version: str = "1.0"
    ) -> Optional[Dict[str, Any]]:
        """
        Get JSON schema for a source.
        
        Args:
            source: Data source identifier
            version: Schema version
        
        Returns:
            JSON schema dictionary or None
        """
        schema = self.get_schema(source, version)
        if schema:
            return schema.model_json_schema()
        return None


# Global schema registry instance
schema_registry = SchemaRegistry()


# Convenience functions
def validate_event(event: Dict[str, Any], **kwargs) -> tuple[bool, Optional[BaseModel], Optional[str]]:
    """Validate a single event using the global registry."""
    return schema_registry.validate_event(event, **kwargs)


def validate_batch(events: List[Dict[str, Any]], **kwargs) -> tuple[List[BaseModel], List[tuple[int, str]]]:
    """Validate a batch of events using the global registry."""
    return schema_registry.validate_batch(events, **kwargs)
