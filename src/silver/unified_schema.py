"""
Unified event schemas for the Silver layer.
All normalized events conform to these Pydantic models.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from enum import Enum


class EventSeverity(str, Enum):
    """Standardized event severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EXTREME = "extreme"


class EventType(str, Enum):
    """Event types."""
    METRIC = "metric"
    INCIDENT = "incident"
    DEPLOY = "deploy"
    ALERT = "alert"
    LOG = "log"
    CHANGE = "change"


class UnifiedEvent(BaseModel):
    """Base unified event schema."""
    
    # Source information
    source: str = Field(..., description="Source system (dynatrace, splunk, etc.)")
    source_id: Optional[str] = Field(None, description="Original event ID from source")
    event_type: EventType = Field(..., description="Event type")
    
    # Temporal
    timestamp: datetime = Field(..., description="Event timestamp in UTC")
    
    # Severity
    severity: EventSeverity = Field(..., description="Event severity")
    
    # Entity
    entity_id: Optional[str] = Field(None, description="Affected entity ID")
    entity_type: Optional[str] = Field(None, description="Entity type (host, service, pod)")
    entity_name: Optional[str] = Field(None, description="Human-readable entity name")
    
    # Content
    title: str = Field(..., description="Event title")
    description: Optional[str] = Field(None, description="Detailed description")
    
    # Enrichment (added by enricher)
    service_name: Optional[str] = Field(None, description="Service name")
    team: Optional[str] = Field(None, description="Owning team")
    environment: Optional[str] = Field(None, description="Environment (prod, staging)")
    region: Optional[str] = Field(None, description="Geographic region")
    
    # Metadata
    tags: Optional[Dict[str, str]] = Field(default_factory=dict, description="Event tags")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "dynatrace",
                "source_id": "PROB-12345",
                "event_type": "metric",
                "timestamp": "2024-01-15T14:05:00Z",
                "severity": "critical",
                "entity_id": "HOST-ABCD1234",
                "entity_type": "host",
                "entity_name": "web-server-01",
                "title": "CPU usage spike detected",
                "description": "CPU usage increased from 45% to 89%",
                "service_name": "auth-service",
                "team": "platform",
                "environment": "production",
                "region": "us-east-1",
                "tags": {"cluster": "prod-cluster-1"},
            }
        }


class MetricEvent(UnifiedEvent):
    """Metric-specific event."""
    
    event_type: EventType = Field(default=EventType.METRIC, description="Event type")
    
    metric_name: str = Field(..., description="Metric name")
    current_value: float = Field(..., description="Current metric value")
    baseline_value: Optional[float] = Field(None, description="Baseline/expected value")
    unit: Optional[str] = Field(None, description="Metric unit")
    
    # Anomaly detection
    z_score: Optional[float] = Field(None, description="Statistical Z-score")
    is_anomaly: bool = Field(default=False, description="Anomaly detected")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "dynatrace",
                "timestamp": "2024-01-15T14:05:00Z",
                "severity": "critical",
                "entity_id": "HOST-ABCD1234",
                "entity_name": "web-server-01",
                "title": "CPU spike: 89%",
                "metric_name": "cpu.usage.percent",
                "current_value": 89.0,
                "baseline_value": 45.0,
                "unit": "percent",
                "z_score": 4.92,
                "is_anomaly": True,
            }
        }


class IncidentEvent(UnifiedEvent):
    """Incident-specific event."""
    
    event_type: EventType = Field(default=EventType.INCIDENT, description="Event type")
    
    incident_id: str = Field(..., description="Incident ID")
    state: str = Field(..., description="Incident state (open, resolved)")
    priority: Optional[str] = Field(None, description="Priority (P1-P5)")
    assigned_to: Optional[str] = Field(None, description="Assigned engineer")
    
    # Impact
    affected_services: Optional[List[str]] = Field(default_factory=list, description="Affected services")
    affected_users: Optional[int] = Field(None, description="Number of affected users")
    
    # Resolution
    resolution: Optional[str] = Field(None, description="Resolution notes")
    resolved_at: Optional[datetime] = Field(None, description="Resolution timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "servicenow",
                "timestamp": "2024-01-15T14:08:00Z",
                "severity": "critical",
                "title": "Auth service degraded performance",
                "incident_id": "INC0012345",
                "state": "open",
                "priority": "P1",
                "assigned_to": "engineer@example.com",
                "affected_services": ["auth-service", "api-gateway"],
                "affected_users": 5000,
            }
        }


class DeployEvent(UnifiedEvent):
    """Deployment event."""
    
    event_type: EventType = Field(default=EventType.DEPLOY, description="Event type")
    
    service: str = Field(..., description="Deployed service")
    version: str = Field(..., description="Version deployed")
    previous_version: Optional[str] = Field(None, description="Previous version")
    deployer: Optional[str] = Field(None, description="Who deployed")
    
    # Changes
    commit_sha: Optional[str] = Field(None, description="Git commit SHA")
    pull_request: Optional[str] = Field(None, description="Pull request number")
    changes: Optional[List[str]] = Field(default_factory=list, description="Change descriptions")
    
    # Deployment metadata
    deployment_id: Optional[str] = Field(None, description="Deployment ID")
    rollback: bool = Field(default=False, description="Is this a rollback")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "github",
                "timestamp": "2024-01-15T14:00:00Z",
                "severity": "info",
                "title": "Deployed auth-service v2.4.1",
                "service": "auth-service",
                "version": "v2.4.1",
                "previous_version": "v2.4.0",
                "deployer": "deploy-bot",
                "commit_sha": "abc123def456",
                "pull_request": "PR-789",
                "changes": ["Fix memory leak", "Update dependencies"],
            }
        }


class AlertEvent(UnifiedEvent):
    """ML prediction or alert event."""
    
    event_type: EventType = Field(default=EventType.ALERT, description="Event type")
    
    alert_type: str = Field(..., description="Alert type (cpu_exhaustion, anomaly, etc.)")
    confidence: float = Field(..., description="Confidence score (0.0-1.0)")
    
    # Prediction
    eta_minutes: Optional[int] = Field(None, description="Estimated time to threshold breach")
    predicted_value: Optional[float] = Field(None, description="Predicted value")
    threshold_value: Optional[float] = Field(None, description="Threshold value")
    
    # Explanation
    explanation: Optional[str] = Field(None, description="Human-readable explanation")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source": "sdf-ml",
                "timestamp": "2024-01-15T14:07:00Z",
                "severity": "warning",
                "title": "CPU exhaustion predicted",
                "alert_type": "cpu_exhaustion",
                "confidence": 0.89,
                "eta_minutes": 6,
                "predicted_value": 100.0,
                "threshold_value": 95.0,
                "explanation": "CPU usage trending upward, will reach 100% in ~6 minutes",
            }
        }
