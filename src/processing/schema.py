"""Pydantic schemas for security events."""
from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID
from pydantic import BaseModel, Field


class RawEventSchema(BaseModel):
    """Bronze layer: Raw event schema."""

    source: str = Field(..., description="Data source name")
    source_id: str = Field(..., description="Source-specific event ID")
    raw_data: Dict[str, Any] = Field(..., description="Raw event data")


class NormalizedEventSchema(BaseModel):
    """Silver layer: Normalized event schema."""

    id: Optional[UUID] = None
    event_type: str = Field(..., description="Normalized event type")
    timestamp: datetime = Field(..., description="Event timestamp (UTC)")
    source: str = Field(..., description="Data source name")
    severity: int = Field(..., ge=1, le=5, description="Severity level (1-5)")
    title: str = Field(..., max_length=500, description="Event title")
    description: Optional[str] = Field(None, description="Event description")
    event_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        from_attributes = True


class EnrichedEventSchema(BaseModel):
    """Gold layer: Enriched event schema."""

    id: Optional[UUID] = None
    normalized_event_id: UUID
    risk_score: Optional[float] = Field(None, ge=0, le=100, description="Risk score (0-100)")
    tags: List[str] = Field(default_factory=list, description="Event tags")
    correlations: List[Dict[str, Any]] = Field(
        default_factory=list, description="Correlated events"
    )
    root_cause_analysis: Optional[Dict[str, Any]] = Field(
        None, description="Root cause analysis"
    )
    incident_id: Optional[str] = Field(None, description="Associated incident ID")

    class Config:
        from_attributes = True


class PredictionSchema(BaseModel):
    """ML prediction schema."""

    id: Optional[UUID] = None
    prediction_type: str = Field(..., description="Type of prediction")
    target_metric: str = Field(..., description="Target metric name")
    current_value: float = Field(..., description="Current metric value")
    predicted_value: Optional[float] = Field(None, description="Predicted future value")
    threshold_value: Optional[float] = Field(None, description="Threshold value")
    time_to_breach: Optional[int] = Field(None, description="Minutes until threshold breach")
    confidence: float = Field(..., ge=0, le=1, description="Prediction confidence (0-1)")
    severity: int = Field(..., ge=1, le=5, description="Severity level (1-5)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")

    class Config:
        from_attributes = True


class AlertSchema(BaseModel):
    """Alert schema."""

    id: Optional[UUID] = None
    alert_type: str = Field(..., description="Type of alert")
    severity: int = Field(..., ge=1, le=5, description="Severity level (1-5)")
    title: str = Field(..., max_length=500, description="Alert title")
    description: Optional[str] = Field(None, description="Alert description")
    event_id: Optional[UUID] = Field(None, description="Associated event ID")
    prediction_id: Optional[UUID] = Field(None, description="Associated prediction ID")
    status: str = Field(default="open", description="Alert status")
    destinations: List[str] = Field(
        default_factory=list, description="Alert delivery destinations"
    )

    class Config:
        from_attributes = True


class IncidentTimelineSchema(BaseModel):
    """Incident timeline schema."""

    id: Optional[UUID] = None
    incident_id: str = Field(..., description="Incident identifier")
    title: str = Field(..., max_length=500, description="Incident title")
    start_time: datetime = Field(..., description="Incident start time")
    end_time: Optional[datetime] = Field(None, description="Incident end time")
    events: List[Dict[str, Any]] = Field(..., description="Timeline events")
    root_cause: Optional[Dict[str, Any]] = Field(None, description="Root cause analysis")
    impact: Optional[str] = Field(None, description="Incident impact")
    resolution: Optional[str] = Field(None, description="Resolution details")

    class Config:
        from_attributes = True


class TimelineEntry(BaseModel):
    """Single timeline entry."""

    timestamp: datetime
    event_type: str
    source: str
    description: str
    severity: int
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SearchQuery(BaseModel):
    """Semantic search query."""

    query: str = Field(..., min_length=1, description="Search query text")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum results")
    min_similarity: float = Field(default=0.5, ge=0, le=1, description="Minimum similarity score")
    boost_recent: bool = Field(default=True, description="Boost recent events in ranking")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Additional filters")


class SearchResult(BaseModel):
    """Search result item."""

    event_id: UUID
    score: float
    title: str
    description: Optional[str]
    timestamp: datetime
    source: str
    severity: int
    metadata: Dict[str, Any]
