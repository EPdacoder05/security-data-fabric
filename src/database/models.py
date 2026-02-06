"""
SQLAlchemy ORM models for Security Data Fabric.
All models with UUID PKs, timestamps, and proper indexes.
"""
from datetime import datetime
from typing import Optional
from uuid import uuid4
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON, ForeignKey, Index, Enum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship
from pgvector.sqlalchemy import Vector
import enum


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class EventSeverity(str, enum.Enum):
    """Event severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EXTREME = "extreme"


class EventState(str, enum.Enum):
    """Event/Incident state."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"


class PredictionType(str, enum.Enum):
    """ML prediction types."""
    CPU_EXHAUSTION = "cpu_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    DISK_FULL = "disk_full"
    ERROR_RATE_SPIKE = "error_rate_spike"
    ANOMALY = "anomaly"


class RawEvent(Base):
    """Bronze layer: raw events from any source."""
    __tablename__ = "raw_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    source = Column(String(100), nullable=False, index=True)  # dynatrace, splunk, etc.
    source_id = Column(String(255), nullable=True, index=True)  # Original event ID from source
    event_type = Column(String(100), nullable=False, index=True)
    raw_data = Column(JSON, nullable=False)
    schema_version = Column(String(20), nullable=False, default="1.0")
    ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_raw_events_source_ingested", "source", "ingested_at"),
        Index("idx_raw_events_type_ingested", "event_type", "ingested_at"),
    )


class NormalizedEvent(Base):
    """Silver layer: normalized unified events."""
    __tablename__ = "normalized_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    raw_event_id = Column(UUID(as_uuid=True), ForeignKey("raw_events.id"), nullable=False)
    
    # Core fields
    source = Column(String(100), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(Enum(EventSeverity), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    
    # Entity information
    entity_id = Column(String(255), nullable=True, index=True)
    entity_type = Column(String(100), nullable=True)  # host, service, pod, etc.
    entity_name = Column(String(255), nullable=True)
    
    # Content
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Enrichment fields
    service_name = Column(String(255), nullable=True, index=True)
    team = Column(String(100), nullable=True)
    environment = Column(String(50), nullable=True)
    region = Column(String(50), nullable=True)
    
    # Metadata
    tags = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    content_hash = Column(String(64), nullable=False, index=True)  # For deduplication
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    raw_event = relationship("RawEvent", backref="normalized_events")
    
    __table_args__ = (
        Index("idx_normalized_severity_timestamp", "severity", "timestamp"),
        Index("idx_normalized_entity_timestamp", "entity_id", "timestamp"),
        Index("idx_normalized_service_timestamp", "service_name", "timestamp"),
    )


class Incident(Base):
    """Gold layer: tracked incidents."""
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_number = Column(String(50), unique=True, nullable=False, index=True)
    
    # Core fields
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(EventSeverity), nullable=False, index=True)
    state = Column(Enum(EventState), nullable=False, default=EventState.OPEN, index=True)
    
    # Attribution
    service_name = Column(String(255), nullable=True, index=True)
    team = Column(String(100), nullable=True)
    assigned_to = Column(String(255), nullable=True)
    
    # Timing
    detected_at = Column(DateTime, nullable=False, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Analysis
    root_cause = Column(Text, nullable=True)
    root_cause_confidence = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)
    
    # Impact
    affected_users = Column(Integer, nullable=True)
    sla_breached = Column(Boolean, default=False)
    
    # External references
    external_ticket_id = Column(String(100), nullable=True)  # ServiceNow, Jira, etc.
    external_ticket_url = Column(String(500), nullable=True)
    
    # Metadata
    tags = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_incidents_state_severity", "state", "severity"),
        Index("idx_incidents_service_detected", "service_name", "detected_at"),
    )


class Correlation(Base):
    """Gold layer: event correlations."""
    __tablename__ = "correlations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    
    # Correlated events
    event_ids = Column(JSON, nullable=False)  # List of normalized_event IDs
    
    # Correlation metadata
    correlation_type = Column(String(100), nullable=False)  # time-based, entity-based, causal
    confidence_score = Column(Float, nullable=False)
    time_window_seconds = Column(Integer, nullable=True)
    
    # Analysis
    summary = Column(Text, nullable=True)
    causal_chain = Column(JSON, nullable=True)  # Ordered list showing cause → effect
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", backref="correlations")
    
    __table_args__ = (
        Index("idx_correlations_incident", "incident_id"),
        Index("idx_correlations_type", "correlation_type"),
    )


class Prediction(Base):
    """ML predictions."""
    __tablename__ = "predictions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Prediction details
    prediction_type = Column(Enum(PredictionType), nullable=False, index=True)
    entity_id = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False)
    entity_name = Column(String(255), nullable=True)
    
    # Values
    current_value = Column(Float, nullable=False)
    predicted_value = Column(Float, nullable=True)
    threshold_value = Column(Float, nullable=True)
    
    # Timing
    predicted_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    eta_minutes = Column(Integer, nullable=True)  # Time until threshold breach
    
    # Confidence
    confidence_score = Column(Float, nullable=False)
    z_score = Column(Float, nullable=True)
    
    # Analysis
    explanation = Column(Text, nullable=True)
    anomaly_detected = Column(Boolean, default=False)
    
    # State
    is_active = Column(Boolean, default=True, index=True)
    resolved_at = Column(DateTime, nullable=True)
    was_accurate = Column(Boolean, nullable=True)  # Post-mortem accuracy
    
    # Metadata
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_predictions_active_type", "is_active", "prediction_type"),
        Index("idx_predictions_entity_predicted", "entity_id", "predicted_at"),
    )


class Embedding(Base):
    """pgvector embeddings for semantic search."""
    __tablename__ = "embeddings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Source reference
    source_type = Column(String(100), nullable=False, index=True)  # incident, event, alert
    source_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    
    # Text content
    text_content = Column(Text, nullable=False)
    text_hash = Column(String(64), nullable=False, index=True)  # For dedup
    
    # Embedding vector (384 dimensions for all-MiniLM-L6-v2)
    embedding = Column(Vector(384), nullable=False)
    
    # Metadata
    model_version = Column(String(100), nullable=False)
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_embeddings_source", "source_type", "source_id"),
        Index("idx_embeddings_hash", "text_hash"),
    )


class AlertHistory(Base):
    """Alert notification history."""
    __tablename__ = "alert_history"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Alert details
    alert_type = Column(String(100), nullable=False, index=True)
    severity = Column(Enum(EventSeverity), nullable=False)
    
    # Related entity
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    prediction_id = Column(UUID(as_uuid=True), ForeignKey("predictions.id"), nullable=True)
    
    # Routing
    channel = Column(String(50), nullable=False)  # slack, pagerduty, servicenow
    recipient = Column(String(255), nullable=True)
    
    # Content
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    
    # Status
    sent_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    delivered = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    
    # Deduplication
    dedup_key = Column(String(255), nullable=True, index=True)
    
    # External reference
    external_id = Column(String(255), nullable=True)
    
    # Metadata
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", backref="alerts")
    prediction = relationship("Prediction", backref="alerts")
    
    __table_args__ = (
        Index("idx_alert_history_channel_sent", "channel", "sent_at"),
        Index("idx_alert_history_dedup", "dedup_key"),
    )


class AuditLog(Base):
    """System audit trail."""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)
    actor = Column(String(255), nullable=True)  # API key, user, system
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=True)
    
    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    request_id = Column(String(100), nullable=True, index=True)
    
    # Data
    details = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index("idx_audit_logs_action_created", "action", "created_at"),
        Index("idx_audit_logs_resource", "resource_type", "resource_id"),
    )
