"""SQLAlchemy models for Security Data Fabric."""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from pgvector.sqlalchemy import Vector

from src.database.connection import Base


class RawEvent(Base):
    """Bronze layer: Raw ingested events."""

    __tablename__ = "raw_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(50), nullable=False, index=True)
    source_id = Column(String(255), nullable=False)
    raw_data = Column(JSON, nullable=False)
    ingested_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    processed = Column(Boolean, default=False, nullable=False, index=True)

    __table_args__ = (
        Index("idx_raw_events_source_processed", "source", "processed"),
        Index("idx_raw_events_source_id", "source", "source_id", unique=True),
    )


class NormalizedEvent(Base):
    """Silver layer: Normalized and cleaned events.
    
    Note: The 'metadata' JSON field is stored in the database as 'event_metadata'
    to avoid conflicts with SQLAlchemy's reserved 'metadata' attribute. The Column
    key parameter maps the database column to the 'metadata' Python attribute.
    """

    __tablename__ = "normalized_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_event_id = Column(UUID(as_uuid=True), ForeignKey("raw_events.id"), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)
    severity = Column(Integer, nullable=False, index=True)  # 1-5 scale
    title = Column(String(500), nullable=False)
    description = Column(Text)
    # Column named 'event_metadata' in DB but mapped to 'metadata' attribute
    # to avoid SQLAlchemy's reserved 'metadata' attribute on Base class
    event_metadata = Column("event_metadata", JSON, key="metadata")
    content_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    raw_event = relationship("RawEvent", backref="normalized_events")

    __table_args__ = (
        Index("idx_normalized_events_type_severity", "event_type", "severity"),
        Index("idx_normalized_events_timestamp", "timestamp"),
    )


class EnrichedEvent(Base):
    """Gold layer: Enriched and correlated events."""

    __tablename__ = "enriched_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    normalized_event_id = Column(
        UUID(as_uuid=True), ForeignKey("normalized_events.id"), nullable=False
    )
    risk_score = Column(Float)
    tags = Column(JSON)
    correlations = Column(JSON)
    root_cause_analysis = Column(JSON)
    incident_id = Column(String(100), index=True)
    enriched_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    normalized_event = relationship("NormalizedEvent", backref="enriched_events")

    __table_args__ = (Index("idx_enriched_events_incident", "incident_id"),)


class Prediction(Base):
    """ML predictions and forecasts."""

    __tablename__ = "predictions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prediction_type = Column(String(50), nullable=False, index=True)
    target_metric = Column(String(100), nullable=False)
    current_value = Column(Float, nullable=False)
    predicted_value = Column(Float)
    threshold_value = Column(Float)
    time_to_breach = Column(Integer)  # Minutes
    confidence = Column(Float, nullable=False)
    severity = Column(Integer, nullable=False, index=True)
    details = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, index=True)
    resolved = Column(Boolean, default=False, nullable=False, index=True)

    __table_args__ = (
        Index("idx_predictions_active", "resolved", "expires_at"),
        Index("idx_predictions_type_severity", "prediction_type", "severity"),
    )


class Embedding(Base):
    """Vector embeddings for semantic search."""

    __tablename__ = "embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("enriched_events.id"), nullable=False)
    embedding = Column(Vector(384))  # MiniLM-L6-v2 dimension
    text_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    event = relationship("EnrichedEvent", backref="embeddings")

    __table_args__ = (Index("idx_embeddings_vector", "embedding", postgresql_using="ivfflat"),)


class Alert(Base):
    """Generated alerts."""

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(Integer, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    event_id = Column(UUID(as_uuid=True), ForeignKey("enriched_events.id"))
    prediction_id = Column(UUID(as_uuid=True), ForeignKey("predictions.id"))
    status = Column(String(20), default="open", nullable=False, index=True)
    destinations = Column(JSON)  # List of where alert was sent
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)

    event = relationship("EnrichedEvent", backref="alerts")
    prediction = relationship("Prediction", backref="alerts")

    __table_args__ = (
        Index("idx_alerts_status_severity", "status", "severity"),
        Index("idx_alerts_created", "created_at"),
    )


class IncidentTimeline(Base):
    """Reconstructed incident timelines."""

    __tablename__ = "incident_timelines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String(100), nullable=False, unique=True, index=True)
    title = Column(String(500), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    events = Column(JSON, nullable=False)  # List of timeline entries
    root_cause = Column(JSON)
    impact = Column(Text)
    resolution = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (Index("idx_incident_timelines_start", "start_time"),)
