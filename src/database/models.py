"""SQLAlchemy models for Security Data Fabric."""

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

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
    """Silver layer: Normalized and cleaned events."""

    __tablename__ = "normalized_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_event_id = Column(UUID(as_uuid=True), ForeignKey("raw_events.id"), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)
    severity = Column(Integer, nullable=False, index=True)  # 1-5 scale
    title = Column(String(500), nullable=False)
    description = Column(Text)
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
    target_timestamp = Column(DateTime, nullable=False, index=True)
    predicted_value = Column(Float, nullable=False)
    confidence_score = Column(Float)
    model_version = Column(String(50))
    features = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_predictions_type_timestamp", "prediction_type", "target_timestamp"),
    )


class EventEmbedding(Base):
    """Vector embeddings for semantic search."""

    __tablename__ = "embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("normalized_events.id"), nullable=False)
    embedding: Vector = Column(Vector(384), nullable=False)  # type: ignore[assignment]
    model_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    normalized_event = relationship("NormalizedEvent", backref="embeddings")

    __table_args__ = (
        Index(
            "idx_embeddings_vector",
            "embedding",
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


class Alert(Base):
    """Alert tracking and deduplication."""

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(Integer, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    source_event_id = Column(UUID(as_uuid=True), ForeignKey("normalized_events.id"))
    sent_to = Column(JSON)  # List of destinations
    dedupe_key = Column(String(255), index=True)
    last_sent_at = Column(DateTime)
    send_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (Index("idx_alerts_dedupe", "dedupe_key", "last_sent_at"),)


class IncidentTimeline(Base):
    """Correlated incident timelines."""

    __tablename__ = "incident_timelines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String(100), nullable=False, index=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("normalized_events.id"))
    event_type = Column(String(50), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    description = Column(Text)
    correlation_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("idx_timeline_incident_timestamp", "incident_id", "timestamp"),)


class AuditLog(Base):
    """Audit log for compliance (7-year retention)."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), index=True)
    action = Column(String(50), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255))
    changes = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_id = Column(UUID(as_uuid=True), index=True)

    __table_args__ = (
        Index("idx_audit_user_timestamp", "user_id", "timestamp"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
    )


class MFAToken(Base):
    """MFA token tracking."""

    __tablename__ = "mfa_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    token_type: SQLEnum = Column(  # type: ignore[assignment]
        SQLEnum("totp", "sms", "email", "push", "webauthn", name="mfa_token_type"),
        nullable=False,
    )
    secret = Column(String(255))  # Encrypted TOTP secret
    phone_number = Column(String(20))  # For SMS
    email = Column(String(255))  # For email
    device_id = Column(String(255))  # For push/webauthn
    verified = Column(Boolean, default=False)
    last_used_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("idx_mfa_user_type", "user_id", "token_type"),)


class RefreshToken(Base):
    """Refresh token rotation tracking."""

    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked = Column(Boolean, default=False, index=True)
    replaced_by = Column(UUID(as_uuid=True), ForeignKey("refresh_tokens.id"))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("idx_refresh_token_user_revoked", "user_id", "revoked"),)


class Anomaly(Base):
    """Detected anomalies from ML."""

    __tablename__ = "anomalies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("normalized_events.id"))
    anomaly_score = Column(Float, nullable=False, index=True)
    anomaly_type = Column(String(50), nullable=False)
    anomaly_reason = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = Column(Integer, nullable=False)

    __table_args__ = (Index("idx_anomaly_score_time", "anomaly_score", "detected_at"),)


class SLATracking(Base):
    """SLA tracking for incidents."""

    __tablename__ = "sla_tracking"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String(100), nullable=False, index=True)
    severity = Column(Integer, nullable=False)
    target_response_minutes = Column(Integer, nullable=False)
    actual_response_minutes = Column(Integer)
    sla_met = Column(Boolean)
    breached_at = Column(DateTime, index=True)
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("idx_sla_incident_sla_met", "incident_id", "sla_met"),)
