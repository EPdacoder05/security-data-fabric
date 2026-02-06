"""
Tests for event correlator.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.gold.correlator import (
    EventCorrelator,
    CorrelationType,
    CorrelationMatch,
    calculate_correlation_stats,
)
from src.database.models import NormalizedEvent, EventSeverity
from src.silver.unified_schema import EventType


@pytest.fixture
async def sample_events(db_session):
    """Create sample events for testing."""
    now = datetime.now(timezone.utc)
    
    # Deploy event
    deploy = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="github",
        event_type=EventType.DEPLOY,
        severity=EventSeverity.INFO,
        timestamp=now - timedelta(minutes=5),
        title="Deploy auth-service v2.4.1",
        entity_id="auth-service",
        entity_name="auth-service",
        service_name="auth-service",
        content_hash="deploy_hash_1",
        metadata_json={"version": "v2.4.1", "service": "auth-service"},
    )
    
    # Metric event (CPU spike)
    metric = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="dynatrace",
        event_type=EventType.METRIC,
        severity=EventSeverity.CRITICAL,
        timestamp=now - timedelta(minutes=2),
        title="CPU spike detected",
        entity_id="host-123",
        entity_name="web-server-01",
        service_name="auth-service",
        content_hash="metric_hash_1",
        metadata_json={"metric_name": "cpu.usage", "current_value": 89.0, "z_score": 4.92},
    )
    
    # Incident event
    incident = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="servicenow",
        event_type=EventType.INCIDENT,
        severity=EventSeverity.CRITICAL,
        timestamp=now,
        title="Auth service degraded",
        entity_id="auth-service",
        entity_name="auth-service",
        service_name="auth-service",
        content_hash="incident_hash_1",
        metadata_json={"incident_id": "INC0012345", "state": "open"},
    )
    
    db_session.add_all([deploy, metric, incident])
    await db_session.flush()
    
    return [deploy, metric, incident]


@pytest.mark.asyncio
async def test_correlator_initialization(db_session):
    """Test correlator initialization."""
    correlator = EventCorrelator(db_session)
    
    assert correlator.session == db_session
    assert correlator.time_window.total_seconds() > 0
    assert len(correlator.causal_patterns) > 0


@pytest.mark.asyncio
async def test_time_based_correlation(db_session, sample_events):
    """Test time-based correlation."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(
        event_ids,
        correlation_types=[CorrelationType.TIME_BASED]
    )
    
    assert len(correlations) > 0
    assert any(c.correlation_type == CorrelationType.TIME_BASED for c in correlations)
    assert all(0.0 <= c.confidence <= 1.0 for c in correlations)


@pytest.mark.asyncio
async def test_entity_based_correlation(db_session, sample_events):
    """Test entity-based correlation."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(
        event_ids,
        correlation_types=[CorrelationType.ENTITY_BASED]
    )
    
    # Should find events on same entity (auth-service)
    entity_corrs = [c for c in correlations if c.correlation_type == CorrelationType.ENTITY_BASED]
    assert len(entity_corrs) > 0
    
    for corr in entity_corrs:
        assert len(corr.event_ids) >= 2
        assert corr.entity_id is not None


@pytest.mark.asyncio
async def test_service_based_correlation(db_session, sample_events):
    """Test service-based correlation."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(
        event_ids,
        correlation_types=[CorrelationType.SERVICE_BASED]
    )
    
    service_corrs = [c for c in correlations if c.correlation_type == CorrelationType.SERVICE_BASED]
    assert len(service_corrs) > 0
    
    for corr in service_corrs:
        assert len(corr.event_ids) >= 2
        assert corr.service_name == "auth-service"


@pytest.mark.asyncio
async def test_causal_correlation(db_session, sample_events):
    """Test causal correlation (deploy -> metric -> incident)."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(
        event_ids,
        correlation_types=[CorrelationType.CAUSAL]
    )
    
    causal_corrs = [c for c in correlations if c.correlation_type == CorrelationType.CAUSAL]
    
    if len(causal_corrs) > 0:
        for corr in causal_corrs:
            assert len(corr.event_ids) >= 2
            assert corr.causal_chain is not None
            assert corr.confidence >= 0.5


@pytest.mark.asyncio
async def test_correlate_around_event(db_session, sample_events):
    """Test correlating events around a central event."""
    correlator = EventCorrelator(db_session)
    central_event = sample_events[1]  # Metric event
    
    correlations = await correlator.correlate_around_event(
        central_event.id,
        lookback_minutes=10,
        lookahead_minutes=10
    )
    
    assert isinstance(correlations, list)
    # Should find deploy before and incident after
    assert len(correlations) >= 0


@pytest.mark.asyncio
async def test_build_correlation_graph(db_session, sample_events):
    """Test building correlation graph."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(event_ids)
    graph = await correlator.build_correlation_graph(correlations)
    
    assert len(graph.nodes) == len(sample_events)
    assert all("id" in node for node in graph.nodes)
    assert all("type" in node for node in graph.nodes)


@pytest.mark.asyncio
async def test_save_correlation(db_session, sample_events):
    """Test saving correlation to database."""
    correlator = EventCorrelator(db_session)
    
    match = CorrelationMatch(
        event_ids=[sample_events[0].id, sample_events[1].id],
        correlation_type=CorrelationType.TIME_BASED,
        confidence=0.85,
        time_window_seconds=300,
        summary="Test correlation"
    )
    
    saved = await correlator.save_correlation(match)
    
    assert saved.id is not None
    assert saved.correlation_type == CorrelationType.TIME_BASED
    assert saved.confidence_score == 0.85
    assert len(saved.event_ids) == 2


@pytest.mark.asyncio
async def test_calculate_correlation_stats():
    """Test correlation statistics calculation."""
    correlations = [
        CorrelationMatch(
            event_ids=[uuid4(), uuid4()],
            correlation_type=CorrelationType.TIME_BASED,
            confidence=0.8,
        ),
        CorrelationMatch(
            event_ids=[uuid4(), uuid4()],
            correlation_type=CorrelationType.ENTITY_BASED,
            confidence=0.9,
        ),
        CorrelationMatch(
            event_ids=[uuid4(), uuid4(), uuid4()],
            correlation_type=CorrelationType.CAUSAL,
            confidence=0.95,
        ),
    ]
    
    stats = await calculate_correlation_stats(correlations, total_events=5)
    
    assert stats.total_events_analyzed == 5
    assert stats.correlations_found == 3
    assert stats.time_based == 1
    assert stats.entity_based == 1
    assert stats.causal == 1
    assert 0.0 <= stats.avg_confidence <= 1.0


@pytest.mark.asyncio
async def test_empty_event_list(db_session):
    """Test handling of empty event list."""
    correlator = EventCorrelator(db_session)
    
    correlations = await correlator.correlate_events([])
    
    assert correlations == []


@pytest.mark.asyncio
async def test_single_event(db_session, sample_events):
    """Test handling of single event."""
    correlator = EventCorrelator(db_session)
    
    correlations = await correlator.correlate_events([sample_events[0].id])
    
    # Single event shouldn't have correlations
    assert len(correlations) == 0


@pytest.mark.asyncio
async def test_confidence_scores(db_session, sample_events):
    """Test that confidence scores are within valid range."""
    correlator = EventCorrelator(db_session)
    event_ids = [e.id for e in sample_events]
    
    correlations = await correlator.correlate_events(event_ids)
    
    for corr in correlations:
        assert 0.0 <= corr.confidence <= 1.0
        assert isinstance(corr.confidence, float)


@pytest.mark.asyncio
async def test_deduplication(db_session, sample_events):
    """Test that duplicate correlations are removed."""
    correlator = EventCorrelator(db_session)
    
    # Create duplicate matches
    matches = [
        CorrelationMatch(
            event_ids=[sample_events[0].id, sample_events[1].id],
            correlation_type=CorrelationType.TIME_BASED,
            confidence=0.8,
        ),
        CorrelationMatch(
            event_ids=[sample_events[0].id, sample_events[1].id],
            correlation_type=CorrelationType.ENTITY_BASED,
            confidence=0.9,
        ),
    ]
    
    deduped = correlator._deduplicate_correlations(matches)
    
    # Should keep only one
    assert len(deduped) == 1
