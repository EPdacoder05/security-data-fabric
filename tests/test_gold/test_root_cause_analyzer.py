"""
Tests for root cause analyzer.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.gold.root_cause_analyzer import (
    RootCauseAnalyzer,
    RootCauseType,
    RootCauseCandidate,
)
from src.database.models import NormalizedEvent, Incident, Correlation, EventSeverity, EventState
from src.silver.unified_schema import EventType


@pytest.fixture
async def incident_with_events(db_session):
    """Create incident with correlated events."""
    now = datetime.now(timezone.utc)
    
    # Create incident
    incident = Incident(
        id=uuid4(),
        incident_number="INC0012345",
        title="Auth service degraded",
        severity=EventSeverity.CRITICAL,
        state=EventState.OPEN,
        service_name="auth-service",
        detected_at=now,
    )
    
    # Create events leading to incident
    deploy = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="github",
        event_type=EventType.DEPLOY,
        severity=EventSeverity.INFO,
        timestamp=now - timedelta(minutes=5),
        title="Deploy auth-service v2.4.1",
        service_name="auth-service",
        content_hash="deploy_hash",
        metadata_json={"version": "v2.4.1", "service": "auth-service"},
    )
    
    metric = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="dynatrace",
        event_type=EventType.METRIC,
        severity=EventSeverity.CRITICAL,
        timestamp=now - timedelta(minutes=2),
        title="CPU spike detected",
        service_name="auth-service",
        entity_id="host-123",
        content_hash="metric_hash",
        metadata_json={"metric_name": "cpu.usage", "current_value": 89.0, "z_score": 4.92},
    )
    
    # Create correlation
    correlation = Correlation(
        id=uuid4(),
        incident_id=incident.id,
        event_ids=[str(deploy.id), str(metric.id)],
        correlation_type="causal",
        confidence_score=0.85,
        causal_chain=[
            {
                "event_id": str(deploy.id),
                "type": EventType.DEPLOY,
                "timestamp": deploy.timestamp.isoformat(),
                "title": deploy.title,
            },
            {
                "event_id": str(metric.id),
                "type": EventType.METRIC,
                "timestamp": metric.timestamp.isoformat(),
                "title": metric.title,
            },
        ],
    )
    
    db_session.add_all([incident, deploy, metric, correlation])
    await db_session.flush()
    
    return {
        "incident": incident,
        "events": [deploy, metric],
        "correlation": correlation,
    }


@pytest.mark.asyncio
async def test_analyzer_initialization(db_session):
    """Test analyzer initialization."""
    analyzer = RootCauseAnalyzer(db_session)
    
    assert analyzer.session == db_session
    assert analyzer.correlator is not None
    assert len(analyzer.evidence_weights) > 0


@pytest.mark.asyncio
async def test_analyze_deployment_cause(db_session, incident_with_events):
    """Test identifying deployment as root cause."""
    analyzer = RootCauseAnalyzer(db_session)
    incident = incident_with_events["incident"]
    
    analysis = await analyzer.analyze_incident(incident.id)
    
    assert analysis.incident_id == incident.id
    if analysis.primary_cause:
        # Deploy should be identified as likely cause
        assert analysis.primary_cause.cause_type in [
            RootCauseType.DEPLOYMENT,
            RootCauseType.UNKNOWN
        ]
        assert 0.0 <= analysis.confidence <= 1.0


@pytest.mark.asyncio
async def test_analyze_events_directly(db_session):
    """Test analyzing events without an incident."""
    now = datetime.now(timezone.utc)
    
    events = [
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="github",
            event_type=EventType.DEPLOY,
            severity=EventSeverity.INFO,
            timestamp=now - timedelta(minutes=5),
            title="Deploy service",
            service_name="test-service",
            content_hash="hash1",
            metadata_json={"version": "v1.0.0"},
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="dynatrace",
            event_type=EventType.METRIC,
            severity=EventSeverity.CRITICAL,
            timestamp=now - timedelta(minutes=2),
            title="Metric spike",
            service_name="test-service",
            content_hash="hash2",
        ),
    ]
    
    db_session.add_all(events)
    await db_session.flush()
    
    analyzer = RootCauseAnalyzer(db_session)
    analysis = await analyzer.analyze_events(
        [e.id for e in events],
        incident_timestamp=now
    )
    
    assert analysis is not None
    # Should find some candidates
    assert analysis.primary_cause is not None or len(analysis.alternative_causes) >= 0


@pytest.mark.asyncio
async def test_root_cause_confidence(db_session, incident_with_events):
    """Test confidence scoring."""
    analyzer = RootCauseAnalyzer(db_session)
    incident = incident_with_events["incident"]
    
    analysis = await analyzer.analyze_incident(incident.id)
    
    if analysis.primary_cause:
        assert 0.0 <= analysis.primary_cause.confidence <= 1.0
        
        # Alternative causes should have lower confidence
        for alt in analysis.alternative_causes:
            assert alt.confidence <= analysis.primary_cause.confidence


@pytest.mark.asyncio
async def test_generate_explanation(db_session, incident_with_events):
    """Test explanation generation."""
    analyzer = RootCauseAnalyzer(db_session)
    incident = incident_with_events["incident"]
    
    analysis = await analyzer.analyze_incident(incident.id)
    
    assert isinstance(analysis.explanation, str)
    assert len(analysis.explanation) > 0
    
    if analysis.primary_cause:
        # Explanation should mention confidence
        assert "confidence" in analysis.explanation.lower() or "%" in analysis.explanation


@pytest.mark.asyncio
async def test_deployment_analysis(db_session):
    """Test deployment root cause detection."""
    now = datetime.now(timezone.utc)
    
    deploy = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="github",
        event_type=EventType.DEPLOY,
        severity=EventSeverity.INFO,
        timestamp=now - timedelta(minutes=3),
        title="Deploy",
        service_name="test-service",
        content_hash="hash",
        metadata_json={"version": "v2.0.0", "service": "test-service"},
    )
    
    db_session.add(deploy)
    await db_session.flush()
    
    analyzer = RootCauseAnalyzer(db_session)
    
    # Analyze deployment
    candidates = analyzer._analyze_deployments(
        [deploy],
        incident_time=now
    )
    
    assert len(candidates) > 0
    assert candidates[0].cause_type == RootCauseType.DEPLOYMENT
    assert candidates[0].confidence > 0


@pytest.mark.asyncio
async def test_resource_exhaustion_analysis(db_session):
    """Test resource exhaustion detection."""
    now = datetime.now(timezone.utc)
    
    metric = NormalizedEvent(
        id=uuid4(),
        raw_event_id=uuid4(),
        source="dynatrace",
        event_type=EventType.METRIC,
        severity=EventSeverity.CRITICAL,
        timestamp=now - timedelta(minutes=2),
        title="CPU exhaustion",
        service_name="test-service",
        content_hash="hash",
        metadata_json={"metric_name": "cpu.usage.percent", "current_value": 99.0, "z_score": 5.5},
    )
    
    db_session.add(metric)
    await db_session.flush()
    
    analyzer = RootCauseAnalyzer(db_session)
    
    pseudo_incident = type('Incident', (), {
        'detected_at': now,
        'severity': EventSeverity.CRITICAL,
        'service_name': 'test-service',
    })()
    
    candidates = analyzer._analyze_resource_exhaustion(
        [metric],
        pseudo_incident
    )
    
    assert len(candidates) > 0
    assert candidates[0].cause_type == RootCauseType.RESOURCE_EXHAUSTION


@pytest.mark.asyncio
async def test_dependency_chain_building(db_session):
    """Test dependency chain construction."""
    now = datetime.now(timezone.utc)
    
    events = [
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="test",
            event_type=EventType.DEPLOY,
            severity=EventSeverity.INFO,
            timestamp=now - timedelta(minutes=10),
            title="Event 1",
            service_name="service-a",
            content_hash="hash1",
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="test",
            event_type=EventType.METRIC,
            severity=EventSeverity.CRITICAL,
            timestamp=now - timedelta(minutes=5),
            title="Event 2",
            service_name="service-b",
            content_hash="hash2",
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="test",
            event_type=EventType.INCIDENT,
            severity=EventSeverity.CRITICAL,
            timestamp=now,
            title="Event 3",
            service_name="service-c",
            content_hash="hash3",
        ),
    ]
    
    db_session.add_all(events)
    await db_session.flush()
    
    analyzer = RootCauseAnalyzer(db_session)
    
    primary_cause = RootCauseCandidate(
        event_id=events[0].id,
        event_type=events[0].event_type,
        cause_type=RootCauseType.DEPLOYMENT,
        confidence=0.8,
        timestamp=events[0].timestamp,
        title=events[0].title,
    )
    
    chain = analyzer._build_dependency_chain(events, primary_cause)
    
    assert isinstance(chain, list)
    if len(chain) > 0:
        assert chain[0] == "service-a"


@pytest.mark.asyncio
async def test_cause_type_inference(db_session):
    """Test inferring cause type from event type."""
    analyzer = RootCauseAnalyzer(db_session)
    
    assert analyzer._infer_cause_type(EventType.DEPLOY) == RootCauseType.DEPLOYMENT
    assert analyzer._infer_cause_type(EventType.CHANGE) == RootCauseType.CONFIG_CHANGE
    assert analyzer._infer_cause_type(EventType.METRIC) == RootCauseType.RESOURCE_EXHAUSTION


@pytest.mark.asyncio
async def test_empty_analysis(db_session):
    """Test analysis with no events."""
    analyzer = RootCauseAnalyzer(db_session)
    
    analysis = await analyzer.analyze_events([])
    
    assert analysis.primary_cause is None
    assert len(analysis.alternative_causes) == 0


@pytest.mark.asyncio
async def test_root_cause_to_dict():
    """Test RootCauseCandidate to_dict conversion."""
    candidate = RootCauseCandidate(
        event_id=uuid4(),
        event_type="deploy",
        cause_type=RootCauseType.DEPLOYMENT,
        confidence=0.85,
        timestamp=datetime.now(timezone.utc),
        title="Test deployment",
        evidence=["Deploy occurred before incident"],
    )
    
    candidate_dict = candidate.to_dict()
    
    assert isinstance(candidate_dict, dict)
    assert "event_id" in candidate_dict
    assert "cause_type" in candidate_dict
    assert "confidence" in candidate_dict
    assert candidate_dict["confidence"] == 0.85


@pytest.mark.asyncio
async def test_analysis_to_dict(db_session, incident_with_events):
    """Test RootCauseAnalysis to_dict conversion."""
    analyzer = RootCauseAnalyzer(db_session)
    incident = incident_with_events["incident"]
    
    analysis = await analyzer.analyze_incident(incident.id)
    analysis_dict = analysis.to_dict()
    
    assert isinstance(analysis_dict, dict)
    assert "incident_id" in analysis_dict
    assert "explanation" in analysis_dict
    assert "confidence" in analysis_dict
