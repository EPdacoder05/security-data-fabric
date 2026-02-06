"""
Tests for risk scorer.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.gold.risk_scorer import (
    RiskScorer,
    RiskWeights,
    Priority,
    RiskTrend,
    get_default_weights,
    create_custom_weights,
)
from src.database.models import Incident, NormalizedEvent, EventSeverity, EventState
from src.silver.unified_schema import EventType


@pytest.fixture
async def sample_incident(db_session):
    """Create sample incident for testing."""
    now = datetime.now(timezone.utc)
    
    incident = Incident(
        id=uuid4(),
        incident_number="INC0012345",
        title="Service degradation",
        severity=EventSeverity.CRITICAL,
        state=EventState.RESOLVED,
        service_name="auth-service",
        detected_at=now - timedelta(hours=2),
        acknowledged_at=now - timedelta(hours=2, minutes=-5),
        resolved_at=now - timedelta(hours=1),
        affected_users=5000,
        sla_breached=True,
    )
    
    db_session.add(incident)
    await db_session.flush()
    
    return incident


@pytest.fixture
async def open_incident(db_session):
    """Create open incident."""
    incident = Incident(
        id=uuid4(),
        incident_number="INC0012346",
        title="Active issue",
        severity=EventSeverity.WARNING,
        state=EventState.OPEN,
        service_name="test-service",
        detected_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        affected_users=1000,
        sla_breached=False,
    )
    
    db_session.add(incident)
    await db_session.flush()
    
    return incident


@pytest.mark.asyncio
async def test_scorer_initialization(db_session):
    """Test risk scorer initialization."""
    scorer = RiskScorer(db_session)
    
    assert scorer.session == db_session
    assert scorer.weights is not None
    assert len(scorer.severity_map) > 0


@pytest.mark.asyncio
async def test_custom_weights(db_session):
    """Test custom weights initialization."""
    weights = RiskWeights(
        severity=0.4,
        blast_radius=0.3,
        sla_impact=0.15,
        frequency=0.1,
        mttr=0.05,
    )
    
    scorer = RiskScorer(db_session, weights)
    
    assert scorer.weights.severity == 0.4
    assert scorer.weights.blast_radius == 0.3


@pytest.mark.asyncio
async def test_calculate_risk_score(db_session, sample_incident):
    """Test calculating comprehensive risk score."""
    scorer = RiskScorer(db_session)
    
    risk_score = await scorer.calculate_risk_score(sample_incident.id)
    
    assert risk_score.incident_id == sample_incident.id
    assert 0.0 <= risk_score.total_score <= 100.0
    assert risk_score.priority in Priority
    assert risk_score.risk_factors is not None
    assert isinstance(risk_score.recommendation, str)


@pytest.mark.asyncio
async def test_severity_score(db_session):
    """Test severity factor calculation."""
    scorer = RiskScorer(db_session)
    
    # Test different severities
    incident_critical = Incident(
        id=uuid4(),
        incident_number="INC001",
        title="Test",
        severity=EventSeverity.CRITICAL,
        state=EventState.OPEN,
        detected_at=datetime.now(timezone.utc),
    )
    
    incident_info = Incident(
        id=uuid4(),
        incident_number="INC002",
        title="Test",
        severity=EventSeverity.INFO,
        state=EventState.OPEN,
        detected_at=datetime.now(timezone.utc),
    )
    
    score_critical = scorer._calculate_severity_score(incident_critical)
    score_info = scorer._calculate_severity_score(incident_info)
    
    assert score_critical > score_info
    assert 0.0 <= score_critical <= 1.0
    assert 0.0 <= score_info <= 1.0


@pytest.mark.asyncio
async def test_blast_radius_score(db_session, sample_incident):
    """Test blast radius calculation."""
    scorer = RiskScorer(db_session)
    
    score = await scorer._calculate_blast_radius_score(sample_incident)
    
    assert 0.0 <= score <= 1.0
    # Should have score > 0 due to affected users
    assert score > 0


@pytest.mark.asyncio
async def test_sla_impact_score(db_session, sample_incident):
    """Test SLA impact calculation."""
    scorer = RiskScorer(db_session)
    
    score = scorer._calculate_sla_impact_score(sample_incident)
    
    assert 0.0 <= score <= 1.0
    # Should have high score due to SLA breach
    assert score > 0.5


@pytest.mark.asyncio
async def test_frequency_score(db_session):
    """Test frequency calculation."""
    now = datetime.now(timezone.utc)
    
    # Create multiple incidents for same service
    incidents = [
        Incident(
            id=uuid4(),
            incident_number=f"INC{i:04d}",
            title=f"Incident {i}",
            severity=EventSeverity.CRITICAL,
            state=EventState.RESOLVED,
            service_name="frequent-service",
            detected_at=now - timedelta(days=i),
            resolved_at=now - timedelta(days=i, hours=-1),
        )
        for i in range(5)
    ]
    
    db_session.add_all(incidents)
    await db_session.flush()
    
    scorer = RiskScorer(db_session)
    
    # Test latest incident
    score = await scorer._calculate_frequency_score(incidents[0])
    
    assert 0.0 <= score <= 1.0
    # Should have elevated score due to frequency
    assert score >= 0.3


@pytest.mark.asyncio
async def test_mttr_score(db_session):
    """Test MTTR calculation."""
    now = datetime.now(timezone.utc)
    
    # Create incident with quick resolution
    quick_incident = Incident(
        id=uuid4(),
        incident_number="INC001",
        title="Quick fix",
        severity=EventSeverity.CRITICAL,
        state=EventState.RESOLVED,
        service_name="quick-service",
        detected_at=now - timedelta(minutes=20),
        resolved_at=now - timedelta(minutes=10),
    )
    
    db_session.add(quick_incident)
    await db_session.flush()
    
    scorer = RiskScorer(db_session)
    score = await scorer._calculate_mttr_score(quick_incident)
    
    assert 0.0 <= score <= 1.0


@pytest.mark.asyncio
async def test_mttr_to_score(db_session):
    """Test MTTR to score conversion."""
    scorer = RiskScorer(db_session)
    
    # Test different MTTR values
    excellent = scorer._mttr_to_score(10)  # 10 minutes
    good = scorer._mttr_to_score(45)       # 45 minutes
    poor = scorer._mttr_to_score(600)      # 10 hours
    
    assert excellent < good < poor
    assert 0.0 <= excellent <= 1.0
    assert 0.0 <= poor <= 1.0


@pytest.mark.asyncio
async def test_score_to_priority(db_session):
    """Test priority assignment."""
    scorer = RiskScorer(db_session)
    
    # Test different score ranges
    p1 = scorer._score_to_priority(85, EventSeverity.CRITICAL)
    p2 = scorer._score_to_priority(65, EventSeverity.WARNING)
    p3 = scorer._score_to_priority(45, EventSeverity.INFO)
    p5 = scorer._score_to_priority(15, EventSeverity.INFO)
    
    assert p1 == Priority.P1
    assert p2 == Priority.P2
    assert p3 == Priority.P3
    assert p5 == Priority.P5


@pytest.mark.asyncio
async def test_calculate_service_risk(db_session):
    """Test service-level risk calculation."""
    now = datetime.now(timezone.utc)
    
    # Create incidents for a service
    incidents = [
        Incident(
            id=uuid4(),
            incident_number=f"INC{i:04d}",
            title=f"Incident {i}",
            severity=EventSeverity.CRITICAL,
            state=EventState.RESOLVED,
            service_name="risky-service",
            detected_at=now - timedelta(days=i),
            resolved_at=now - timedelta(days=i, hours=-1),
        )
        for i in range(3)
    ]
    
    db_session.add_all(incidents)
    await db_session.flush()
    
    scorer = RiskScorer(db_session)
    service_risk = await scorer.calculate_service_risk("risky-service", lookback_days=30)
    
    assert service_risk["service_name"] == "risky-service"
    assert service_risk["incident_count"] >= 3
    assert "avg_risk_score" in service_risk
    assert "trend" in service_risk


@pytest.mark.asyncio
async def test_risk_trend_calculation(db_session):
    """Test risk trend detection."""
    now = datetime.now(timezone.utc)
    
    # Create increasing trend
    incidents = [
        Incident(
            id=uuid4(),
            incident_number=f"INC{i:04d}",
            title=f"Incident {i}",
            severity=EventSeverity.CRITICAL,
            state=EventState.RESOLVED,
            service_name="trending-service",
            detected_at=now - timedelta(days=i),
            resolved_at=now - timedelta(days=i, hours=-1),
        )
        for i in range(6)
    ]
    
    db_session.add_all(incidents)
    await db_session.flush()
    
    scorer = RiskScorer(db_session)
    trend = await scorer._calculate_risk_trend(incidents[0])
    
    assert trend in RiskTrend


@pytest.mark.asyncio
async def test_recommendation_generation(db_session, sample_incident):
    """Test recommendation generation."""
    scorer = RiskScorer(db_session)
    
    risk_score = await scorer.calculate_risk_score(sample_incident.id)
    
    assert len(risk_score.recommendation) > 0
    assert isinstance(risk_score.recommendation, str)


@pytest.mark.asyncio
async def test_default_weights():
    """Test default weights."""
    weights = get_default_weights()
    
    assert weights.severity + weights.blast_radius + weights.sla_impact + \
           weights.frequency + weights.mttr == pytest.approx(1.0, abs=0.01)


@pytest.mark.asyncio
async def test_custom_weights_creation():
    """Test custom weights creation."""
    weights = create_custom_weights(
        severity=0.35,
        blast_radius=0.25,
        sla_impact=0.2,
        frequency=0.15,
        mttr=0.05,
    )
    
    assert weights.severity == 0.35
    assert weights.blast_radius == 0.25


@pytest.mark.asyncio
async def test_invalid_weights():
    """Test invalid weights validation."""
    with pytest.raises(ValueError):
        RiskWeights(
            severity=0.5,
            blast_radius=0.5,
            sla_impact=0.5,  # Sum > 1.0
            frequency=0.0,
            mttr=0.0,
        )


@pytest.mark.asyncio
async def test_risk_score_to_dict(db_session, sample_incident):
    """Test RiskScore to_dict conversion."""
    scorer = RiskScorer(db_session)
    risk_score = await scorer.calculate_risk_score(sample_incident.id)
    
    risk_dict = risk_score.to_dict()
    
    assert isinstance(risk_dict, dict)
    assert "incident_id" in risk_dict
    assert "total_score" in risk_dict
    assert "priority" in risk_dict
    assert "risk_factors" in risk_dict


@pytest.mark.asyncio
async def test_risk_factors_to_dict():
    """Test RiskFactors to_dict conversion."""
    from src.gold.risk_scorer import RiskFactors
    
    factors = RiskFactors(
        severity_score=0.8,
        blast_radius_score=0.6,
        sla_impact_score=0.7,
        frequency_score=0.4,
        mttr_score=0.3,
    )
    
    factors_dict = factors.to_dict()
    
    assert isinstance(factors_dict, dict)
    assert "severity" in factors_dict
    assert "blast_radius" in factors_dict
    assert factors_dict["severity"] == 0.8


@pytest.mark.asyncio
async def test_extreme_severity_priority(db_session):
    """Test that extreme severity gets P1 priority."""
    scorer = RiskScorer(db_session)
    
    priority = scorer._score_to_priority(70, EventSeverity.EXTREME)
    
    assert priority == Priority.P1


@pytest.mark.asyncio
async def test_open_incident_sla_impact(db_session, open_incident):
    """Test SLA impact for open incidents."""
    scorer = RiskScorer(db_session)
    
    score = scorer._calculate_sla_impact_score(open_incident)
    
    assert 0.0 <= score <= 1.0


@pytest.mark.asyncio
async def test_nonexistent_incident(db_session):
    """Test handling of nonexistent incident."""
    scorer = RiskScorer(db_session)
    
    with pytest.raises(ValueError):
        await scorer.calculate_risk_score(uuid4())


@pytest.mark.asyncio
async def test_service_with_no_incidents(db_session):
    """Test service risk calculation with no incidents."""
    scorer = RiskScorer(db_session)
    
    service_risk = await scorer.calculate_service_risk("nonexistent-service")
    
    assert service_risk["incident_count"] == 0
    assert service_risk["avg_risk_score"] == 0
