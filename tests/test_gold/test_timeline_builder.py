"""
Tests for timeline builder.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.gold.timeline_builder import (
    TimelineBuilder,
    TimelineFormat,
    TimelineEntry,
    TimelineGap,
)
from src.database.models import NormalizedEvent, Incident, EventSeverity, EventState
from src.silver.unified_schema import EventType


@pytest.fixture
async def sample_incident(db_session):
    """Create sample incident."""
    now = datetime.now(timezone.utc)
    
    incident = Incident(
        id=uuid4(),
        incident_number="INC0012345",
        title="Auth service degraded",
        severity=EventSeverity.CRITICAL,
        state=EventState.RESOLVED,
        service_name="auth-service",
        detected_at=now - timedelta(hours=1),
        acknowledged_at=now - timedelta(minutes=50),
        resolved_at=now - timedelta(minutes=10),
    )
    
    db_session.add(incident)
    await db_session.flush()
    
    return incident


@pytest.fixture
async def timeline_events(db_session):
    """Create events for timeline."""
    now = datetime.now(timezone.utc)
    
    events = [
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="github",
            event_type=EventType.DEPLOY,
            severity=EventSeverity.INFO,
            timestamp=now - timedelta(minutes=60),
            title="Deploy auth-service v2.4.1",
            service_name="auth-service",
            content_hash="hash1",
            metadata_json={"version": "v2.4.1"},
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="dynatrace",
            event_type=EventType.METRIC,
            severity=EventSeverity.CRITICAL,
            timestamp=now - timedelta(minutes=55),
            title="CPU spike 89%",
            service_name="auth-service",
            content_hash="hash2",
            metadata_json={"z_score": 4.92},
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="servicenow",
            event_type=EventType.INCIDENT,
            severity=EventSeverity.CRITICAL,
            timestamp=now - timedelta(minutes=52),
            title="INC0012345 created",
            service_name="auth-service",
            content_hash="hash3",
            metadata_json={"incident_id": "INC0012345"},
        ),
    ]
    
    db_session.add_all(events)
    await db_session.flush()
    
    return events


@pytest.mark.asyncio
async def test_builder_initialization(db_session):
    """Test timeline builder initialization."""
    builder = TimelineBuilder(db_session)
    
    assert builder.session == db_session
    assert builder.lookback_hours > 0


@pytest.mark.asyncio
async def test_build_timeline_from_events(db_session, timeline_events):
    """Test building timeline from event IDs."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    
    assert timeline.total_events == len(timeline_events)
    assert len(timeline.entries) == len(timeline_events)
    assert timeline.start_time is not None
    assert timeline.end_time is not None
    assert len(timeline.sources) == 3  # github, dynatrace, servicenow


@pytest.mark.asyncio
async def test_timeline_chronological_order(db_session, timeline_events):
    """Test that timeline entries are in chronological order."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    
    # Check entries are sorted by timestamp
    for i in range(len(timeline.entries) - 1):
        assert timeline.entries[i].timestamp <= timeline.entries[i + 1].timestamp


@pytest.mark.asyncio
async def test_build_timeline_around_time(db_session, timeline_events):
    """Test building timeline around a specific time."""
    builder = TimelineBuilder(db_session)
    center_time = timeline_events[1].timestamp
    
    timeline = await builder.build_timeline_around_time(
        center_time,
        lookback_minutes=10,
        lookahead_minutes=10,
        service_name="auth-service"
    )
    
    assert timeline.total_events >= 0
    # Should include events within window
    if timeline.entries:
        for entry in timeline.entries:
            time_diff = abs((entry.timestamp - center_time).total_seconds() / 60)
            assert time_diff <= 10


@pytest.mark.asyncio
async def test_format_text(db_session, timeline_events):
    """Test text formatting."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    text_output = builder.format_timeline(timeline, TimelineFormat.TEXT)
    
    assert isinstance(text_output, str)
    assert len(text_output) > 0
    assert "Timeline:" in text_output
    assert "Sources:" in text_output


@pytest.mark.asyncio
async def test_format_json(db_session, timeline_events):
    """Test JSON formatting."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    json_output = builder.format_timeline(timeline, TimelineFormat.JSON)
    
    assert isinstance(json_output, str)
    # Should be valid JSON
    import json
    parsed = json.loads(json_output)
    assert "total_events" in parsed
    assert "entries" in parsed


@pytest.mark.asyncio
async def test_format_html(db_session, timeline_events):
    """Test HTML formatting."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    html_output = builder.format_timeline(timeline, TimelineFormat.HTML)
    
    assert isinstance(html_output, str)
    assert '<div class="timeline">' in html_output
    assert "</div>" in html_output


@pytest.mark.asyncio
async def test_detect_gaps(db_session):
    """Test gap detection in timeline."""
    now = datetime.now(timezone.utc)
    
    # Create events with a large gap
    events = [
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="test",
            event_type=EventType.METRIC,
            severity=EventSeverity.INFO,
            timestamp=now - timedelta(minutes=30),
            title="Event 1",
            content_hash="hash1",
        ),
        NormalizedEvent(
            id=uuid4(),
            raw_event_id=uuid4(),
            source="test",
            event_type=EventType.METRIC,
            severity=EventSeverity.INFO,
            timestamp=now - timedelta(minutes=20),  # 10 minute gap
            title="Event 2",
            content_hash="hash2",
        ),
    ]
    
    db_session.add_all(events)
    await db_session.flush()
    
    builder = TimelineBuilder(db_session)
    timeline = await builder.build_timeline_from_events([e.id for e in events])
    
    # Should detect gap
    assert len(timeline.gaps) > 0
    gap = timeline.gaps[0]
    assert gap.duration_seconds > 0


@pytest.mark.asyncio
async def test_timeline_entry_to_dict():
    """Test TimelineEntry to_dict conversion."""
    entry = TimelineEntry(
        timestamp=datetime.now(timezone.utc),
        event_id=uuid4(),
        event_type="metric",
        source="dynatrace",
        severity="critical",
        title="Test event",
    )
    
    entry_dict = entry.to_dict()
    
    assert isinstance(entry_dict, dict)
    assert "timestamp" in entry_dict
    assert "event_id" in entry_dict
    assert "event_type" in entry_dict
    assert entry_dict["source"] == "dynatrace"


@pytest.mark.asyncio
async def test_timeline_gap_format():
    """Test TimelineGap formatting."""
    gap = TimelineGap(
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc) + timedelta(minutes=15),
        duration_seconds=900,
    )
    
    gap_dict = gap.to_dict()
    
    assert isinstance(gap_dict, dict)
    assert "duration_human" in gap_dict
    assert "duration_seconds" in gap_dict


@pytest.mark.asyncio
async def test_timeline_to_dict(db_session, timeline_events):
    """Test Timeline to_dict conversion."""
    builder = TimelineBuilder(db_session)
    event_ids = [e.id for e in timeline_events]
    
    timeline = await builder.build_timeline_from_events(event_ids)
    timeline_dict = timeline.to_dict()
    
    assert isinstance(timeline_dict, dict)
    assert "total_events" in timeline_dict
    assert "entries" in timeline_dict
    assert "sources" in timeline_dict
    assert timeline_dict["total_events"] == len(timeline_events)


@pytest.mark.asyncio
async def test_empty_timeline(db_session):
    """Test building timeline with no events."""
    builder = TimelineBuilder(db_session)
    
    timeline = await builder.build_timeline_from_events([])
    
    assert timeline.total_events == 0
    assert len(timeline.entries) == 0
    assert timeline.start_time is None


@pytest.mark.asyncio
async def test_severity_markers(db_session):
    """Test severity to marker conversion."""
    builder = TimelineBuilder(db_session)
    
    assert builder._severity_to_marker("info") == "ℹ️"
    assert builder._severity_to_marker("warning") == "⚠️"
    assert builder._severity_to_marker("critical") == "🔴"
    assert builder._severity_to_marker("extreme") == "💥"


@pytest.mark.asyncio
async def test_extract_event_metadata(db_session, timeline_events):
    """Test metadata extraction from events."""
    builder = TimelineBuilder(db_session)
    
    deploy_event = timeline_events[0]
    metadata = builder._extract_event_metadata(deploy_event)
    
    assert isinstance(metadata, dict)
    if deploy_event.event_type == EventType.DEPLOY:
        assert "version" in metadata
