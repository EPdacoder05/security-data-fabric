"""Tests for data processing components."""
import pytest
from datetime import datetime

from src.processing import EventNormalizer, EventDeduplicator, EventEnricher
from src.processing.schema import NormalizedEventSchema


def test_event_normalizer_dynatrace():
    """Test Dynatrace event normalization."""
    normalizer = EventNormalizer()
    
    raw_data = {
        "metric_id": "builtin:host.cpu.usage",
        "value": 85.5,
        "unit": "percent",
        "timestamp": datetime.utcnow(),
        "dimensions": {"host": "test-host"},
    }
    
    normalized = normalizer.normalize("dynatrace", raw_data)
    
    assert normalized.source == "dynatrace"
    assert normalized.event_type == "metric"
    assert normalized.severity >= 1 and normalized.severity <= 5
    assert "CPU" in normalized.title or "Metric" in normalized.title


def test_event_normalizer_github():
    """Test GitHub event normalization."""
    normalizer = EventNormalizer()
    
    raw_data = {
        "event_type": "deployment",
        "repository": "test-org/test-repo",
        "environment": "production",
        "ref": "main",
        "timestamp": datetime.utcnow(),
    }
    
    normalized = normalizer.normalize("github", raw_data)
    
    assert normalized.source == "github"
    assert normalized.event_type == "deployment"
    assert "Deployment" in normalized.title
    assert "production" in normalized.title


def test_content_hash_computation():
    """Test content hash computation."""
    from src.processing.normalizer import EventNormalizer
    
    event = NormalizedEventSchema(
        event_type="test",
        timestamp=datetime.utcnow(),
        source="test",
        severity=3,
        title="Test Event",
        description="Test",
        metadata={},
    )
    
    hash1 = EventNormalizer.compute_content_hash(event)
    hash2 = EventNormalizer.compute_content_hash(event)
    
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex


def test_event_deduplicator():
    """Test event deduplication."""
    deduplicator = EventDeduplicator(time_window_minutes=5)
    
    event = NormalizedEventSchema(
        event_type="test",
        timestamp=datetime.utcnow(),
        source="test",
        severity=3,
        title="Test Event",
        description="Test",
        metadata={},
    )
    
    from src.processing.normalizer import EventNormalizer
    content_hash = EventNormalizer.compute_content_hash(event)
    
    # First occurrence - not a duplicate
    assert not deduplicator.is_duplicate(event, content_hash)
    
    # Second occurrence - is a duplicate
    assert deduplicator.is_duplicate(event, content_hash)


def test_event_enricher(sample_normalized_event):
    """Test event enrichment."""
    enricher = EventEnricher()
    
    # Set ID for the event
    sample_normalized_event.id = None  # Will be set by database
    
    # For testing, we'll create a mock ID
    from uuid import uuid4
    sample_normalized_event.id = uuid4()
    
    enriched = enricher.enrich(sample_normalized_event)
    
    assert enriched.normalized_event_id == sample_normalized_event.id
    assert enriched.risk_score is not None
    assert 0 <= enriched.risk_score <= 100
    assert len(enriched.tags) > 0
    assert "source:dynatrace" in enriched.tags


def test_enricher_tag_generation():
    """Test tag generation."""
    enricher = EventEnricher()
    
    event = NormalizedEventSchema(
        event_type="incident",
        timestamp=datetime.utcnow(),
        source="pagerduty",
        severity=5,
        title="Critical Incident",
        description="Test incident",
        metadata={"urgency": "high", "status": "triggered"},
    )
    
    from uuid import uuid4
    event.id = uuid4()
    
    enriched = enricher.enrich(event)
    
    assert "source:pagerduty" in enriched.tags
    assert "type:incident" in enriched.tags
    assert "severity:critical" in enriched.tags
