"""
Unit tests for the EventDeduplicator.
Tests deduplication logic including content hashing and fuzzy matching.
"""
import pytest
from datetime import datetime, timezone, timedelta

from src.silver.deduplicator import EventDeduplicator
from src.silver.unified_schema import UnifiedEvent, EventSeverity, EventType


class TestEventDeduplicator:
    """Test suite for EventDeduplicator."""
    
    @pytest.fixture
    def deduplicator(self):
        """Create a deduplicator instance."""
        return EventDeduplicator(time_window_minutes=5)
    
    @pytest.fixture
    def deduplicator_fuzzy(self):
        """Create a deduplicator with fuzzy matching enabled."""
        return EventDeduplicator(
            time_window_minutes=5,
            enable_fuzzy_matching=True,
            fuzzy_threshold=0.9,
        )
    
    @pytest.fixture
    def sample_event(self) -> UnifiedEvent:
        """Create a sample event."""
        return UnifiedEvent(
            source="dynatrace",
            source_id="PROB-12345",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-ABCD1234",
            entity_type="host",
            entity_name="web-server-01",
            title="CPU usage spike detected",
            description="CPU usage increased from 45% to 89%",
        )
    
    @pytest.mark.asyncio
    async def test_first_event_not_duplicate(self, deduplicator, sample_event):
        """Test that the first occurrence of an event is not a duplicate."""
        is_dup = await deduplicator.is_duplicate(sample_event)
        assert is_dup is False
        assert deduplicator.stats.unique_events == 1
        assert deduplicator.stats.duplicates_found == 0
    
    @pytest.mark.asyncio
    async def test_exact_duplicate_detection(self, deduplicator, sample_event):
        """Test detection of exact duplicates."""
        # First occurrence
        is_dup1 = await deduplicator.is_duplicate(sample_event)
        assert is_dup1 is False
        
        # Second occurrence (duplicate)
        is_dup2 = await deduplicator.is_duplicate(sample_event)
        assert is_dup2 is True
        
        assert deduplicator.stats.unique_events == 1
        assert deduplicator.stats.duplicates_found == 1
    
    @pytest.mark.asyncio
    async def test_different_events_not_duplicate(self, deduplicator):
        """Test that different events are not considered duplicates."""
        event1 = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-ABCD1234",
            title="CPU spike",
        )
        
        event2 = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-EFGH5678",  # Different entity
            title="CPU spike",
        )
        
        is_dup1 = await deduplicator.is_duplicate(event1)
        is_dup2 = await deduplicator.is_duplicate(event2)
        
        assert is_dup1 is False
        assert is_dup2 is False
        assert deduplicator.stats.unique_events == 2
    
    @pytest.mark.asyncio
    async def test_content_hash_computation(self, deduplicator, sample_event):
        """Test content hash computation is consistent."""
        hash1 = deduplicator.compute_content_hash(sample_event)
        hash2 = deduplicator.compute_content_hash(sample_event)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters
    
    @pytest.mark.asyncio
    async def test_time_window_expiry(self, deduplicator, sample_event):
        """Test that events outside time window are not considered duplicates."""
        # Mark event as seen
        await deduplicator.is_duplicate(sample_event)
        
        # Manually expire the cache entry
        content_hash = deduplicator.compute_content_hash(sample_event)
        deduplicator._hash_cache[content_hash] = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        )
        
        # Cleanup should remove expired entries
        deduplicator._cleanup_cache()
        
        # Now should not be duplicate
        is_dup = await deduplicator.is_duplicate(sample_event)
        assert is_dup is False
    
    @pytest.mark.asyncio
    async def test_batch_deduplication(self, deduplicator):
        """Test batch deduplication."""
        events = []
        
        # Create 5 unique events
        for i in range(5):
            events.append(
                UnifiedEvent(
                    source="test",
                    event_type=EventType.ALERT,
                    timestamp=datetime.now(timezone.utc),
                    severity=EventSeverity.INFO,
                    entity_id=f"entity-{i}",
                    title=f"Event {i}",
                )
            )
        
        # Add 3 duplicates
        events.append(events[0])  # Duplicate of first
        events.append(events[1])  # Duplicate of second
        events.append(events[0])  # Another duplicate of first
        
        unique = await deduplicator.deduplicate_batch(events)
        
        assert len(unique) == 5
        assert deduplicator.stats.unique_events == 5
        assert deduplicator.stats.duplicates_found == 3
    
    @pytest.mark.asyncio
    async def test_fuzzy_matching_similar_titles(self, deduplicator_fuzzy):
        """Test fuzzy matching detects similar events."""
        event1 = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-123",
            title="CPU usage is very high",
        )
        
        event2 = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-123",
            title="CPU usage very high",  # Similar but not identical
        )
        
        is_dup1 = await deduplicator_fuzzy.is_duplicate(event1)
        is_dup2 = await deduplicator_fuzzy.is_duplicate(event2)
        
        assert is_dup1 is False
        assert is_dup2 is True  # Should be detected as fuzzy duplicate
        assert deduplicator_fuzzy.stats.fuzzy_matches >= 1
    
    @pytest.mark.asyncio
    async def test_different_severity_not_duplicate(self, deduplicator):
        """Test that events with different severity are not duplicates."""
        base_time = datetime.now(timezone.utc)
        
        event1 = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=base_time,
            severity=EventSeverity.INFO,
            entity_id="entity-1",
            title="Test event",
        )
        
        event2 = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=base_time,
            severity=EventSeverity.CRITICAL,  # Different severity
            entity_id="entity-1",
            title="Test event",
        )
        
        is_dup1 = await deduplicator.is_duplicate(event1)
        is_dup2 = await deduplicator.is_duplicate(event2)
        
        assert is_dup1 is False
        assert is_dup2 is False
    
    @pytest.mark.asyncio
    async def test_timestamp_rounding_tolerance(self, deduplicator):
        """Test that events within the same minute are considered duplicates."""
        base_time = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        
        event1 = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=base_time.replace(second=15),
            severity=EventSeverity.INFO,
            entity_id="entity-1",
            title="Test",
        )
        
        event2 = UnifiedEvent(
            source="test",
            event_type=EventType.ALERT,
            timestamp=base_time.replace(second=45),  # Different second, same minute
            severity=EventSeverity.INFO,
            entity_id="entity-1",
            title="Test",
        )
        
        is_dup1 = await deduplicator.is_duplicate(event1)
        is_dup2 = await deduplicator.is_duplicate(event2)
        
        assert is_dup1 is False
        assert is_dup2 is True  # Should be duplicate due to minute rounding
    
    @pytest.mark.asyncio
    async def test_cache_size_tracking(self, deduplicator):
        """Test cache size tracking."""
        events = [
            UnifiedEvent(
                source="test",
                event_type=EventType.ALERT,
                timestamp=datetime.now(timezone.utc),
                severity=EventSeverity.INFO,
                entity_id=f"entity-{i}",
                title=f"Event {i}",
            )
            for i in range(10)
        ]
        
        for event in events:
            await deduplicator.is_duplicate(event)
        
        cache_size = deduplicator.get_cache_size()
        assert cache_size["hash_cache_size"] == 10
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, deduplicator):
        """Test statistics are tracked correctly."""
        event = UnifiedEvent(
            source="dynatrace",
            event_type=EventType.METRIC,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.CRITICAL,
            entity_id="HOST-123",
            title="Test",
        )
        
        # Process event twice
        await deduplicator.is_duplicate(event)
        await deduplicator.is_duplicate(event)
        
        stats = deduplicator.get_stats()
        assert stats["total_processed"] == 2
        assert stats["unique_events"] == 1
        assert stats["duplicates_found"] == 1
        assert stats["duplicate_rate"] == 0.5
        assert "dynatrace" in stats["by_source"]
    
    @pytest.mark.asyncio
    async def test_reset_stats(self, deduplicator, sample_event):
        """Test statistics reset."""
        await deduplicator.is_duplicate(sample_event)
        assert deduplicator.stats.total_processed == 1
        
        deduplicator.reset_stats()
        assert deduplicator.stats.total_processed == 0
        assert deduplicator.stats.unique_events == 0
    
    @pytest.mark.asyncio
    async def test_clear_cache(self, deduplicator, sample_event):
        """Test cache clearing."""
        await deduplicator.is_duplicate(sample_event)
        assert deduplicator.get_cache_size()["hash_cache_size"] > 0
        
        deduplicator.clear_cache()
        assert deduplicator.get_cache_size()["hash_cache_size"] == 0
    
    @pytest.mark.asyncio
    async def test_multiple_sources_deduplication(self, deduplicator):
        """Test deduplication tracks multiple sources correctly."""
        sources = ["dynatrace", "splunk", "pagerduty"]
        
        for source in sources:
            event = UnifiedEvent(
                source=source,
                event_type=EventType.ALERT,
                timestamp=datetime.now(timezone.utc),
                severity=EventSeverity.INFO,
                entity_id="test-entity",
                title="Test",
            )
            await deduplicator.is_duplicate(event)
        
        stats = deduplicator.get_stats()
        assert len(stats["by_source"]) == 3
        for source in sources:
            assert source in stats["by_source"]
    
    @pytest.mark.asyncio
    async def test_null_entity_handling(self, deduplicator):
        """Test handling of events without entity IDs."""
        event1 = UnifiedEvent(
            source="test",
            event_type=EventType.LOG,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            entity_id=None,  # No entity
            title="Generic log",
        )
        
        event2 = UnifiedEvent(
            source="test",
            event_type=EventType.LOG,
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.INFO,
            entity_id=None,  # No entity
            title="Generic log",
        )
        
        is_dup1 = await deduplicator.is_duplicate(event1)
        is_dup2 = await deduplicator.is_duplicate(event2)
        
        assert is_dup1 is False
        assert is_dup2 is True  # Should still detect as duplicate
