"""Event deduplication engine."""
from typing import Set, Tuple
from datetime import datetime, timedelta
import hashlib

from src.processing.schema import NormalizedEventSchema
from src.observability import get_logger

logger = get_logger(__name__)


class EventDeduplicator:
    """Deduplicate security events."""

    def __init__(self, time_window_minutes: int = 5) -> None:
        """Initialize deduplicator.
        
        Args:
            time_window_minutes: Time window for temporal deduplication
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self._seen_hashes: Set[str] = set()
        self._seen_with_time: list = []  # [(hash, timestamp), ...]

    def is_duplicate(self, event: NormalizedEventSchema, content_hash: str) -> bool:
        """Check if event is a duplicate.
        
        Args:
            event: Normalized event
            content_hash: Content hash of the event
            
        Returns:
            True if event is a duplicate
        """
        # Clean up old entries
        self._cleanup_old_entries()

        # Check content-based deduplication
        if content_hash in self._seen_hashes:
            logger.debug(f"Duplicate event detected (content hash): {content_hash}")
            return True

        # Check time-window deduplication
        if self._is_duplicate_in_window(event, content_hash):
            logger.debug(
                f"Duplicate event detected (time window): {content_hash}",
                extra={"source": event.source, "title": event.title},
            )
            return True

        # Not a duplicate - record it
        self._record_event(content_hash, event.timestamp)
        return False

    def _is_duplicate_in_window(self, event: NormalizedEventSchema, content_hash: str) -> bool:
        """Check if similar event exists within time window.
        
        Args:
            event: Normalized event
            content_hash: Content hash
            
        Returns:
            True if duplicate found in time window
        """
        event_time = event.timestamp
        for seen_hash, seen_time in self._seen_with_time:
            time_diff = abs((event_time - seen_time).total_seconds())
            if time_diff <= self.time_window.total_seconds():
                # Check if it's the same event (similar hash)
                if self._hashes_similar(content_hash, seen_hash):
                    return True
        return False

    def _hashes_similar(self, hash1: str, hash2: str) -> bool:
        """Check if two hashes represent similar events.
        
        For now, exact match. Could be enhanced with fuzzy matching.
        
        Args:
            hash1: First hash
            hash2: Second hash
            
        Returns:
            True if hashes are similar
        """
        return hash1 == hash2

    def _record_event(self, content_hash: str, timestamp: datetime) -> None:
        """Record event for future deduplication checks.
        
        Args:
            content_hash: Content hash
            timestamp: Event timestamp
        """
        self._seen_hashes.add(content_hash)
        self._seen_with_time.append((content_hash, timestamp))

    def _cleanup_old_entries(self) -> None:
        """Remove entries older than time window."""
        cutoff_time = datetime.utcnow() - self.time_window
        
        # Filter out old entries
        self._seen_with_time = [
            (h, t) for h, t in self._seen_with_time if t > cutoff_time
        ]
        
        # Rebuild hash set from remaining entries
        self._seen_hashes = {h for h, t in self._seen_with_time}

    def get_stats(self) -> dict:
        """Get deduplication statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            "tracked_events": len(self._seen_with_time),
            "unique_hashes": len(self._seen_hashes),
            "time_window_minutes": self.time_window.total_seconds() / 60,
        }
