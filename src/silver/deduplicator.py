"""
Event deduplicator for Silver layer.
Identifies and removes duplicate events using content hashing and time windows.
"""
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from dataclasses import dataclass, field

from src.silver.unified_schema import UnifiedEvent
from src.config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class DeduplicationStats:
    """Statistics for deduplication operations."""
    total_processed: int = 0
    duplicates_found: int = 0
    unique_events: int = 0
    fuzzy_matches: int = 0
    by_source: Dict[str, int] = field(default_factory=dict)


class EventDeduplicator:
    """
    Deduplicates events using content-based hashing.
    Maintains a time-windowed cache of seen event hashes.
    """
    
    def __init__(
        self,
        time_window_minutes: Optional[int] = None,
        enable_fuzzy_matching: bool = False,
        fuzzy_threshold: float = 0.9,
    ):
        """
        Initialize the deduplicator.
        
        Args:
            time_window_minutes: Time window for deduplication (from settings if None)
            enable_fuzzy_matching: Enable fuzzy matching for near-duplicates
            fuzzy_threshold: Similarity threshold for fuzzy matching (0.0-1.0)
        """
        self.time_window_minutes = time_window_minutes or settings.dedup_time_window_minutes
        self.enable_fuzzy_matching = enable_fuzzy_matching
        self.fuzzy_threshold = fuzzy_threshold
        
        # Cache of seen event hashes with timestamps
        self._hash_cache: Dict[str, datetime] = {}
        
        # For fuzzy matching: cache of event fingerprints
        self._fingerprint_cache: Dict[str, List[Dict[str, Any]]] = {}
        
        # Statistics
        self.stats = DeduplicationStats()
        
        logger.info(
            f"Deduplicator initialized with {self.time_window_minutes}min window, "
            f"fuzzy_matching={self.enable_fuzzy_matching}"
        )
    
    async def is_duplicate(self, event: UnifiedEvent) -> bool:
        """
        Check if an event is a duplicate.
        
        Args:
            event: UnifiedEvent to check
            
        Returns:
            True if the event is a duplicate, False otherwise
        """
        self.stats.total_processed += 1
        
        # Generate content hash
        content_hash = self.compute_content_hash(event)
        
        # Clean up old entries
        self._cleanup_cache()
        
        # Check exact hash match
        if content_hash in self._hash_cache:
            self.stats.duplicates_found += 1
            logger.debug(f"Exact duplicate found: {content_hash[:16]}")
            return True
        
        # Check fuzzy match if enabled
        if self.enable_fuzzy_matching:
            if await self._is_fuzzy_duplicate(event, content_hash):
                self.stats.duplicates_found += 1
                self.stats.fuzzy_matches += 1
                logger.debug(f"Fuzzy duplicate found: {content_hash[:16]}")
                return True
        
        # Not a duplicate - add to cache
        self._hash_cache[content_hash] = datetime.now(timezone.utc)
        self.stats.unique_events += 1
        
        # Update source stats
        source = event.source
        self.stats.by_source[source] = self.stats.by_source.get(source, 0) + 1
        
        return False
    
    async def deduplicate_batch(
        self, events: List[UnifiedEvent]
    ) -> List[UnifiedEvent]:
        """
        Deduplicate a batch of events.
        
        Args:
            events: List of UnifiedEvents
            
        Returns:
            List of unique events (duplicates removed)
        """
        unique_events = []
        
        for event in events:
            if not await self.is_duplicate(event):
                unique_events.append(event)
        
        logger.info(
            f"Deduplicated {len(events)} events -> {len(unique_events)} unique "
            f"({len(events) - len(unique_events)} duplicates removed)"
        )
        
        return unique_events
    
    def compute_content_hash(self, event: UnifiedEvent) -> str:
        """
        Compute SHA-256 hash of event content.
        
        Uses key fields to generate a stable hash:
        - source + entity_id + title + timestamp (rounded to minute)
        
        Args:
            event: UnifiedEvent to hash
            
        Returns:
            SHA-256 hash string (hex)
        """
        # Build hash components
        components = [
            event.source,
            event.entity_id or "no-entity",
            event.title,
            # Round timestamp to minute for slight variation tolerance
            event.timestamp.replace(second=0, microsecond=0).isoformat(),
            event.severity.value,
            event.event_type.value,
        ]
        
        # Create string representation
        hash_input = "|".join(str(c) for c in components)
        
        # Compute SHA-256
        hash_obj = hashlib.sha256(hash_input.encode("utf-8"))
        return hash_obj.hexdigest()
    
    async def _is_fuzzy_duplicate(
        self, event: UnifiedEvent, content_hash: str
    ) -> bool:
        """
        Check for fuzzy duplicates using similarity matching.
        
        Args:
            event: Event to check
            content_hash: Event's content hash
            
        Returns:
            True if a similar event exists in the time window
        """
        # Create fingerprint for fuzzy matching
        fingerprint = self._create_fingerprint(event)
        fingerprint_key = self._get_fingerprint_key(event)
        
        # Check against cached fingerprints
        if fingerprint_key in self._fingerprint_cache:
            for cached in self._fingerprint_cache[fingerprint_key]:
                similarity = self._calculate_similarity(fingerprint, cached["fingerprint"])
                if similarity >= self.fuzzy_threshold:
                    return True
        
        # Add to fingerprint cache
        if fingerprint_key not in self._fingerprint_cache:
            self._fingerprint_cache[fingerprint_key] = []
        
        self._fingerprint_cache[fingerprint_key].append({
            "fingerprint": fingerprint,
            "timestamp": datetime.now(timezone.utc),
            "hash": content_hash,
        })
        
        return False
    
    def _create_fingerprint(self, event: UnifiedEvent) -> Dict[str, Any]:
        """
        Create a fingerprint for fuzzy matching.
        
        Args:
            event: Event to fingerprint
            
        Returns:
            Dictionary of key event features
        """
        return {
            "source": event.source,
            "entity_id": event.entity_id,
            "entity_type": event.entity_type,
            "title_normalized": self._normalize_text(event.title),
            "severity": event.severity.value,
            "event_type": event.event_type.value,
            "service_name": event.service_name,
        }
    
    def _get_fingerprint_key(self, event: UnifiedEvent) -> str:
        """
        Get a key for grouping similar events.
        
        Args:
            event: Event
            
        Returns:
            Key string
        """
        return f"{event.source}:{event.entity_id}:{event.event_type.value}"
    
    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for comparison.
        
        Args:
            text: Input text
            
        Returns:
            Normalized text (lowercase, stripped, no extra spaces)
        """
        if not text:
            return ""
        return " ".join(text.lower().strip().split())
    
    def _calculate_similarity(
        self, fp1: Dict[str, Any], fp2: Dict[str, Any]
    ) -> float:
        """
        Calculate similarity between two fingerprints.
        
        Uses Jaccard similarity on text fields and exact matching on others.
        
        Args:
            fp1: First fingerprint
            fp2: Second fingerprint
            
        Returns:
            Similarity score (0.0-1.0)
        """
        scores = []
        
        # Exact matches
        for key in ["source", "entity_id", "severity", "event_type"]:
            if fp1.get(key) == fp2.get(key):
                scores.append(1.0)
            else:
                scores.append(0.0)
        
        # Text similarity (Jaccard)
        title1 = set(fp1.get("title_normalized", "").split())
        title2 = set(fp2.get("title_normalized", "").split())
        
        if title1 or title2:
            intersection = len(title1 & title2)
            union = len(title1 | title2)
            title_sim = intersection / union if union > 0 else 0.0
            scores.append(title_sim)
        
        # Average similarity
        return sum(scores) / len(scores) if scores else 0.0
    
    def _cleanup_cache(self):
        """Remove entries older than the time window."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.time_window_minutes)
        
        # Clean hash cache
        expired_hashes = [
            h for h, ts in self._hash_cache.items() if ts < cutoff
        ]
        for h in expired_hashes:
            del self._hash_cache[h]
        
        # Clean fingerprint cache
        for key in list(self._fingerprint_cache.keys()):
            self._fingerprint_cache[key] = [
                fp for fp in self._fingerprint_cache[key]
                if fp["timestamp"] >= cutoff
            ]
            # Remove empty keys
            if not self._fingerprint_cache[key]:
                del self._fingerprint_cache[key]
        
        if expired_hashes:
            logger.debug(f"Cleaned {len(expired_hashes)} expired cache entries")
    
    def get_cache_size(self) -> Dict[str, int]:
        """
        Get current cache sizes.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            "hash_cache_size": len(self._hash_cache),
            "fingerprint_cache_keys": len(self._fingerprint_cache),
            "fingerprint_cache_total": sum(
                len(v) for v in self._fingerprint_cache.values()
            ),
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get deduplication statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_processed": self.stats.total_processed,
            "duplicates_found": self.stats.duplicates_found,
            "unique_events": self.stats.unique_events,
            "fuzzy_matches": self.stats.fuzzy_matches,
            "duplicate_rate": (
                self.stats.duplicates_found / self.stats.total_processed
                if self.stats.total_processed > 0
                else 0.0
            ),
            "by_source": self.stats.by_source,
            "cache": self.get_cache_size(),
        }
    
    def reset_stats(self):
        """Reset statistics."""
        self.stats = DeduplicationStats()
    
    def clear_cache(self):
        """Clear all caches."""
        self._hash_cache.clear()
        self._fingerprint_cache.clear()
        logger.info("Deduplication caches cleared")
