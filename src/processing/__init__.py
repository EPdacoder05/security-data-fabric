"""Data processing module - Silver Layer."""
from src.processing.schema import (
    NormalizedEventSchema,
    EnrichedEventSchema,
    PredictionSchema,
    AlertSchema,
    IncidentTimelineSchema,
    SearchQuery,
    SearchResult,
)
from src.processing.normalizer import EventNormalizer
from src.processing.deduplicator import EventDeduplicator
from src.processing.enricher import EventEnricher

__all__ = [
    "NormalizedEventSchema",
    "EnrichedEventSchema",
    "PredictionSchema",
    "AlertSchema",
    "IncidentTimelineSchema",
    "SearchQuery",
    "SearchResult",
    "EventNormalizer",
    "EventDeduplicator",
    "EventEnricher",
]
