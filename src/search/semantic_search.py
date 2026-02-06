"""Semantic search service for natural language queries."""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID
import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.search.vector_store import VectorStore
from src.ml.embedding_engine import EmbeddingEngine
from src.database.models import EnrichedEvent, NormalizedEvent
from src.processing.schema import SearchResult
from src.config import settings
from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class SemanticSearch:
    """Natural language semantic search for security events."""

    def __init__(
        self,
        embedding_engine: Optional[EmbeddingEngine] = None,
        vector_store: Optional[VectorStore] = None,
    ) -> None:
        """Initialize semantic search service.

        Args:
            embedding_engine: Embedding engine instance
            vector_store: Vector store instance
        """
        self.embedding_engine = embedding_engine or EmbeddingEngine()
        self.vector_store = vector_store or VectorStore(
            dimension=settings.embedding_dimension
        )
        logger.info("Initialized SemanticSearch")

    async def search(
        self,
        session: AsyncSession,
        query: str,
        limit: int = 10,
        min_similarity: float = 0.5,
        filters: Optional[Dict[str, Any]] = None,
        boost_recent: bool = True,
    ) -> List[SearchResult]:
        """Perform semantic search on security events.

        Args:
            session: Database session
            query: Natural language search query
            limit: Maximum number of results
            min_similarity: Minimum similarity threshold (0-1)
            filters: Optional filters (source, severity, time_range)
            boost_recent: Whether to boost recent events in ranking

        Returns:
            List of search results ordered by relevance
        """
        try:
            metrics.increment("semantic_search.queries")
            logger.info(
                "Performing semantic search",
                extra={
                    "query": query[:100],
                    "limit": limit,
                    "min_similarity": min_similarity,
                },
            )

            # Generate query embedding
            query_embedding = self.embedding_engine.embed_text(query)

            # Perform vector similarity search
            similar_events = await self.vector_store.similarity_search(
                session=session,
                query_embedding=query_embedding,
                limit=limit * 2,  # Get more results for re-ranking
                min_similarity=min_similarity,
                filters=filters,
            )

            if not similar_events:
                logger.info("No similar events found")
                return []

            # Fetch event details and rank results
            results = await self._fetch_and_rank_results(
                session=session,
                similar_events=similar_events,
                boost_recent=boost_recent,
                limit=limit,
            )

            metrics.increment("semantic_search.results_returned", len(results))
            logger.info(
                "Semantic search completed",
                extra={"results": len(results)},
            )

            return results

        except Exception as e:
            logger.error(
                "Semantic search failed",
                extra={"query": query[:100], "error": str(e)},
                exc_info=True,
            )
            metrics.increment("semantic_search.errors")
            raise

    async def _fetch_and_rank_results(
        self,
        session: AsyncSession,
        similar_events: List[tuple],
        boost_recent: bool,
        limit: int,
    ) -> List[SearchResult]:
        """Fetch event details and rank by relevance and recency.

        Args:
            session: Database session
            similar_events: List of (event_id, similarity, metadata) tuples
            boost_recent: Whether to boost recent events
            limit: Maximum results to return

        Returns:
            Ranked list of search results
        """
        event_ids = [event_id for event_id, _, _ in similar_events]
        similarity_map = {event_id: similarity for event_id, similarity, _ in similar_events}

        # Fetch event details
        query = (
            select(EnrichedEvent, NormalizedEvent)
            .join(NormalizedEvent, EnrichedEvent.normalized_event_id == NormalizedEvent.id)
            .where(EnrichedEvent.id.in_(event_ids))
        )

        result = await session.execute(query)
        rows = result.all()

        # Build search results with ranking
        results = []
        now = datetime.now(timezone.utc)

        for enriched_event, normalized_event in rows:
            similarity_score = similarity_map[enriched_event.id]

            # Calculate recency boost (0-1, decays over 30 days)
            if boost_recent:
                age_hours = (now - normalized_event.timestamp).total_seconds() / 3600
                recency_boost = max(0.0, 1.0 - (age_hours / (30 * 24)))  # 30 days decay
                # Combine similarity and recency (70% similarity, 30% recency)
                final_score = (similarity_score * 0.7) + (recency_boost * 0.3)
            else:
                final_score = similarity_score

            results.append(
                SearchResult(
                    event_id=enriched_event.id,
                    score=final_score,
                    title=normalized_event.title,
                    description=normalized_event.description,
                    timestamp=normalized_event.timestamp,
                    source=normalized_event.source,
                    severity=normalized_event.severity,
                    metadata={
                        "risk_score": enriched_event.risk_score,
                        "tags": enriched_event.tags or [],
                        "incident_id": enriched_event.incident_id,
                        "event_type": normalized_event.event_type,
                        "raw_similarity": similarity_score,
                    },
                )
            )

        # Sort by final score and limit
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:limit]

    async def find_similar_events(
        self,
        session: AsyncSession,
        event_id: UUID,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> List[SearchResult]:
        """Find events similar to a given event.

        Args:
            session: Database session
            event_id: Source event ID
            limit: Maximum number of results
            min_similarity: Minimum similarity threshold

        Returns:
            List of similar events
        """
        try:
            metrics.increment("semantic_search.similar_event_queries")
            logger.info(
                "Finding similar events",
                extra={"event_id": str(event_id), "limit": limit},
            )

            # Find nearest neighbors
            neighbors = await self.vector_store.find_nearest_neighbors(
                session=session,
                event_id=event_id,
                limit=limit,
                min_similarity=min_similarity,
            )

            if not neighbors:
                logger.info("No similar events found")
                return []

            # Convert to similar_events format for ranking
            similar_events = [
                (neighbor_id, similarity, {}) for neighbor_id, similarity in neighbors
            ]

            # Fetch and rank results
            results = await self._fetch_and_rank_results(
                session=session,
                similar_events=similar_events,
                boost_recent=False,  # Don't boost recency for similarity queries
                limit=limit,
            )

            metrics.increment("semantic_search.similar_events_returned", len(results))
            logger.info(
                "Found similar events",
                extra={"event_id": str(event_id), "results": len(results)},
            )

            return results

        except Exception as e:
            logger.error(
                "Failed to find similar events",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("semantic_search.similar_event_errors")
            raise

    async def get_recent_events(
        self,
        session: AsyncSession,
        hours: int = 24,
        limit: int = 50,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """Get recent security events.

        Args:
            session: Database session
            hours: Number of hours to look back
            limit: Maximum number of results
            filters: Optional filters (source, severity)

        Returns:
            List of recent events
        """
        try:
            metrics.increment("semantic_search.recent_event_queries")
            logger.info(
                "Fetching recent events",
                extra={"hours": hours, "limit": limit},
            )

            # Calculate time threshold
            time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)

            # Build query
            query = (
                select(EnrichedEvent, NormalizedEvent)
                .join(NormalizedEvent, EnrichedEvent.normalized_event_id == NormalizedEvent.id)
                .where(NormalizedEvent.timestamp >= time_threshold)
            )

            # Apply filters
            if filters:
                if "source" in filters:
                    query = query.where(NormalizedEvent.source == filters["source"])
                if "severity" in filters:
                    query = query.where(NormalizedEvent.severity == filters["severity"])
                if "min_severity" in filters:
                    query = query.where(NormalizedEvent.severity >= filters["min_severity"])

            # Order by timestamp (most recent first) and limit
            query = query.order_by(NormalizedEvent.timestamp.desc()).limit(limit)

            result = await session.execute(query)
            rows = result.all()

            # Build search results
            results = []
            for enriched_event, normalized_event in rows:
                results.append(
                    SearchResult(
                        event_id=enriched_event.id,
                        score=1.0,  # All recent events have equal score
                        title=normalized_event.title,
                        description=normalized_event.description,
                        timestamp=normalized_event.timestamp,
                        source=normalized_event.source,
                        severity=normalized_event.severity,
                        metadata={
                            "risk_score": enriched_event.risk_score,
                            "tags": enriched_event.tags or [],
                            "incident_id": enriched_event.incident_id,
                            "event_type": normalized_event.event_type,
                        },
                    )
                )

            metrics.increment("semantic_search.recent_events_returned", len(results))
            logger.info(
                "Fetched recent events",
                extra={"results": len(results)},
            )

            return results

        except Exception as e:
            logger.error(
                "Failed to fetch recent events",
                extra={"hours": hours, "error": str(e)},
                exc_info=True,
            )
            metrics.increment("semantic_search.recent_event_errors")
            raise

    async def index_event(
        self,
        session: AsyncSession,
        event_id: UUID,
    ) -> None:
        """Index an event for semantic search.

        Args:
            session: Database session
            event_id: Enriched event ID to index
        """
        try:
            # Fetch event details
            query = (
                select(EnrichedEvent, NormalizedEvent)
                .join(NormalizedEvent, EnrichedEvent.normalized_event_id == NormalizedEvent.id)
                .where(EnrichedEvent.id == event_id)
            )

            result = await session.execute(query)
            row = result.first()

            if not row:
                logger.warning("Event not found for indexing", extra={"event_id": str(event_id)})
                return

            enriched_event, normalized_event = row

            # Create text content for embedding
            text_content = self._build_text_content(normalized_event, enriched_event)

            # Generate embedding
            embedding = self.embedding_engine.embed_text(text_content)

            # Store in vector store
            await self.vector_store.store_embedding(
                session=session,
                event_id=event_id,
                embedding=embedding,
                text_content=text_content,
            )

            metrics.increment("semantic_search.events_indexed")
            logger.info("Indexed event", extra={"event_id": str(event_id)})

        except Exception as e:
            logger.error(
                "Failed to index event",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("semantic_search.indexing_errors")
            raise

    def _build_text_content(
        self,
        normalized_event: NormalizedEvent,
        enriched_event: EnrichedEvent,
    ) -> str:
        """Build text content for embedding generation.

        Args:
            normalized_event: Normalized event
            enriched_event: Enriched event

        Returns:
            Combined text content
        """
        parts = [
            f"Title: {normalized_event.title}",
            f"Type: {normalized_event.event_type}",
            f"Source: {normalized_event.source}",
            f"Severity: {normalized_event.severity}",
        ]

        if normalized_event.description:
            parts.append(f"Description: {normalized_event.description}")

        if enriched_event.tags:
            parts.append(f"Tags: {', '.join(enriched_event.tags)}")

        return " | ".join(parts)
