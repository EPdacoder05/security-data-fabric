"""Vector store for semantic search using pgvector."""
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
import numpy as np
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import Embedding, EnrichedEvent
from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class VectorStore:
    """pgvector-based vector store for semantic search."""

    # Filter keys that require NormalizedEvent join
    NORMALIZED_EVENT_FILTER_KEYS = {"source", "severity", "time_range"}

    def __init__(self, dimension: int = 384) -> None:
        """Initialize vector store.

        Args:
            dimension: Embedding vector dimension
        """
        self.dimension = dimension
        logger.info("Initialized VectorStore", extra={"dimension": dimension})

    async def store_embedding(
        self,
        session: AsyncSession,
        event_id: UUID,
        embedding: np.ndarray,
        text_content: str,
    ) -> UUID:
        """Store a single embedding with metadata.

        Args:
            session: Database session
            event_id: Associated enriched event ID
            embedding: Embedding vector
            text_content: Text used to generate embedding

        Returns:
            UUID of created embedding record
        """
        try:
            if embedding.shape[0] != self.dimension:
                raise ValueError(
                    f"Embedding dimension mismatch: expected {self.dimension}, "
                    f"got {embedding.shape[0]}"
                )

            # Convert numpy array to list for pgvector
            embedding_list = embedding.tolist()

            db_embedding = Embedding(
                event_id=event_id,
                embedding=embedding_list,
                text_content=text_content,
            )

            session.add(db_embedding)
            await session.flush()

            metrics.increment("vector_store.embeddings_stored")
            logger.debug(
                "Stored embedding",
                extra={"event_id": str(event_id), "embedding_id": str(db_embedding.id)},
            )

            return db_embedding.id

        except Exception as e:
            logger.error(
                "Failed to store embedding",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("vector_store.store_errors")
            raise

    async def store_embeddings_batch(
        self,
        session: AsyncSession,
        embeddings_data: List[Tuple[UUID, np.ndarray, str]],
    ) -> List[UUID]:
        """Store multiple embeddings efficiently.

        Args:
            session: Database session
            embeddings_data: List of (event_id, embedding, text_content) tuples

        Returns:
            List of created embedding record UUIDs
        """
        try:
            if not embeddings_data:
                return []

            db_embeddings = []
            for event_id, embedding, text_content in embeddings_data:
                if embedding.shape[0] != self.dimension:
                    logger.warning(
                        "Skipping embedding with incorrect dimension",
                        extra={
                            "event_id": str(event_id),
                            "expected": self.dimension,
                            "actual": embedding.shape[0],
                        },
                    )
                    continue

                db_embeddings.append(
                    Embedding(
                        event_id=event_id,
                        embedding=embedding.tolist(),
                        text_content=text_content,
                    )
                )

            session.add_all(db_embeddings)
            await session.flush()

            embedding_ids = [emb.id for emb in db_embeddings]
            metrics.increment("vector_store.embeddings_stored", len(embedding_ids))
            logger.info(
                "Stored embeddings batch",
                extra={"count": len(embedding_ids)},
            )

            return embedding_ids

        except Exception as e:
            logger.error(
                "Failed to store embeddings batch",
                extra={"batch_size": len(embeddings_data), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("vector_store.batch_store_errors")
            raise

    async def similarity_search(
        self,
        session: AsyncSession,
        query_embedding: np.ndarray,
        limit: int = 10,
        min_similarity: float = 0.5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[UUID, float, Dict[str, Any]]]:
        """Find similar embeddings using cosine similarity.

        Args:
            session: Database session
            query_embedding: Query embedding vector
            limit: Maximum number of results
            min_similarity: Minimum similarity threshold (0-1)
            filters: Optional filters (source, severity, time_range)

        Returns:
            List of (event_id, similarity_score, metadata) tuples
        """
        try:
            metrics.increment("vector_store.similarity_searches")

            if query_embedding.shape[0] != self.dimension:
                raise ValueError(
                    f"Query embedding dimension mismatch: expected {self.dimension}, "
                    f"got {query_embedding.shape[0]}"
                )

            # Convert to list for pgvector
            query_list = query_embedding.tolist()

            # Build query with cosine similarity (1 - cosine_distance)
            # pgvector's <=> operator is cosine distance, so we convert to similarity
            query = (
                select(
                    Embedding.event_id,
                    (1 - Embedding.embedding.cosine_distance(query_list)).label("similarity"),
                    EnrichedEvent.normalized_event_id,
                )
                .join(EnrichedEvent, Embedding.event_id == EnrichedEvent.id)
                .where((1 - Embedding.embedding.cosine_distance(query_list)) >= min_similarity)
            )

            # Apply filters if provided
            query = self._apply_filters(query, filters)

            # Order by similarity and limit
            query = query.order_by(text("similarity DESC")).limit(limit)

            result = await session.execute(query)
            rows = result.all()

            results = [
                (
                    row.event_id,
                    float(row.similarity),
                    {"normalized_event_id": row.normalized_event_id},
                )
                for row in rows
            ]

            metrics.increment("vector_store.similarity_search_results", len(results))
            logger.info(
                "Completed similarity search",
                extra={"results": len(results), "limit": limit},
            )

            return results

        except Exception as e:
            logger.error(
                "Similarity search failed",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("vector_store.search_errors")
            raise

    def _apply_filters(self, query, filters: Optional[Dict[str, Any]]):
        """Apply filters to query with proper joins.

        Args:
            query: SQLAlchemy query
            filters: Optional filters (source, severity, time_range)

        Returns:
            Updated query with filters applied
        """
        if not filters:
            return query

        # Determine if we need to join NormalizedEvent
        needs_join = any(key in filters for key in self.NORMALIZED_EVENT_FILTER_KEYS)
        
        if needs_join:
            from src.database.models import NormalizedEvent
            query = query.join(
                NormalizedEvent,
                EnrichedEvent.normalized_event_id == NormalizedEvent.id,
            )

            if "source" in filters:
                query = query.where(NormalizedEvent.source == filters["source"])

            if "severity" in filters:
                query = query.where(NormalizedEvent.severity == filters["severity"])

            if "time_range" in filters:
                time_range = filters["time_range"]
                if "start" in time_range:
                    query = query.where(NormalizedEvent.timestamp >= time_range["start"])
                if "end" in time_range:
                    query = query.where(NormalizedEvent.timestamp <= time_range["end"])

        return query

    async def find_nearest_neighbors(
        self,
        session: AsyncSession,
        event_id: UUID,
        limit: int = 10,
        min_similarity: float = 0.5,
    ) -> List[Tuple[UUID, float]]:
        """Find nearest neighbor events for a given event.

        Args:
            session: Database session
            event_id: Source event ID
            limit: Maximum number of results
            min_similarity: Minimum similarity threshold

        Returns:
            List of (event_id, similarity_score) tuples
        """
        try:
            # Get the embedding for the source event
            query = select(Embedding.embedding).where(Embedding.event_id == event_id)
            result = await session.execute(query)
            embedding_row = result.first()

            if not embedding_row:
                logger.warning(
                    "No embedding found for event",
                    extra={"event_id": str(event_id)},
                )
                return []

            # Convert to numpy array
            source_embedding = np.array(embedding_row[0])

            # Find similar embeddings, excluding the source event
            query = (
                select(
                    Embedding.event_id,
                    (1 - Embedding.embedding.cosine_distance(source_embedding.tolist())).label(
                        "similarity"
                    ),
                )
                .where(Embedding.event_id != event_id)
                .where(
                    (1 - Embedding.embedding.cosine_distance(source_embedding.tolist()))
                    >= min_similarity
                )
                .order_by(text("similarity DESC"))
                .limit(limit)
            )

            result = await session.execute(query)
            rows = result.all()

            results = [(row.event_id, float(row.similarity)) for row in rows]

            logger.info(
                "Found nearest neighbors",
                extra={"event_id": str(event_id), "neighbors": len(results)},
            )

            return results

        except Exception as e:
            logger.error(
                "Failed to find nearest neighbors",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("vector_store.nearest_neighbor_errors")
            raise

    async def get_embedding(
        self,
        session: AsyncSession,
        event_id: UUID,
    ) -> Optional[np.ndarray]:
        """Get embedding vector for an event.

        Args:
            session: Database session
            event_id: Event ID

        Returns:
            Embedding vector as numpy array, or None if not found
        """
        try:
            query = select(Embedding.embedding).where(Embedding.event_id == event_id)
            result = await session.execute(query)
            row = result.first()

            if row:
                return np.array(row[0])
            return None

        except Exception as e:
            logger.error(
                "Failed to get embedding",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            raise

    async def delete_embedding(
        self,
        session: AsyncSession,
        event_id: UUID,
    ) -> bool:
        """Delete embedding for an event.

        Args:
            session: Database session
            event_id: Event ID

        Returns:
            True if deleted, False if not found
        """
        try:
            query = select(Embedding).where(Embedding.event_id == event_id)
            result = await session.execute(query)
            embedding = result.scalar_one_or_none()

            if embedding:
                await session.delete(embedding)
                await session.flush()
                metrics.increment("vector_store.embeddings_deleted")
                logger.debug("Deleted embedding", extra={"event_id": str(event_id)})
                return True

            return False

        except Exception as e:
            logger.error(
                "Failed to delete embedding",
                extra={"event_id": str(event_id), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("vector_store.delete_errors")
            raise

    async def count_embeddings(self, session: AsyncSession) -> int:
        """Count total embeddings in store.

        Args:
            session: Database session

        Returns:
            Number of embeddings
        """
        try:
            query = select(func.count(Embedding.id))
            result = await session.execute(query)
            count = result.scalar()
            return count or 0

        except Exception as e:
            logger.error("Failed to count embeddings", extra={"error": str(e)}, exc_info=True)
            raise
