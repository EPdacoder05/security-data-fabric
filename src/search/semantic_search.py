"""
Natural language query interface for semantic search.
Converts queries to embeddings and retrieves relevant results.
"""
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc
import numpy as np

from src.search.vector_store import VectorStore, VectorStoreError
from src.ml.embedding_engine import EmbeddingEngine
from src.database.models import (
    Embedding, NormalizedEvent, Incident, Prediction,
    EventSeverity, EventState
)
from src.config.settings import settings

logger = logging.getLogger(__name__)


class SearchError(Exception):
    """Base exception for search operations."""
    pass


class SearchResultType(str, Enum):
    """Types of search results."""
    EVENT = "event"
    INCIDENT = "incident"
    PREDICTION = "prediction"


class SearchResult:
    """Container for search result with metadata."""
    
    def __init__(
        self,
        result_type: SearchResultType,
        entity_id: UUID,
        entity_data: Dict[str, Any],
        similarity_score: float,
        embedding_id: UUID
    ):
        self.result_type = result_type
        self.entity_id = entity_id
        self.entity_data = entity_data
        self.similarity_score = similarity_score
        self.embedding_id = embedding_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'result_type': self.result_type.value,
            'entity_id': str(self.entity_id),
            'similarity_score': self.similarity_score,
            'embedding_id': str(self.embedding_id),
            **self.entity_data
        }


class SemanticSearch:
    """
    Natural language query interface for semantic search.
    
    Provides semantic search over security events, incidents, and predictions
    using embeddings and vector similarity.
    """
    
    def __init__(
        self,
        session: AsyncSession,
        embedding_engine: Optional[EmbeddingEngine] = None
    ):
        """
        Initialize semantic search.
        
        Args:
            session: Async SQLAlchemy session
            embedding_engine: Optional embedding engine (creates new if None)
        """
        self.session = session
        self.vector_store = VectorStore(session)
        self.embedding_engine = embedding_engine or EmbeddingEngine()
        self._initialized = False
        
        logger.debug("SemanticSearch initialized")
    
    async def initialize(self) -> None:
        """Initialize embedding engine."""
        if not self._initialized:
            await self.embedding_engine.initialize()
            self._initialized = True
            logger.info("SemanticSearch ready")
    
    async def search(
        self,
        query: str,
        limit: int = 10,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        severity: Optional[EventSeverity] = None,
        source: Optional[str] = None,
        entity_filter: Optional[str] = None,
        source_types: Optional[List[SearchResultType]] = None,
        min_similarity: float = 0.3
    ) -> List[SearchResult]:
        """
        Perform semantic search with filters.
        
        Args:
            query: Natural language query
            limit: Maximum results to return
            time_range: Optional (start_time, end_time) filter
            severity: Optional severity filter
            source: Optional source system filter
            entity_filter: Optional entity ID/name filter
            source_types: Filter by result types (event, incident, prediction)
            min_similarity: Minimum similarity threshold (0-1)
        
        Returns:
            List of SearchResult objects ordered by relevance
        
        Raises:
            SearchError: If search fails
        
        Examples:
            >>> results = await search.search(
            ...     "authentication failures last Tuesday",
            ...     severity=EventSeverity.CRITICAL,
            ...     limit=5
            ... )
        """
        try:
            if not query or not query.strip():
                raise SearchError("Query cannot be empty")
            
            await self.initialize()
            
            logger.info(f"Semantic search: '{query}' (limit={limit})")
            
            # Generate query embedding
            query_embedding = await self.embedding_engine.generate_embedding(query)
            
            # Build metadata filters
            metadata_filters = {}
            if source:
                metadata_filters['source'] = source
            if entity_filter:
                metadata_filters['entity_id'] = entity_filter
            
            # Search vector store
            similar_embeddings = await self.vector_store.search(
                query_embedding=query_embedding,
                limit=limit * 3,  # Get extra to filter down
                min_similarity=min_similarity,
                metadata_filters=metadata_filters if metadata_filters else None
            )
            
            if not similar_embeddings:
                logger.info(f"No results found for query: '{query}'")
                return []
            
            logger.debug(f"Found {len(similar_embeddings)} similar embeddings")
            
            # Group by source type and retrieve entities
            results = await self._retrieve_entities(
                similar_embeddings,
                time_range=time_range,
                severity=severity,
                source=source,
                entity_filter=entity_filter,
                source_types=source_types
            )
            
            # Sort by similarity and limit
            results.sort(key=lambda r: r.similarity_score, reverse=True)
            results = results[:limit]
            
            logger.info(f"Returning {len(results)} search results")
            return results
            
        except VectorStoreError as e:
            logger.error(f"Vector store error during search: {e}")
            raise SearchError(f"Search failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during search: {e}")
            raise SearchError(f"Search failed: {e}")
    
    async def search_paginated(
        self,
        query: str,
        page: int = 1,
        page_size: int = 10,
        **filters
    ) -> Dict[str, Any]:
        """
        Perform paginated semantic search.
        
        Args:
            query: Natural language query
            page: Page number (1-indexed)
            page_size: Results per page
            **filters: Additional search filters
        
        Returns:
            Dictionary with results and pagination info
        """
        try:
            if page < 1:
                raise SearchError("Page must be >= 1")
            if page_size < 1 or page_size > 100:
                raise SearchError("Page size must be between 1 and 100")
            
            # Get more results to handle pagination
            total_limit = page * page_size * 2
            all_results = await self.search(
                query,
                limit=total_limit,
                **filters
            )
            
            # Calculate pagination
            total_results = len(all_results)
            total_pages = (total_results + page_size - 1) // page_size
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            
            page_results = all_results[start_idx:end_idx]
            
            return {
                'query': query,
                'results': [r.to_dict() for r in page_results],
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_results': total_results,
                    'total_pages': total_pages,
                    'has_next': page < total_pages,
                    'has_prev': page > 1
                }
            }
            
        except Exception as e:
            logger.error(f"Paginated search failed: {e}")
            raise SearchError(f"Paginated search failed: {e}")
    
    async def find_similar(
        self,
        entity_type: str,
        entity_id: UUID,
        limit: int = 10,
        min_similarity: float = 0.5
    ) -> List[SearchResult]:
        """
        Find similar entities based on an existing entity.
        
        Args:
            entity_type: Type of entity (event, incident, prediction)
            entity_id: UUID of the entity
            limit: Maximum results
            min_similarity: Minimum similarity threshold
        
        Returns:
            List of similar SearchResult objects
        
        Raises:
            SearchError: If entity not found or search fails
        """
        try:
            logger.info(f"Finding similar to {entity_type}:{entity_id}")
            
            # Get embedding for the entity
            stmt = select(Embedding).where(
                and_(
                    Embedding.source_type == entity_type,
                    Embedding.source_id == entity_id
                )
            )
            result = await self.session.execute(stmt)
            embedding_obj = result.scalar_one_or_none()
            
            if not embedding_obj:
                raise SearchError(f"No embedding found for {entity_type}:{entity_id}")
            
            # Convert stored embedding to numpy array
            query_embedding = np.array(embedding_obj.embedding)
            
            # Search for similar
            similar_embeddings = await self.vector_store.search(
                query_embedding=query_embedding,
                limit=limit + 1,  # +1 to exclude self
                min_similarity=min_similarity
            )
            
            # Filter out the query entity itself
            similar_embeddings = [
                (emb, score) for emb, score in similar_embeddings
                if emb.source_id != entity_id
            ][:limit]
            
            # Retrieve entities
            results = await self._retrieve_entities(similar_embeddings)
            
            logger.info(f"Found {len(results)} similar entities")
            return results
            
        except Exception as e:
            logger.error(f"Find similar failed: {e}")
            raise SearchError(f"Find similar failed: {e}")
    
    async def _retrieve_entities(
        self,
        embeddings: List[Tuple[Embedding, float]],
        time_range: Optional[Tuple[datetime, datetime]] = None,
        severity: Optional[EventSeverity] = None,
        source: Optional[str] = None,
        entity_filter: Optional[str] = None,
        source_types: Optional[List[SearchResultType]] = None
    ) -> List[SearchResult]:
        """
        Retrieve full entity data for embeddings with filtering.
        
        Args:
            embeddings: List of (Embedding, similarity_score) tuples
            time_range: Optional time filter
            severity: Optional severity filter
            source: Optional source filter
            entity_filter: Optional entity filter
            source_types: Filter by result types
        
        Returns:
            List of SearchResult objects
        """
        results = []
        
        # Group embeddings by source type
        by_type = {}
        for emb, score in embeddings:
            if source_types and emb.source_type not in [st.value for st in source_types]:
                continue
            
            if emb.source_type not in by_type:
                by_type[emb.source_type] = []
            by_type[emb.source_type].append((emb, score))
        
        # Retrieve events
        if 'event' in by_type:
            event_results = await self._retrieve_events(
                by_type['event'],
                time_range=time_range,
                severity=severity,
                source=source,
                entity_filter=entity_filter
            )
            results.extend(event_results)
        
        # Retrieve incidents
        if 'incident' in by_type:
            incident_results = await self._retrieve_incidents(
                by_type['incident'],
                time_range=time_range,
                severity=severity
            )
            results.extend(incident_results)
        
        # Retrieve predictions
        if 'prediction' in by_type:
            prediction_results = await self._retrieve_predictions(
                by_type['prediction'],
                time_range=time_range,
                entity_filter=entity_filter
            )
            results.extend(prediction_results)
        
        return results
    
    async def _retrieve_events(
        self,
        embeddings: List[Tuple[Embedding, float]],
        time_range: Optional[Tuple[datetime, datetime]] = None,
        severity: Optional[EventSeverity] = None,
        source: Optional[str] = None,
        entity_filter: Optional[str] = None
    ) -> List[SearchResult]:
        """Retrieve NormalizedEvent entities."""
        event_ids = [emb.source_id for emb, _ in embeddings]
        
        stmt = select(NormalizedEvent).where(NormalizedEvent.id.in_(event_ids))
        
        # Apply filters
        conditions = []
        if time_range:
            conditions.append(NormalizedEvent.timestamp.between(*time_range))
        if severity:
            conditions.append(NormalizedEvent.severity == severity)
        if source:
            conditions.append(NormalizedEvent.source == source)
        if entity_filter:
            conditions.append(
                or_(
                    NormalizedEvent.entity_id == entity_filter,
                    NormalizedEvent.entity_name.ilike(f"%{entity_filter}%")
                )
            )
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        result = await self.session.execute(stmt)
        events = {str(e.id): e for e in result.scalars().all()}
        
        # Create search results
        results = []
        for emb, score in embeddings:
            event_id = str(emb.source_id)
            if event_id in events:
                event = events[event_id]
                results.append(SearchResult(
                    result_type=SearchResultType.EVENT,
                    entity_id=event.id,
                    similarity_score=score,
                    embedding_id=emb.id,
                    entity_data={
                        'title': event.title,
                        'description': event.description,
                        'severity': event.severity.value,
                        'timestamp': event.timestamp.isoformat(),
                        'source': event.source,
                        'event_type': event.event_type,
                        'entity_id': event.entity_id,
                        'entity_name': event.entity_name,
                        'service_name': event.service_name,
                        'tags': event.tags
                    }
                ))
        
        return results
    
    async def _retrieve_incidents(
        self,
        embeddings: List[Tuple[Embedding, float]],
        time_range: Optional[Tuple[datetime, datetime]] = None,
        severity: Optional[EventSeverity] = None
    ) -> List[SearchResult]:
        """Retrieve Incident entities."""
        incident_ids = [emb.source_id for emb, _ in embeddings]
        
        stmt = select(Incident).where(Incident.id.in_(incident_ids))
        
        # Apply filters
        conditions = []
        if time_range:
            conditions.append(Incident.detected_at.between(*time_range))
        if severity:
            conditions.append(Incident.severity == severity)
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        result = await self.session.execute(stmt)
        incidents = {str(i.id): i for i in result.scalars().all()}
        
        # Create search results
        results = []
        for emb, score in embeddings:
            incident_id = str(emb.source_id)
            if incident_id in incidents:
                incident = incidents[incident_id]
                results.append(SearchResult(
                    result_type=SearchResultType.INCIDENT,
                    entity_id=incident.id,
                    similarity_score=score,
                    embedding_id=emb.id,
                    entity_data={
                        'incident_number': incident.incident_number,
                        'title': incident.title,
                        'description': incident.description,
                        'severity': incident.severity.value,
                        'state': incident.state.value,
                        'detected_at': incident.detected_at.isoformat(),
                        'service_name': incident.service_name,
                        'team': incident.team,
                        'root_cause': incident.root_cause,
                        'risk_score': incident.risk_score,
                        'external_ticket_id': incident.external_ticket_id
                    }
                ))
        
        return results
    
    async def _retrieve_predictions(
        self,
        embeddings: List[Tuple[Embedding, float]],
        time_range: Optional[Tuple[datetime, datetime]] = None,
        entity_filter: Optional[str] = None
    ) -> List[SearchResult]:
        """Retrieve Prediction entities."""
        prediction_ids = [emb.source_id for emb, _ in embeddings]
        
        stmt = select(Prediction).where(Prediction.id.in_(prediction_ids))
        
        # Apply filters
        conditions = []
        if time_range:
            conditions.append(Prediction.predicted_at.between(*time_range))
        if entity_filter:
            conditions.append(
                or_(
                    Prediction.entity_id == entity_filter,
                    Prediction.entity_name.ilike(f"%{entity_filter}%")
                )
            )
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        result = await self.session.execute(stmt)
        predictions = {str(p.id): p for p in result.scalars().all()}
        
        # Create search results
        results = []
        for emb, score in embeddings:
            prediction_id = str(emb.source_id)
            if prediction_id in predictions:
                prediction = predictions[prediction_id]
                results.append(SearchResult(
                    result_type=SearchResultType.PREDICTION,
                    entity_id=prediction.id,
                    similarity_score=score,
                    embedding_id=emb.id,
                    entity_data={
                        'prediction_type': prediction.prediction_type.value,
                        'entity_id': prediction.entity_id,
                        'entity_name': prediction.entity_name,
                        'current_value': prediction.current_value,
                        'predicted_value': prediction.predicted_value,
                        'confidence_score': prediction.confidence_score,
                        'predicted_at': prediction.predicted_at.isoformat(),
                        'eta_minutes': prediction.eta_minutes,
                        'explanation': prediction.explanation,
                        'is_active': prediction.is_active
                    }
                ))
        
        return results
