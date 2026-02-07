"""
Semantic search endpoints for Security Data Fabric API.
Natural language query interface for security events and incidents.
"""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_database_session, get_embedding_engine
from src.search.semantic_search import SemanticSearch, SearchResultType
from src.ml.embedding_engine import EmbeddingEngine
from src.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/search", tags=["search"])


# Pydantic models
class SearchRequest(BaseModel):
    """Request model for semantic search."""
    query: str = Field(..., min_length=1, max_length=1000, description="Natural language query")
    result_types: Optional[List[SearchResultType]] = Field(
        None,
        description="Filter by result types (event, incident, prediction)"
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of results"
    )
    similarity_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum similarity score"
    )
    time_range_hours: Optional[int] = Field(
        None,
        ge=1,
        le=720,
        description="Limit results to last N hours"
    )


class SearchResultResponse(BaseModel):
    """Response model for search result."""
    id: str
    result_type: SearchResultType
    title: str
    description: Optional[str]
    similarity_score: float
    timestamp: datetime
    source: Optional[str]
    severity: Optional[str]
    service_name: Optional[str]
    entity_id: Optional[str]
    metadata: Dict[str, Any]


class SearchResponse(BaseModel):
    """Response model for search."""
    query: str
    results: List[SearchResultResponse]
    total_results: int
    search_time_ms: float
    timestamp: datetime


@router.post("", response_model=SearchResponse)
async def semantic_search(
    request: SearchRequest,
    db: AsyncSession = Depends(get_database_session),
    embedding_engine: EmbeddingEngine = Depends(get_embedding_engine)
) -> SearchResponse:
    """
    Perform semantic search using natural language query.
    
    Converts the query to embeddings and finds semantically similar events,
    incidents, and predictions using vector similarity.
    
    **Example queries:**
    - "Show me all database connection failures in the last 24 hours"
    - "What caused the payment service outage?"
    - "Find high severity incidents related to authentication"
    - "Memory leaks in production environment"
    
    **Parameters:**
    - **query**: Natural language search query
    - **result_types**: Optional filter by result types
    - **max_results**: Maximum results to return (1-100)
    - **similarity_threshold**: Minimum similarity score (0.0-1.0)
    - **time_range_hours**: Limit to recent events (1-720 hours)
    """
    if not settings.enable_semantic_search:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Semantic search is disabled"
        )
    
    start_time = datetime.utcnow()
    
    try:
        # Initialize semantic search
        semantic_search_engine = SemanticSearch(
            session=db,
            embedding_engine=embedding_engine
        )
        await semantic_search_engine.initialize()
        
        # Calculate time range if specified
        time_range = None
        if request.time_range_hours:
            end_time = datetime.utcnow()
            start_time_range = end_time - timedelta(hours=request.time_range_hours)
            time_range = (start_time_range, end_time)
        
        # Perform search
        results = await semantic_search_engine.search(
            query=request.query,
            limit=request.max_results,
            time_range=time_range,
            source_types=request.result_types,
            min_similarity=request.similarity_threshold
        )
        
        # Convert results to response format
        search_results = []
        for result in results:
            # Extract data from entity_data dict
            entity_data = result.entity_data
            
            search_results.append(
                SearchResultResponse(
                    id=str(result.entity_id),
                    result_type=result.result_type,
                    title=entity_data.get("title", ""),
                    description=entity_data.get("description"),
                    similarity_score=result.similarity_score,
                    timestamp=entity_data.get("timestamp", datetime.utcnow()),
                    source=entity_data.get("source"),
                    severity=entity_data.get("severity"),
                    service_name=entity_data.get("service_name"),
                    entity_id=entity_data.get("entity_id"),
                    metadata=entity_data.get("metadata", {})
                )
            )
        
        # Calculate search time
        end_time = datetime.utcnow()
        search_time_ms = (end_time - start_time).total_seconds() * 1000
        
        logger.info(
            f"Semantic search completed: query='{request.query}', "
            f"results={len(search_results)}, time={search_time_ms:.2f}ms"
        )
        
        return SearchResponse(
            query=request.query,
            results=search_results,
            total_results=len(search_results),
            search_time_ms=round(search_time_ms, 2),
            timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Semantic search failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )
