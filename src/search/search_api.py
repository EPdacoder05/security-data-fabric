"""FastAPI endpoints for semantic search."""
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.connection import get_db
from src.search.semantic_search import SemanticSearch
from src.processing.schema import SearchQuery, SearchResult
from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)

router = APIRouter(prefix="/search", tags=["search"])

# Global semantic search instance
_semantic_search: Optional[SemanticSearch] = None


def get_semantic_search() -> SemanticSearch:
    """Get or create semantic search instance.

    Returns:
        SemanticSearch instance
    """
    global _semantic_search
    if _semantic_search is None:
        _semantic_search = SemanticSearch()
    return _semantic_search


@router.post("/", response_model=List[SearchResult])
async def semantic_search(
    search_query: SearchQuery,
    session: AsyncSession = Depends(get_db),
    search_service: SemanticSearch = Depends(get_semantic_search),
) -> List[SearchResult]:
    """Perform semantic search on security events.

    Args:
        search_query: Search query parameters
        session: Database session
        search_service: Semantic search service

    Returns:
        List of matching events ranked by relevance

    Raises:
        HTTPException: If search fails
    """
    try:
        metrics.increment("search_api.search_requests")
        logger.info(
            "Search API request",
            extra={
                "query": search_query.query[:100],
                "limit": search_query.limit,
            },
        )

        results = await search_service.search(
            session=session,
            query=search_query.query,
            limit=search_query.limit,
            min_similarity=search_query.min_similarity,
            filters=search_query.filters,
            boost_recent=search_query.boost_recent,
        )

        logger.info(
            "Search completed",
            extra={"results": len(results)},
        )

        return results

    except Exception as e:
        logger.error(
            "Search request failed",
            extra={"query": search_query.query[:100], "error": str(e)},
            exc_info=True,
        )
        metrics.increment("search_api.search_errors")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}",
        )


@router.get("/recent", response_model=List[SearchResult])
async def get_recent_events(
    hours: int = Query(default=24, ge=1, le=168, description="Hours to look back (max 7 days)"),
    limit: int = Query(default=50, ge=1, le=100, description="Maximum results"),
    source: Optional[str] = Query(default=None, description="Filter by source"),
    severity: Optional[int] = Query(default=None, ge=1, le=5, description="Filter by severity"),
    min_severity: Optional[int] = Query(
        default=None, ge=1, le=5, description="Filter by minimum severity"
    ),
    session: AsyncSession = Depends(get_db),
    search_service: SemanticSearch = Depends(get_semantic_search),
) -> List[SearchResult]:
    """Get recent security events.

    Args:
        hours: Number of hours to look back
        limit: Maximum number of results
        source: Optional source filter
        severity: Optional exact severity filter
        min_severity: Optional minimum severity filter
        session: Database session
        search_service: Semantic search service

    Returns:
        List of recent events ordered by timestamp

    Raises:
        HTTPException: If query fails
    """
    try:
        metrics.increment("search_api.recent_requests")
        logger.info(
            "Recent events API request",
            extra={"hours": hours, "limit": limit},
        )

        # Build filters
        filters: Dict[str, Any] = {}
        if source:
            filters["source"] = source
        if severity:
            filters["severity"] = severity
        if min_severity:
            filters["min_severity"] = min_severity

        results = await search_service.get_recent_events(
            session=session,
            hours=hours,
            limit=limit,
            filters=filters if filters else None,
        )

        logger.info(
            "Recent events retrieved",
            extra={"results": len(results)},
        )

        return results

    except Exception as e:
        logger.error(
            "Recent events request failed",
            extra={"hours": hours, "error": str(e)},
            exc_info=True,
        )
        metrics.increment("search_api.recent_errors")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve recent events: {str(e)}",
        )


@router.get("/similar/{event_id}", response_model=List[SearchResult])
async def find_similar_events(
    event_id: UUID,
    limit: int = Query(default=10, ge=1, le=50, description="Maximum results"),
    min_similarity: float = Query(
        default=0.7, ge=0.0, le=1.0, description="Minimum similarity threshold"
    ),
    session: AsyncSession = Depends(get_db),
    search_service: SemanticSearch = Depends(get_semantic_search),
) -> List[SearchResult]:
    """Find events similar to a given event.

    Args:
        event_id: Source event ID
        limit: Maximum number of results
        min_similarity: Minimum similarity threshold
        session: Database session
        search_service: Semantic search service

    Returns:
        List of similar events ranked by similarity

    Raises:
        HTTPException: If query fails or event not found
    """
    try:
        metrics.increment("search_api.similar_requests")
        logger.info(
            "Similar events API request",
            extra={"event_id": str(event_id), "limit": limit},
        )

        results = await search_service.find_similar_events(
            session=session,
            event_id=event_id,
            limit=limit,
            min_similarity=min_similarity,
        )

        if not results:
            raise HTTPException(
                status_code=404,
                detail=f"No similar events found for event {event_id}",
            )

        logger.info(
            "Similar events retrieved",
            extra={"event_id": str(event_id), "results": len(results)},
        )

        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Similar events request failed",
            extra={"event_id": str(event_id), "error": str(e)},
            exc_info=True,
        )
        metrics.increment("search_api.similar_errors")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to find similar events: {str(e)}",
        )


@router.post("/index/{event_id}")
async def index_event(
    event_id: UUID,
    session: AsyncSession = Depends(get_db),
    search_service: SemanticSearch = Depends(get_semantic_search),
) -> Dict[str, Any]:
    """Index an event for semantic search.

    Args:
        event_id: Event ID to index
        session: Database session
        search_service: Semantic search service

    Returns:
        Success message

    Raises:
        HTTPException: If indexing fails
    """
    try:
        metrics.increment("search_api.index_requests")
        logger.info("Index event API request", extra={"event_id": str(event_id)})

        await search_service.index_event(session=session, event_id=event_id)

        logger.info("Event indexed", extra={"event_id": str(event_id)})

        return {
            "success": True,
            "message": f"Event {event_id} indexed successfully",
        }

    except Exception as e:
        logger.error(
            "Index event request failed",
            extra={"event_id": str(event_id), "error": str(e)},
            exc_info=True,
        )
        metrics.increment("search_api.index_errors")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to index event: {str(e)}",
        )
