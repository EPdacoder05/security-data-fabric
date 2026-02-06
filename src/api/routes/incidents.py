"""Incident endpoints."""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db, models
from src.api.dependencies import get_current_user, CurrentUser
from src.observability import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentSummary(BaseModel):
    """Incident summary model."""

    incident_id: str
    title: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    event_count: int
    severity: int


class IncidentListResponse(BaseModel):
    """List of incidents response."""

    incidents: List[IncidentSummary]
    total: int
    page: int
    page_size: int


class TimelineEventDetail(BaseModel):
    """Detailed timeline event."""

    event_id: str
    timestamp: datetime
    event_type: str
    severity: int
    title: str
    description: Optional[str]
    source: str
    risk_score: Optional[float]
    tags: Optional[List[str]]
    correlations: Optional[Dict[str, Any]]


class IncidentTimelineDetail(BaseModel):
    """Detailed incident timeline."""

    incident_id: str
    title: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    events: List[TimelineEventDetail]
    root_cause: Optional[Dict[str, Any]]
    impact: Optional[str]
    resolution: Optional[str]
    created_at: datetime
    updated_at: datetime


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, description="Filter by status: active, resolved"),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> IncidentListResponse:
    """List incidents with filtering and pagination.
    
    Args:
        page: Page number
        page_size: Items per page
        status_filter: Filter by status (active/resolved)
        days: Number of days to look back
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        List of incidents
    """
    logger.info(
        "Listing incidents",
        extra={
            "page": page,
            "page_size": page_size,
            "status_filter": status_filter,
            "days": days,
        },
    )
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Build query
    query = select(models.IncidentTimeline).where(
        models.IncidentTimeline.start_time >= cutoff
    )
    
    # Apply status filter
    if status_filter == "active":
        query = query.where(models.IncidentTimeline.end_time.is_(None))
    elif status_filter == "resolved":
        query = query.where(models.IncidentTimeline.end_time.isnot(None))
    
    # Order by start time descending
    query = query.order_by(models.IncidentTimeline.start_time.desc())
    
    # Count total
    count_query = select(models.IncidentTimeline).where(
        models.IncidentTimeline.start_time >= cutoff
    )
    if status_filter == "active":
        count_query = count_query.where(models.IncidentTimeline.end_time.is_(None))
    elif status_filter == "resolved":
        count_query = count_query.where(models.IncidentTimeline.end_time.isnot(None))
    
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    # Build response
    incident_summaries = []
    for incident in incidents:
        # Determine status
        status_value = "active" if incident.end_time is None else "resolved"
        
        # Count events
        event_count = len(incident.events) if incident.events else 0
        
        # Determine severity (max severity from events)
        max_severity = 1
        if incident.events:
            for event in incident.events:
                event_severity = event.get("severity", 1)
                if event_severity > max_severity:
                    max_severity = event_severity
        
        incident_summaries.append(
            IncidentSummary(
                incident_id=incident.incident_id,
                title=incident.title,
                start_time=incident.start_time,
                end_time=incident.end_time,
                status=status_value,
                event_count=event_count,
                severity=max_severity,
            )
        )
    
    return IncidentListResponse(
        incidents=incident_summaries,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineDetail)
async def get_incident_timeline_detail(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> IncidentTimelineDetail:
    """Get detailed incident timeline with all events.
    
    Args:
        incident_id: Incident ID
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        Detailed incident timeline
        
    Raises:
        HTTPException: If incident not found
    """
    logger.info(
        f"Fetching incident timeline detail",
        extra={"incident_id": incident_id},
    )
    
    # Get incident timeline
    query = select(models.IncidentTimeline).where(
        models.IncidentTimeline.incident_id == incident_id
    )
    result = await db.execute(query)
    timeline = result.scalar_one_or_none()
    
    if not timeline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    
    # Parse timeline events
    timeline_events = []
    if timeline.events:
        for event_data in timeline.events:
            timeline_events.append(
                TimelineEventDetail(
                    event_id=event_data.get("event_id", "unknown"),
                    timestamp=datetime.fromisoformat(event_data.get("timestamp")),
                    event_type=event_data.get("event_type", "unknown"),
                    severity=event_data.get("severity", 1),
                    title=event_data.get("title", ""),
                    description=event_data.get("description"),
                    source=event_data.get("source", "unknown"),
                    risk_score=event_data.get("risk_score"),
                    tags=event_data.get("tags"),
                    correlations=event_data.get("correlations"),
                )
            )
    
    # Determine status
    status_value = "active" if timeline.end_time is None else "resolved"
    
    return IncidentTimelineDetail(
        incident_id=timeline.incident_id,
        title=timeline.title,
        start_time=timeline.start_time,
        end_time=timeline.end_time,
        status=status_value,
        events=timeline_events,
        root_cause=timeline.root_cause,
        impact=timeline.impact,
        resolution=timeline.resolution,
        created_at=timeline.created_at,
        updated_at=timeline.updated_at,
    )
