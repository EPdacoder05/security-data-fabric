"""
Incident CRUD endpoints for Security Data Fabric API.
Provides incident management, timeline, and root cause analysis.
"""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_database_session
from src.database.models import (
    Incident, NormalizedEvent, Correlation, 
    EventSeverity, EventState
)
from src.gold.timeline_builder import TimelineBuilder
from src.gold.root_cause_analyzer import RootCauseAnalyzer
from src.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


# Pydantic models for request/response
class IncidentCreate(BaseModel):
    """Request model for creating an incident."""
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: EventSeverity
    service_name: Optional[str] = None
    team: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    detected_at: Optional[datetime] = None


class IncidentResponse(BaseModel):
    """Response model for incident."""
    id: UUID
    incident_number: str
    title: str
    description: Optional[str]
    severity: EventSeverity
    state: EventState
    service_name: Optional[str]
    team: Optional[str]
    assigned_to: Optional[str]
    detected_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    root_cause: Optional[str]
    root_cause_confidence: Optional[float]
    risk_score: Optional[float]
    affected_users: Optional[int]
    sla_breached: bool
    external_ticket_id: Optional[str]
    external_ticket_url: Optional[str]
    tags: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class TimelineEntryResponse(BaseModel):
    """Response model for timeline entry."""
    timestamp: datetime
    event_id: UUID
    event_type: str
    source: str
    severity: str
    title: str
    description: Optional[str]
    entity_id: Optional[str]
    entity_name: Optional[str]
    service_name: Optional[str]
    metadata: Dict[str, Any]


class TimelineResponse(BaseModel):
    """Response model for incident timeline."""
    incident_id: UUID
    entries: List[TimelineEntryResponse]
    total_events: int
    time_range: Dict[str, datetime]


class RootCauseResponse(BaseModel):
    """Response model for root cause analysis."""
    incident_id: UUID
    root_cause: Optional[str]
    confidence: float
    candidates: List[Dict[str, Any]]
    analysis_timestamp: datetime


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    state: Optional[EventState] = None,
    severity: Optional[EventSeverity] = None,
    service_name: Optional[str] = None,
    team: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_database_session)
) -> List[IncidentResponse]:
    """
    List incidents with optional filters.
    
    - **state**: Filter by incident state (open, acknowledged, resolved, closed)
    - **severity**: Filter by severity level
    - **service_name**: Filter by service name
    - **team**: Filter by team
    - **limit**: Maximum number of results (default: 50, max: 500)
    - **offset**: Pagination offset
    """
    query = select(Incident)
    
    # Apply filters
    filters = []
    if state:
        filters.append(Incident.state == state)
    if severity:
        filters.append(Incident.severity == severity)
    if service_name:
        filters.append(Incident.service_name == service_name)
    if team:
        filters.append(Incident.team == team)
    
    if filters:
        query = query.where(and_(*filters))
    
    # Order by detected_at descending
    query = query.order_by(desc(Incident.detected_at))
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    logger.info(f"Retrieved {len(incidents)} incidents")
    return [IncidentResponse.model_validate(inc) for inc in incidents]


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_database_session)
) -> IncidentResponse:
    """
    Get a single incident by ID.
    """
    query = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )
    
    return IncidentResponse.model_validate(incident)


@router.get("/{incident_id}/timeline", response_model=TimelineResponse)
async def get_incident_timeline(
    incident_id: UUID,
    lookback_hours: int = Query(default=24, ge=1, le=168),
    db: AsyncSession = Depends(get_database_session)
) -> TimelineResponse:
    """
    Get correlated timeline for an incident.
    
    - **incident_id**: Incident UUID
    - **lookback_hours**: Hours to look back from incident detection (default: 24, max: 168)
    """
    # Get incident
    query = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )
    
    # Build timeline
    timeline_builder = TimelineBuilder(db)
    timeline = await timeline_builder.build_timeline_for_incident(
        incident_id=incident_id,
        lookback_hours=lookback_hours
    )
    
    # Convert to response format
    entries = [
        TimelineEntryResponse(
            timestamp=entry.timestamp,
            event_id=entry.event_id,
            event_type=entry.event_type,
            source=entry.source,
            severity=entry.severity,
            title=entry.title,
            description=entry.description,
            entity_id=entry.entity_id,
            entity_name=entry.entity_name,
            service_name=entry.service_name,
            metadata=entry.metadata
        )
        for entry in timeline.entries
    ]
    
    time_range = {
        "start": timeline.entries[0].timestamp if timeline.entries else incident.detected_at,
        "end": timeline.entries[-1].timestamp if timeline.entries else incident.detected_at
    }
    
    return TimelineResponse(
        incident_id=incident_id,
        entries=entries,
        total_events=len(entries),
        time_range=time_range
    )


@router.get("/{incident_id}/root-cause", response_model=RootCauseResponse)
async def get_root_cause_analysis(
    incident_id: UUID,
    db: AsyncSession = Depends(get_database_session)
) -> RootCauseResponse:
    """
    Perform root cause analysis for an incident.
    
    - **incident_id**: Incident UUID
    """
    # Get incident
    query = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )
    
    # Perform root cause analysis
    rca = RootCauseAnalyzer(db)
    analysis = await rca.analyze_incident(incident_id)
    
    # Build candidates list from primary, alternative, and contributing causes
    candidates = []
    if analysis.primary_cause:
        candidates.append(analysis.primary_cause.to_dict())
    candidates.extend([c.to_dict() for c in analysis.alternative_causes])
    candidates.extend([c.to_dict() for c in analysis.contributing_factors])
    
    # Get root cause text from primary cause or explanation
    root_cause = None
    if analysis.primary_cause:
        root_cause = analysis.primary_cause.title
    elif analysis.explanation:
        root_cause = analysis.explanation
    
    return RootCauseResponse(
        incident_id=incident_id,
        root_cause=root_cause,
        confidence=analysis.confidence,
        candidates=candidates,
        analysis_timestamp=datetime.utcnow()
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident: IncidentCreate,
    db: AsyncSession = Depends(get_database_session)
) -> IncidentResponse:
    """
    Manually create an incident.
    
    This endpoint allows manual incident creation for testing or external integrations.
    """
    # Generate incident number
    query = select(func.count(Incident.id))
    result = await db.execute(query)
    count = result.scalar() or 0
    incident_number = f"INC-{count + 1:06d}"
    
    # Create incident
    new_incident = Incident(
        incident_number=incident_number,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        state=EventState.OPEN,
        service_name=incident.service_name,
        team=incident.team,
        detected_at=incident.detected_at or datetime.utcnow(),
        tags=incident.tags
    )
    
    db.add(new_incident)
    await db.commit()
    await db.refresh(new_incident)
    
    logger.info(f"Created incident {incident_number} ({new_incident.id})")
    
    return IncidentResponse.model_validate(new_incident)
