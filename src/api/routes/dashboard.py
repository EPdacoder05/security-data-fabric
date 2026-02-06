"""Dashboard data endpoints."""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db, models
from src.api.dependencies import get_current_user, CurrentUser
from src.observability import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class MetricData(BaseModel):
    """Metric data point."""

    label: str
    value: int
    change_percent: Optional[float] = None


class OverviewResponse(BaseModel):
    """CISO dashboard overview response."""

    total_events_today: MetricData
    active_incidents: MetricData
    active_predictions: MetricData
    critical_alerts: MetricData
    avg_risk_score: float
    top_event_sources: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]
    recent_activity: List[Dict[str, Any]]
    timestamp: datetime


class RiskScoreItem(BaseModel):
    """Risk score for an asset."""

    asset_id: str
    asset_name: str
    risk_score: float
    severity: int
    last_updated: datetime
    event_count: int


class RiskScoresResponse(BaseModel):
    """Risk scores response."""

    risk_scores: List[RiskScoreItem]
    total: int
    page: int
    page_size: int


class TimelineEvent(BaseModel):
    """Timeline event item."""

    event_id: str
    timestamp: datetime
    event_type: str
    severity: int
    title: str
    description: Optional[str]
    risk_score: Optional[float]


class TimelineResponse(BaseModel):
    """Incident timeline response."""

    incident_id: str
    title: str
    start_time: datetime
    end_time: Optional[datetime]
    events: List[TimelineEvent]
    root_cause: Optional[Dict[str, Any]]
    impact: Optional[str]
    resolution: Optional[str]


@router.get("/overview", response_model=OverviewResponse)
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> OverviewResponse:
    """Get CISO dashboard overview with key metrics.
    
    Args:
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        Dashboard overview data
    """
    logger.info("Fetching dashboard overview")
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    
    # Total events today
    today_events_query = select(func.count(models.NormalizedEvent.id)).where(
        models.NormalizedEvent.created_at >= today_start
    )
    today_events_result = await db.execute(today_events_query)
    today_events_count = today_events_result.scalar() or 0
    
    # Yesterday events for comparison
    yesterday_events_query = select(func.count(models.NormalizedEvent.id)).where(
        and_(
            models.NormalizedEvent.created_at >= yesterday_start,
            models.NormalizedEvent.created_at < today_start,
        )
    )
    yesterday_events_result = await db.execute(yesterday_events_query)
    yesterday_events_count = yesterday_events_result.scalar() or 0
    
    events_change = (
        ((today_events_count - yesterday_events_count) / yesterday_events_count * 100)
        if yesterday_events_count > 0
        else 0.0
    )
    
    # Active incidents (incidents with no end_time)
    active_incidents_query = select(func.count(models.IncidentTimeline.id)).where(
        models.IncidentTimeline.end_time.is_(None)
    )
    active_incidents_result = await db.execute(active_incidents_query)
    active_incidents_count = active_incidents_result.scalar() or 0
    
    # Active predictions
    active_predictions_query = select(func.count(models.Prediction.id)).where(
        and_(
            models.Prediction.resolved == False,
            models.Prediction.expires_at > now,
        )
    )
    active_predictions_result = await db.execute(active_predictions_query)
    active_predictions_count = active_predictions_result.scalar() or 0
    
    # Critical alerts (severity 5, status open)
    critical_alerts_query = select(func.count(models.Alert.id)).where(
        and_(
            models.Alert.severity == 5,
            models.Alert.status == "open",
        )
    )
    critical_alerts_result = await db.execute(critical_alerts_query)
    critical_alerts_count = critical_alerts_result.scalar() or 0
    
    # Average risk score
    avg_risk_query = select(func.avg(models.EnrichedEvent.risk_score)).where(
        and_(
            models.EnrichedEvent.enriched_at >= today_start,
            models.EnrichedEvent.risk_score.isnot(None),
        )
    )
    avg_risk_result = await db.execute(avg_risk_query)
    avg_risk_score = float(avg_risk_result.scalar() or 0.0)
    
    # Top event sources
    top_sources_query = (
        select(
            models.NormalizedEvent.source,
            func.count(models.NormalizedEvent.id).label("count"),
        )
        .where(models.NormalizedEvent.created_at >= today_start)
        .group_by(models.NormalizedEvent.source)
        .order_by(func.count(models.NormalizedEvent.id).desc())
        .limit(5)
    )
    top_sources_result = await db.execute(top_sources_query)
    top_sources = [
        {"source": row[0], "count": row[1]} for row in top_sources_result.all()
    ]
    
    # Severity distribution
    severity_dist_query = (
        select(
            models.NormalizedEvent.severity,
            func.count(models.NormalizedEvent.id).label("count"),
        )
        .where(models.NormalizedEvent.created_at >= today_start)
        .group_by(models.NormalizedEvent.severity)
    )
    severity_dist_result = await db.execute(severity_dist_query)
    severity_distribution = {
        str(row[0]): row[1] for row in severity_dist_result.all()
    }
    
    # Recent activity (last 10 events)
    recent_query = (
        select(models.NormalizedEvent)
        .order_by(models.NormalizedEvent.timestamp.desc())
        .limit(10)
    )
    recent_result = await db.execute(recent_query)
    recent_events = recent_result.scalars().all()
    recent_activity = [
        {
            "event_id": str(e.id),
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "severity": e.severity,
            "title": e.title,
            "source": e.source,
        }
        for e in recent_events
    ]
    
    return OverviewResponse(
        total_events_today=MetricData(
            label="Total Events Today",
            value=today_events_count,
            change_percent=round(events_change, 2),
        ),
        active_incidents=MetricData(
            label="Active Incidents",
            value=active_incidents_count,
        ),
        active_predictions=MetricData(
            label="Active Predictions",
            value=active_predictions_count,
        ),
        critical_alerts=MetricData(
            label="Critical Alerts",
            value=critical_alerts_count,
        ),
        avg_risk_score=round(avg_risk_score, 2),
        top_event_sources=top_sources,
        severity_distribution=severity_distribution,
        recent_activity=recent_activity,
        timestamp=now,
    )


@router.get("/risk-scores", response_model=RiskScoresResponse)
async def get_risk_scores(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    min_severity: Optional[int] = Query(None, ge=1, le=5),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> RiskScoresResponse:
    """Get risk scores for assets.
    
    Args:
        page: Page number
        page_size: Items per page
        min_severity: Minimum severity filter
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        List of risk scores by asset
    """
    logger.info(
        "Fetching risk scores",
        extra={"page": page, "page_size": page_size, "min_severity": min_severity},
    )
    
    # Group by incident_id and calculate risk metrics
    query = (
        select(
            models.EnrichedEvent.incident_id,
            func.max(models.EnrichedEvent.risk_score).label("max_risk"),
            func.count(models.EnrichedEvent.id).label("event_count"),
            func.max(models.EnrichedEvent.enriched_at).label("last_updated"),
        )
        .where(
            and_(
                models.EnrichedEvent.incident_id.isnot(None),
                models.EnrichedEvent.risk_score.isnot(None),
            )
        )
        .group_by(models.EnrichedEvent.incident_id)
        .order_by(func.max(models.EnrichedEvent.risk_score).desc())
    )
    
    # Count total
    count_result = await db.execute(query)
    total = len(count_result.all())
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    result = await db.execute(query)
    rows = result.all()
    
    risk_scores = []
    for row in rows:
        incident_id = row[0]
        max_risk = float(row[1]) if row[1] else 0.0
        event_count = row[2]
        last_updated = row[3]
        
        # Calculate severity from risk score
        if max_risk >= 90:
            severity = 5
        elif max_risk >= 70:
            severity = 4
        elif max_risk >= 50:
            severity = 3
        elif max_risk >= 30:
            severity = 2
        else:
            severity = 1
        
        if min_severity is not None and severity < min_severity:
            continue
        
        risk_scores.append(
            RiskScoreItem(
                asset_id=incident_id,
                asset_name=f"Incident {incident_id}",
                risk_score=round(max_risk, 2),
                severity=severity,
                last_updated=last_updated,
                event_count=event_count,
            )
        )
    
    return RiskScoresResponse(
        risk_scores=risk_scores,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/timeline/{incident_id}", response_model=TimelineResponse)
async def get_incident_timeline(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> TimelineResponse:
    """Get incident timeline with events.
    
    Args:
        incident_id: Incident ID
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        Incident timeline with events
        
    Raises:
        HTTPException: If incident not found
    """
    logger.info(f"Fetching incident timeline", extra={"incident_id": incident_id})
    
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
    
    # Parse timeline events from JSON
    timeline_events = []
    for event_data in timeline.events:
        timeline_events.append(
            TimelineEvent(
                event_id=event_data.get("event_id", "unknown"),
                timestamp=datetime.fromisoformat(event_data.get("timestamp")),
                event_type=event_data.get("event_type", "unknown"),
                severity=event_data.get("severity", 1),
                title=event_data.get("title", ""),
                description=event_data.get("description"),
                risk_score=event_data.get("risk_score"),
            )
        )
    
    return TimelineResponse(
        incident_id=timeline.incident_id,
        title=timeline.title,
        start_time=timeline.start_time,
        end_time=timeline.end_time,
        events=timeline_events,
        root_cause=timeline.root_cause,
        impact=timeline.impact,
        resolution=timeline.resolution,
    )
