"""
CISO dashboard endpoints for Security Data Fabric API.
Provides high-level metrics and trends for executive visibility.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_database_session
from src.database.models import (
    Incident, NormalizedEvent, Prediction,
    EventSeverity, EventState, PredictionType
)
from src.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


# Pydantic models
class SeverityCount(BaseModel):
    """Count by severity."""
    severity: EventSeverity
    count: int


class StateCount(BaseModel):
    """Count by state."""
    state: EventState
    count: int


class OverviewResponse(BaseModel):
    """Dashboard overview response."""
    timestamp: datetime
    time_range_hours: int
    incidents: Dict[str, Any]
    events: Dict[str, Any]
    predictions: Dict[str, Any]
    top_affected_services: List[Dict[str, Any]]


class RiskDataPoint(BaseModel):
    """Single data point in risk trend."""
    timestamp: datetime
    avg_risk_score: float
    incident_count: int
    high_severity_count: int


class RiskTrendResponse(BaseModel):
    """Risk trend over time response."""
    time_range_hours: int
    data_points: List[RiskDataPoint]
    summary: Dict[str, Any]


@router.get("/overview", response_model=OverviewResponse)
async def get_dashboard_overview(
    hours: int = Query(default=24, ge=1, le=168, description="Time range in hours"),
    db: AsyncSession = Depends(get_database_session)
) -> OverviewResponse:
    """
    Get CISO dashboard overview with summary statistics.
    
    Provides key metrics including:
    - Incident counts by severity and state
    - Event volumes by severity
    - Active predictions and anomalies
    - Top affected services
    
    **Parameters:**
    - **hours**: Time range for metrics (1-168 hours, default: 24)
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Incident statistics
    incident_query = select(
        Incident.severity,
        Incident.state,
        func.count(Incident.id).label("count")
    ).where(
        Incident.detected_at >= cutoff_time
    ).group_by(Incident.severity, Incident.state)
    
    incident_result = await db.execute(incident_query)
    incident_rows = incident_result.all()
    
    incidents_by_severity = {}
    incidents_by_state = {}
    total_incidents = 0
    
    for row in incident_rows:
        severity = row.severity.value
        state = row.state.value
        count = row.count
        
        incidents_by_severity[severity] = incidents_by_severity.get(severity, 0) + count
        incidents_by_state[state] = incidents_by_state.get(state, 0) + count
        total_incidents += count
    
    # Event statistics
    event_query = select(
        NormalizedEvent.severity,
        func.count(NormalizedEvent.id).label("count")
    ).where(
        NormalizedEvent.timestamp >= cutoff_time
    ).group_by(NormalizedEvent.severity)
    
    event_result = await db.execute(event_query)
    event_rows = event_result.all()
    
    events_by_severity = {row.severity.value: row.count for row in event_rows}
    total_events = sum(events_by_severity.values())
    
    # Prediction statistics
    prediction_query = select(
        func.count(Prediction.id).label("total"),
        func.sum(func.cast(Prediction.is_active, int)).label("active"),
        func.sum(func.cast(Prediction.anomaly_detected, int)).label("anomalies")
    ).where(
        Prediction.predicted_at >= cutoff_time
    )
    
    pred_result = await db.execute(prediction_query)
    pred_row = pred_result.one()
    
    predictions = {
        "total": pred_row.total or 0,
        "active": pred_row.active or 0,
        "anomalies": pred_row.anomalies or 0
    }
    
    # Top affected services
    service_query = select(
        Incident.service_name,
        func.count(Incident.id).label("incident_count"),
        func.avg(Incident.risk_score).label("avg_risk")
    ).where(
        and_(
            Incident.detected_at >= cutoff_time,
            Incident.service_name.isnot(None)
        )
    ).group_by(
        Incident.service_name
    ).order_by(
        desc("incident_count")
    ).limit(10)
    
    service_result = await db.execute(service_query)
    service_rows = service_result.all()
    
    top_services = [
        {
            "service_name": row.service_name,
            "incident_count": row.incident_count,
            "avg_risk_score": round(row.avg_risk, 2) if row.avg_risk else None
        }
        for row in service_rows
    ]
    
    logger.info(f"Dashboard overview generated for {hours}h timeframe")
    
    return OverviewResponse(
        timestamp=datetime.utcnow(),
        time_range_hours=hours,
        incidents={
            "total": total_incidents,
            "by_severity": incidents_by_severity,
            "by_state": incidents_by_state
        },
        events={
            "total": total_events,
            "by_severity": events_by_severity
        },
        predictions=predictions,
        top_affected_services=top_services
    )


@router.get("/risk-trend", response_model=RiskTrendResponse)
async def get_risk_trend(
    hours: int = Query(default=168, ge=24, le=720, description="Time range in hours"),
    interval_hours: int = Query(default=24, ge=1, le=24, description="Data point interval"),
    db: AsyncSession = Depends(get_database_session)
) -> RiskTrendResponse:
    """
    Get risk trend over time.
    
    Returns time-series data showing risk score trends and incident patterns.
    
    **Parameters:**
    - **hours**: Total time range (24-720 hours, default: 168)
    - **interval_hours**: Interval between data points (1-24 hours, default: 24)
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    data_points = []
    
    # Generate time buckets
    num_buckets = hours // interval_hours
    
    for i in range(num_buckets):
        bucket_end = datetime.utcnow() - timedelta(hours=i * interval_hours)
        bucket_start = bucket_end - timedelta(hours=interval_hours)
        
        # Query incidents in this bucket
        query = select(
            func.count(Incident.id).label("count"),
            func.avg(Incident.risk_score).label("avg_risk"),
            func.sum(
                func.cast(
                    Incident.severity.in_([EventSeverity.CRITICAL, EventSeverity.EXTREME]),
                    int
                )
            ).label("high_severity")
        ).where(
            and_(
                Incident.detected_at >= bucket_start,
                Incident.detected_at < bucket_end
            )
        )
        
        result = await db.execute(query)
        row = result.one()
        
        data_points.append(
            RiskDataPoint(
                timestamp=bucket_start,
                avg_risk_score=round(row.avg_risk, 2) if row.avg_risk else 0.0,
                incident_count=row.count or 0,
                high_severity_count=row.high_severity or 0
            )
        )
    
    # Reverse to get chronological order
    data_points.reverse()
    
    # Calculate summary statistics
    total_incidents = sum(dp.incident_count for dp in data_points)
    avg_risk = sum(dp.avg_risk_score for dp in data_points) / len(data_points) if data_points else 0.0
    total_high_severity = sum(dp.high_severity_count for dp in data_points)
    
    summary = {
        "total_incidents": total_incidents,
        "avg_risk_score": round(avg_risk, 2),
        "total_high_severity": total_high_severity,
        "data_point_count": len(data_points)
    }
    
    logger.info(f"Risk trend generated: {hours}h range, {len(data_points)} data points")
    
    return RiskTrendResponse(
        time_range_hours=hours,
        data_points=data_points,
        summary=summary
    )
