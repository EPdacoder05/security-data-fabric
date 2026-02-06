"""Prediction query endpoints."""
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db, models
from src.api.dependencies import get_current_user, CurrentUser
from src.observability import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/predictions", tags=["predictions"])


class PredictionResponse(BaseModel):
    """Prediction response model."""

    id: str
    prediction_type: str
    target_metric: str
    current_value: float
    predicted_value: Optional[float]
    threshold_value: Optional[float]
    time_to_breach: Optional[int]
    confidence: float
    severity: int
    details: Optional[dict]
    created_at: datetime
    expires_at: Optional[datetime]
    resolved: bool

    class Config:
        from_attributes = True


class PredictionListResponse(BaseModel):
    """List of predictions response."""

    predictions: List[PredictionResponse]
    total: int
    page: int
    page_size: int


@router.get("/active", response_model=PredictionListResponse)
async def get_active_predictions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity_min: Optional[int] = Query(None, ge=1, le=5),
    prediction_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> PredictionListResponse:
    """Get active predictions.
    
    Args:
        page: Page number
        page_size: Items per page
        severity_min: Minimum severity filter
        prediction_type: Filter by prediction type
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        List of active predictions
    """
    logger.info(
        "Fetching active predictions",
        extra={
            "page": page,
            "page_size": page_size,
            "severity_min": severity_min,
            "prediction_type": prediction_type,
        },
    )
    
    # Build query
    query = select(models.Prediction).where(
        and_(
            models.Prediction.resolved == False,
            models.Prediction.expires_at > datetime.utcnow(),
        )
    )
    
    if severity_min is not None:
        query = query.where(models.Prediction.severity >= severity_min)
    
    if prediction_type:
        query = query.where(models.Prediction.prediction_type == prediction_type)
    
    # Order by severity and created_at
    query = query.order_by(
        models.Prediction.severity.desc(),
        models.Prediction.created_at.desc(),
    )
    
    # Count total
    count_query = select(models.Prediction).where(
        and_(
            models.Prediction.resolved == False,
            models.Prediction.expires_at > datetime.utcnow(),
        )
    )
    if severity_min is not None:
        count_query = count_query.where(models.Prediction.severity >= severity_min)
    if prediction_type:
        count_query = count_query.where(models.Prediction.prediction_type == prediction_type)
    
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    return PredictionListResponse(
        predictions=[
            PredictionResponse(
                id=str(p.id),
                prediction_type=p.prediction_type,
                target_metric=p.target_metric,
                current_value=p.current_value,
                predicted_value=p.predicted_value,
                threshold_value=p.threshold_value,
                time_to_breach=p.time_to_breach,
                confidence=p.confidence,
                severity=p.severity,
                details=p.details,
                created_at=p.created_at,
                expires_at=p.expires_at,
                resolved=p.resolved,
            )
            for p in predictions
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/history", response_model=PredictionListResponse)
async def get_prediction_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> PredictionListResponse:
    """Get prediction history.
    
    Args:
        page: Page number
        page_size: Items per page
        days: Number of days to look back
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        List of historical predictions
    """
    logger.info(
        "Fetching prediction history",
        extra={"page": page, "page_size": page_size, "days": days},
    )
    
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Build query
    query = select(models.Prediction).where(
        models.Prediction.created_at >= cutoff
    ).order_by(models.Prediction.created_at.desc())
    
    # Count total
    count_query = select(models.Prediction).where(
        models.Prediction.created_at >= cutoff
    )
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    return PredictionListResponse(
        predictions=[
            PredictionResponse(
                id=str(p.id),
                prediction_type=p.prediction_type,
                target_metric=p.target_metric,
                current_value=p.current_value,
                predicted_value=p.predicted_value,
                threshold_value=p.threshold_value,
                time_to_breach=p.time_to_breach,
                confidence=p.confidence,
                severity=p.severity,
                details=p.details,
                created_at=p.created_at,
                expires_at=p.expires_at,
                resolved=p.resolved,
            )
            for p in predictions
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{prediction_id}", response_model=PredictionResponse)
async def get_prediction(
    prediction_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> PredictionResponse:
    """Get specific prediction by ID.
    
    Args:
        prediction_id: Prediction UUID
        db: Database session
        current_user: Current user (optional)
        
    Returns:
        Prediction details
        
    Raises:
        HTTPException: If prediction not found
    """
    logger.info(f"Fetching prediction", extra={"prediction_id": str(prediction_id)})
    
    query = select(models.Prediction).where(models.Prediction.id == prediction_id)
    result = await db.execute(query)
    prediction = result.scalar_one_or_none()
    
    if not prediction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction {prediction_id} not found",
        )
    
    return PredictionResponse(
        id=str(prediction.id),
        prediction_type=prediction.prediction_type,
        target_metric=prediction.target_metric,
        current_value=prediction.current_value,
        predicted_value=prediction.predicted_value,
        threshold_value=prediction.threshold_value,
        time_to_breach=prediction.time_to_breach,
        confidence=prediction.confidence,
        severity=prediction.severity,
        details=prediction.details,
        created_at=prediction.created_at,
        expires_at=prediction.expires_at,
        resolved=prediction.resolved,
    )
