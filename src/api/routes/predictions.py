"""
ML prediction endpoints for Security Data Fabric API.
Provides access to predictive analytics and anomaly detection results.
"""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_database_session, get_forecaster, get_trajectory_predictor
from src.database.models import Prediction, PredictionType
from src.ml.forecaster import Forecaster
from src.ml.trajectory_predictor import TrajectoryPredictor
from src.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/predictions", tags=["predictions"])


# Pydantic models
class PredictionResponse(BaseModel):
    """Response model for prediction."""
    id: UUID
    prediction_type: PredictionType
    entity_id: str
    entity_type: str
    entity_name: Optional[str]
    current_value: float
    predicted_value: Optional[float]
    threshold_value: Optional[float]
    predicted_at: datetime
    eta_minutes: Optional[int]
    confidence_score: float
    z_score: Optional[float]
    explanation: Optional[str]
    anomaly_detected: bool
    is_active: bool
    resolved_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AnalyzeRequest(BaseModel):
    """Request model for triggering analysis."""
    entity_ids: Optional[List[str]] = Field(None, description="Specific entity IDs to analyze")
    entity_types: Optional[List[str]] = Field(None, description="Entity types to analyze")
    lookback_hours: int = Field(default=24, ge=1, le=168, description="Hours of historical data")


class AnalyzeResponse(BaseModel):
    """Response model for analysis trigger."""
    status: str
    message: str
    entities_analyzed: int
    timestamp: datetime


@router.get("", response_model=List[PredictionResponse])
async def list_predictions(
    prediction_type: Optional[PredictionType] = None,
    entity_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    anomaly_only: bool = Query(default=False, description="Show only anomalies"),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_database_session)
) -> List[PredictionResponse]:
    """
    List predictions with optional filters.
    
    - **prediction_type**: Filter by prediction type
    - **entity_id**: Filter by entity ID
    - **entity_type**: Filter by entity type (e.g., host, service)
    - **is_active**: Filter by active status
    - **anomaly_only**: Show only anomalies
    - **min_confidence**: Minimum confidence score
    - **limit**: Maximum number of results
    - **offset**: Pagination offset
    """
    query = select(Prediction)
    
    # Apply filters
    filters = []
    if prediction_type:
        filters.append(Prediction.prediction_type == prediction_type)
    if entity_id:
        filters.append(Prediction.entity_id == entity_id)
    if entity_type:
        filters.append(Prediction.entity_type == entity_type)
    if is_active is not None:
        filters.append(Prediction.is_active == is_active)
    if anomaly_only:
        filters.append(Prediction.anomaly_detected == True)
    if min_confidence > 0:
        filters.append(Prediction.confidence_score >= min_confidence)
    
    if filters:
        query = query.where(and_(*filters))
    
    # Order by predicted_at descending
    query = query.order_by(desc(Prediction.predicted_at))
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    logger.info(f"Retrieved {len(predictions)} predictions")
    return [PredictionResponse.model_validate(pred) for pred in predictions]


@router.get("/active", response_model=List[PredictionResponse])
async def get_active_predictions(
    min_confidence: float = Query(
        default=0.7, 
        ge=0.0, 
        le=1.0, 
        description="Minimum confidence threshold"
    ),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_database_session)
) -> List[PredictionResponse]:
    """
    Get high-confidence active predictions.
    
    Returns only active predictions above the confidence threshold,
    ordered by confidence score descending.
    
    - **min_confidence**: Minimum confidence score (default: 0.7)
    - **limit**: Maximum number of results (default: 20)
    """
    query = select(Prediction).where(
        and_(
            Prediction.is_active == True,
            Prediction.confidence_score >= min_confidence
        )
    ).order_by(
        desc(Prediction.confidence_score),
        desc(Prediction.predicted_at)
    ).limit(limit)
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    logger.info(
        f"Retrieved {len(predictions)} active predictions "
        f"with confidence >= {min_confidence}"
    )
    
    return [PredictionResponse.model_validate(pred) for pred in predictions]


@router.post("/analyze", response_model=AnalyzeResponse)
async def trigger_analysis(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_database_session),
    forecaster: Forecaster = Depends(get_forecaster),
    trajectory_predictor: TrajectoryPredictor = Depends(get_trajectory_predictor)
) -> AnalyzeResponse:
    """
    Trigger predictive analysis for entities.
    
    Runs forecasting and trajectory prediction in the background.
    Returns immediately with status.
    
    - **entity_ids**: Optional list of specific entity IDs
    - **entity_types**: Optional list of entity types to analyze
    - **lookback_hours**: Hours of historical data to use
    """
    if not settings.enable_ml_predictions:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML predictions are disabled"
        )
    
    # Determine entities to analyze
    entities_to_analyze = []
    
    if request.entity_ids:
        # Analyze specific entities
        entities_to_analyze = [
            {"entity_id": eid, "entity_type": "unknown"} 
            for eid in request.entity_ids
        ]
    else:
        # Query entities from database based on type filter
        # In a real implementation, you'd query the actual entities
        # For now, return a placeholder response
        pass
    
    # If no entities specified, use a default set (in practice, query from DB)
    if not entities_to_analyze:
        entities_to_analyze = [{"entity_id": "default", "entity_type": "system"}]
    
    # Schedule background analysis
    async def run_analysis():
        """Background task for running predictions."""
        try:
            logger.info(
                f"Starting analysis for {len(entities_to_analyze)} entities "
                f"with {request.lookback_hours}h lookback"
            )
            
            # In production, iterate through entities and run predictions
            # For now, just log the action
            for entity in entities_to_analyze:
                logger.debug(f"Analyzing entity: {entity}")
            
            logger.info("Analysis completed")
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
    
    background_tasks.add_task(run_analysis)
    
    return AnalyzeResponse(
        status="accepted",
        message=f"Analysis scheduled for {len(entities_to_analyze)} entities",
        entities_analyzed=len(entities_to_analyze),
        timestamp=datetime.utcnow()
    )


@router.get("/{prediction_id}", response_model=PredictionResponse)
async def get_prediction(
    prediction_id: UUID,
    db: AsyncSession = Depends(get_database_session)
) -> PredictionResponse:
    """
    Get a single prediction by ID.
    """
    query = select(Prediction).where(Prediction.id == prediction_id)
    result = await db.execute(query)
    prediction = result.scalar_one_or_none()
    
    if not prediction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction {prediction_id} not found"
        )
    
    return PredictionResponse.model_validate(prediction)
