"""Health check endpoints."""
from datetime import datetime
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.observability import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: datetime
    version: str = "0.1.0"


class ReadinessResponse(BaseModel):
    """Readiness check response model."""

    status: str
    timestamp: datetime
    checks: dict[str, bool]
    version: str = "0.1.0"


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check() -> HealthResponse:
    """Basic health check endpoint.
    
    Returns:
        Health status
    """
    return HealthResponse(status="healthy", timestamp=datetime.utcnow())


@router.get("/ready", response_model=ReadinessResponse, status_code=status.HTTP_200_OK)
async def readiness_check(db: AsyncSession = Depends(get_db)) -> ReadinessResponse:
    """Readiness check with dependency verification.
    
    Checks:
        - Database connectivity
        
    Args:
        db: Database session
        
    Returns:
        Readiness status with check results
    """
    checks = {}
    overall_status = "ready"
    
    # Check database
    try:
        result = await db.execute(text("SELECT 1"))
        checks["database"] = result.scalar() == 1
    except Exception as e:
        logger.error(f"Database readiness check failed: {e}")
        checks["database"] = False
        overall_status = "not_ready"
    
    return ReadinessResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        checks=checks,
    )
