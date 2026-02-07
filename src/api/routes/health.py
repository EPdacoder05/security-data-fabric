"""
Health check endpoints for Security Data Fabric API.
Provides liveness, readiness, and version information.
"""
import logging
from typing import Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from src.api.dependencies import get_database_session, get_redis
from src.config.settings import settings
from src.database.connection import db_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """
    Liveness check - returns 200 if service is running.
    Used by orchestrators to determine if the service should be restarted.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": settings.app_name,
        "version": settings.app_version
    }


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check(
    db: AsyncSession = Depends(get_database_session),
    redis_client: redis.Redis = Depends(get_redis)
) -> JSONResponse:
    """
    Readiness check - verifies all dependencies are available.
    Returns 200 if ready to serve traffic, 503 if not ready.
    """
    checks = {
        "database": "unknown",
        "redis": "unknown",
    }
    all_healthy = True
    
    # Check database
    try:
        healthy = await db_manager.health_check()
        checks["database"] = "healthy" if healthy else "unhealthy"
        if not healthy:
            all_healthy = False
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        checks["database"] = f"error: {str(e)}"
        all_healthy = False
    
    # Check Redis
    try:
        await redis_client.ping()
        checks["redis"] = "healthy"
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        checks["redis"] = f"error: {str(e)}"
        all_healthy = False
    
    response_data = {
        "status": "ready" if all_healthy else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
        "service": settings.app_name,
        "version": settings.app_version
    }
    
    status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return JSONResponse(
        status_code=status_code,
        content=response_data
    )


@router.get("/version", status_code=status.HTTP_200_OK)
async def version_info() -> Dict[str, Any]:
    """
    Version information endpoint.
    Returns service name, version, and environment details.
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "debug": settings.debug,
        "features": {
            "ml_predictions": settings.enable_ml_predictions,
            "semantic_search": settings.enable_semantic_search,
            "auto_ticketing": settings.enable_auto_ticketing,
        },
        "timestamp": datetime.utcnow().isoformat()
    }
