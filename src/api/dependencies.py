"""
FastAPI dependencies for Security Data Fabric API.
Provides database sessions, Redis connections, ML models, and API key validation.
"""
import logging
from typing import AsyncGenerator, Optional
from functools import lru_cache

from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from src.database.connection import get_db
from src.config.settings import settings
from src.ml.embedding_engine import EmbeddingEngine
from src.ml.anomaly_detector import AnomalyDetector
from src.ml.forecaster import Forecaster
from src.ml.trajectory_predictor import TrajectoryPredictor

logger = logging.getLogger(__name__)


# Database dependency (re-export from connection.py)
async def get_database_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency."""
    async for session in get_db():
        yield session


# Redis connection pool
_redis_pool: Optional[redis.ConnectionPool] = None


async def get_redis_pool() -> redis.ConnectionPool:
    """Get or create Redis connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=settings.redis_max_connections,
            decode_responses=True
        )
        logger.info("Redis connection pool created")
    return _redis_pool


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """Get Redis connection dependency."""
    pool = await get_redis_pool()
    client = redis.Redis(connection_pool=pool)
    try:
        yield client
    finally:
        await client.close()


async def close_redis_pool():
    """Close Redis connection pool (call on shutdown)."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.disconnect()
        _redis_pool = None
        logger.info("Redis connection pool closed")


# ML Model instances (lazy loading with caching)
_embedding_engine: Optional[EmbeddingEngine] = None
_anomaly_detector: Optional[AnomalyDetector] = None
_forecaster: Optional[Forecaster] = None
_trajectory_predictor: Optional[TrajectoryPredictor] = None


@lru_cache(maxsize=1)
def get_embedding_engine() -> EmbeddingEngine:
    """Get embedding engine instance (lazy loaded, cached)."""
    global _embedding_engine
    if _embedding_engine is None:
        if not settings.enable_semantic_search:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Semantic search is disabled"
            )
        _embedding_engine = EmbeddingEngine(model_name=settings.ml_embedding_model)
        logger.info("Embedding engine initialized")
    return _embedding_engine


@lru_cache(maxsize=1)
def get_anomaly_detector() -> AnomalyDetector:
    """Get anomaly detector instance (lazy loaded, cached)."""
    global _anomaly_detector
    if _anomaly_detector is None:
        if not settings.enable_ml_predictions:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML predictions are disabled"
            )
        _anomaly_detector = AnomalyDetector(threshold=settings.ml_anomaly_threshold)
        logger.info("Anomaly detector initialized")
    return _anomaly_detector


@lru_cache(maxsize=1)
def get_forecaster() -> Forecaster:
    """Get forecaster instance (lazy loaded, cached)."""
    global _forecaster
    if _forecaster is None:
        if not settings.enable_ml_predictions:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML predictions are disabled"
            )
        _forecaster = Forecaster()
        logger.info("Forecaster initialized")
    return _forecaster


@lru_cache(maxsize=1)
def get_trajectory_predictor() -> TrajectoryPredictor:
    """Get trajectory predictor instance (lazy loaded, cached)."""
    global _trajectory_predictor
    if _trajectory_predictor is None:
        if not settings.enable_ml_predictions:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML predictions are disabled"
            )
        _trajectory_predictor = TrajectoryPredictor(model_path=settings.ml_model_path)
        logger.info("Trajectory predictor initialized")
    return _trajectory_predictor


# API Key validation (optional)
async def validate_api_key(
    x_api_key: Optional[str] = Header(None, alias=settings.api_key_header)
) -> Optional[str]:
    """
    Validate API key if provided.
    Note: This is a basic implementation. In production, validate against database.
    """
    # If no API key header is sent, allow request (optional auth)
    if x_api_key is None:
        return None
    
    # In production, validate against database or external service
    # For now, accept any non-empty key (placeholder implementation)
    if not x_api_key or len(x_api_key) < 10:
        logger.warning(f"Invalid API key format: {x_api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    return x_api_key


# Required API key validation
async def require_api_key(
    x_api_key: str = Header(..., alias=settings.api_key_header)
) -> str:
    """Require valid API key for protected endpoints."""
    if not x_api_key or len(x_api_key) < 10:
        logger.warning(f"Missing or invalid API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # In production, validate against database
    return x_api_key


# Cleanup function for shutdown
async def cleanup_dependencies():
    """Cleanup all dependencies (call on shutdown)."""
    await close_redis_pool()
    
    # Clear model caches
    global _embedding_engine, _anomaly_detector, _forecaster, _trajectory_predictor
    _embedding_engine = None
    _anomaly_detector = None
    _forecaster = None
    _trajectory_predictor = None
    
    # Clear LRU caches
    get_embedding_engine.cache_clear()
    get_anomaly_detector.cache_clear()
    get_forecaster.cache_clear()
    get_trajectory_predictor.cache_clear()
    
    logger.info("All dependencies cleaned up")
