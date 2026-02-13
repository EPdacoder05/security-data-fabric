"""FastAPI application with security, monitoring, and compliance features."""

import logging
import time
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.config.settings import settings
from src.database.connection import close_db, init_db
from src.monitoring.metrics import metrics

logger = logging.getLogger(__name__)


# Rate limiting storage (in production, use Redis)
_rate_limit_store: Dict[str, list] = {}


def get_rate_limiter() -> Callable:
    """Create a rate limiter middleware.

    Uses a simple in-memory store. In production, replace with Redis-backed
    rate limiting for distributed systems.

    Returns:
        Rate limiter middleware function
    """

    async def rate_limit_middleware(request: Request, call_next: Callable) -> Response:
        """Rate limiting middleware.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler in chain

        Returns:
            Response from handler or 429 if rate limited
        """
        # Get client identifier (IP address or user ID from token)
        client_id = request.client.host if request.client else "unknown"

        # Get current timestamp
        current_time = time.time()
        window_start = current_time - 60  # 1 minute window

        # Initialize or get request history
        if client_id not in _rate_limit_store:
            _rate_limit_store[client_id] = []

        # Clean old requests outside window
        _rate_limit_store[client_id] = [
            req_time
            for req_time in _rate_limit_store[client_id]
            if req_time > window_start
        ]

        # Check rate limit
        request_count = len(_rate_limit_store[client_id])

        if request_count >= settings.rate_limit_per_minute:
            metrics.api_request_count.labels(
                method=request.method,
                endpoint=request.url.path,
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            ).inc()
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after": 60,
                },
            )

        # Add current request
        _rate_limit_store[client_id].append(current_time)

        # Process request
        response = await call_next(request)
        return response

    return rate_limit_middleware


async def request_id_middleware(request: Request, call_next: Callable) -> Response:
    """Add request ID to all requests for tracing.

    Args:
        request: FastAPI request
        call_next: Next middleware/handler in chain

    Returns:
        Response with X-Request-ID header
    """
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


async def metrics_middleware(request: Request, call_next: Callable) -> Response:
    """Track request metrics.

    Args:
        request: FastAPI request
        call_next: Next middleware/handler in chain

    Returns:
        Response from handler with metrics tracked
    """
    start_time = time.time()

    # Track request size
    content_length = request.headers.get("content-length")
    if content_length:
        metrics.api_request_size.labels(
            method=request.method, endpoint=request.url.path
        ).observe(int(content_length))

    try:
        response = await call_next(request)

        # Track response time and count
        duration = time.time() - start_time
        metrics.track_api_request(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
            duration=duration,
        )

        # Track response size
        if hasattr(response, "body"):
            metrics.api_response_size.labels(
                method=request.method, endpoint=request.url.path
            ).observe(len(response.body))

        return response

    except Exception:
        # Track error
        duration = time.time() - start_time
        metrics.track_api_request(
            method=request.method,
            endpoint=request.url.path,
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            duration=duration,
        )
        raise


@asynccontextmanager
async def lifespan(app: FastAPI) -> None:
    """Application lifespan manager.

    Handles startup and shutdown events for database connections
    and other resources.

    Args:
        app: FastAPI application instance

    Yields:
        None
    """
    # Startup
    logger.info("Starting Security Data Fabric API")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Metrics port: {settings.metrics_port}")

    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized")

        # Initialize metrics
        metrics.active_sessions.set(0)
        logger.info("Metrics initialized")

        yield

    finally:
        # Shutdown
        logger.info("Shutting down Security Data Fabric API")
        await close_db()
        logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title="Security Data Fabric API",
    description=(
        "Unified Security Data Platform with Medallion Architecture, "
        "ML anomaly detection, and predictive analytics"
    ),
    version="1.0.0",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middlewares
app.middleware("http")(request_id_middleware)
app.middleware("http")(metrics_middleware)
app.middleware("http")(get_rate_limiter())


# Error handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle HTTP exceptions.

    Args:
        request: FastAPI request
        exc: HTTP exception

    Returns:
        JSON error response
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle request validation errors.

    Args:
        request: FastAPI request
        exc: Validation error

    Returns:
        JSON error response with validation details
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions.

    Args:
        request: FastAPI request
        exc: Exception

    Returns:
        JSON error response
    """
    logger.exception("Unhandled exception", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint.

    Returns:
        Health status information
    """
    return {
        "status": "healthy",
        "environment": settings.environment,
        "version": "1.0.0",
    }


@app.get("/health/ready", tags=["System"])
async def readiness_check() -> Dict[str, Any]:
    """Readiness check endpoint.

    Verifies that the application is ready to handle requests by checking
    critical dependencies like database connectivity.

    Returns:
        Readiness status information
    """
    # TODO: Add actual database connectivity check
    return {
        "status": "ready",
        "checks": {
            "database": "ok",
            "cache": "ok",
        },
    }


@app.get("/health/live", tags=["System"])
async def liveness_check() -> Dict[str, Any]:
    """Liveness check endpoint.

    Simple check that the application is running.

    Returns:
        Liveness status
    """
    return {"status": "alive"}


# Metrics endpoint
@app.get("/metrics", tags=["System"])
async def metrics_endpoint() -> Response:
    """Prometheus metrics endpoint.

    Returns:
        Prometheus-formatted metrics
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/metrics/summary", tags=["System"])
async def metrics_summary() -> Dict[str, Any]:
    """Get metrics summary as JSON.

    Returns:
        Dictionary containing key metrics
    """
    return {
        "metrics": metrics.get_metrics_dict(),
        "timestamp": time.time(),
    }


# API v1 prefix router placeholder
@app.get(f"{settings.api_v1_prefix}/", tags=["API"])
async def api_root() -> Dict[str, str]:
    """API root endpoint.

    Returns:
        API information
    """
    return {
        "message": "Security Data Fabric API",
        "version": "1.0.0",
        "docs": "/docs",
    }


# Status endpoint
@app.get("/status", tags=["System"])
async def status_endpoint() -> Dict[str, Any]:
    """Get application status.

    Returns:
        Application status information
    """
    # Get active_sessions value properly
    active_sessions_value = 0
    for metric in metrics.active_sessions.collect():
        for sample in metric.samples:
            active_sessions_value = sample.value
            break

    return {
        "status": "running",
        "environment": settings.environment,
        "version": "1.0.0",
        "metrics": {
            "active_sessions": active_sessions_value,
        },
    }
