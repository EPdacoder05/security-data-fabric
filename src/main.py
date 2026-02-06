"""FastAPI application entry point for Security Data Fabric."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import settings
from src.database import init_db, close_db
from src.observability import setup_logging, get_logger
from src.api.middleware import setup_middleware
from src.api.routes import health, ingest, predictions, dashboard, incidents
from src.search import search_router

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for startup and shutdown events.
    
    Args:
        app: FastAPI application instance
        
    Yields:
        None
    """
    # Startup
    logger.info("Starting Security Data Fabric API")
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Security Data Fabric API")
    try:
        await close_db()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database: {e}", exc_info=True)


# Create FastAPI application
app = FastAPI(
    title="Security Data Fabric API",
    description="Unified Security Data Platform with medallion architecture, pgvector semantic search, ML-powered anomaly detection, and predictive analytics",
    version="0.1.0",
    lifespan=lifespan,
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup custom middleware
setup_middleware(app)

# Register routers
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(predictions.router)
app.include_router(dashboard.router)
app.include_router(incidents.router)
app.include_router(search_router)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Security Data Fabric API",
        "version": "0.1.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "readiness": "/ready",
            "documentation": "/docs",
            "openapi": "/openapi.json",
        },
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
