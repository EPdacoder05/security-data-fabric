"""
API routes for Security Data Fabric.
"""
from src.api.routes import (
    health,
    incidents,
    predictions,
    search,
    dashboard,
    ingest
)

__all__ = [
    "health",
    "incidents",
    "predictions",
    "search",
    "dashboard",
    "ingest"
]
