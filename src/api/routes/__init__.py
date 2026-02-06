"""API routes module."""
from src.api.routes import health, ingest, predictions, dashboard, incidents

__all__ = [
    "health",
    "ingest",
    "predictions",
    "dashboard",
    "incidents",
]
