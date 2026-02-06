"""API module for Security Data Fabric."""
from src.api import middleware, dependencies
from src.api.routes import health, ingest, predictions, dashboard, incidents

__all__ = [
    "middleware",
    "dependencies",
    "health",
    "ingest",
    "predictions",
    "dashboard",
    "incidents",
]
