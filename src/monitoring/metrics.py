"""Prometheus metrics for monitoring application performance."""
import logging
import time
from functools import wraps
from typing import Callable

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

logger = logging.getLogger(__name__)


# ============================================================================
# HTTP Metrics
# ============================================================================

http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

http_requests_in_progress = Gauge(
    'http_requests_in_progress',
    'HTTP requests currently in progress',
    ['method', 'endpoint']
)


# ============================================================================
# Cache Metrics
# ============================================================================

cache_hits_total = Counter(
    'cache_hits_total',
    'Total cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

cache_operations_duration_seconds = Histogram(
    'cache_operations_duration_seconds',
    'Cache operation duration in seconds',
    ['operation', 'cache_type'],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1)
)


def cache_hit_rate() -> float:
    """Calculate cache hit rate (0-1)."""
    hits = cache_hits_total._value.get()
    misses = cache_misses_total._value.get()
    total = hits + misses
    return hits / total if total > 0 else 0.0


# ============================================================================
# Database Metrics
# ============================================================================

db_query_duration_seconds = Histogram(
    'db_query_duration_seconds',
    'Database query duration in seconds',
    ['query_type'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

db_connections_active = Gauge(
    'db_connections_active',
    'Number of active database connections'
)

db_queries_total = Counter(
    'db_queries_total',
    'Total database queries',
    ['query_type', 'status']
)


# ============================================================================
# ML Metrics
# ============================================================================

ml_prediction_duration_seconds = Histogram(
    'ml_prediction_duration_seconds',
    'ML prediction duration in seconds',
    ['model_type'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

ml_prediction_errors_total = Counter(
    'ml_prediction_errors_total',
    'Total ML prediction errors',
    ['model_type', 'error_type']
)

ml_predictions_total = Counter(
    'ml_predictions_total',
    'Total ML predictions',
    ['model_type']
)

ml_model_accuracy = Gauge(
    'ml_model_accuracy',
    'ML model accuracy score',
    ['model_type']
)


# ============================================================================
# Business Metrics
# ============================================================================

incidents_created_total = Counter(
    'incidents_created_total',
    'Total security incidents created',
    ['severity']
)

incidents_resolved_total = Counter(
    'incidents_resolved_total',
    'Total security incidents resolved',
    ['severity']
)

mfa_verifications_total = Counter(
    'mfa_verifications_total',
    'Total MFA verifications',
    ['method', 'status']
)

api_tokens_created_total = Counter(
    'api_tokens_created_total',
    'Total API tokens created',
    ['token_type']
)

sla_breaches_total = Counter(
    'sla_breaches_total',
    'Total SLA breaches',
    ['severity']
)

anomalies_detected_total = Counter(
    'anomalies_detected_total',
    'Total anomalies detected',
    ['anomaly_type']
)


# ============================================================================
# System Metrics
# ============================================================================

app_info = Gauge(
    'app_info',
    'Application information',
    ['version', 'environment']
)

background_tasks_active = Gauge(
    'background_tasks_active',
    'Number of active background tasks',
    ['task_type']
)

background_tasks_total = Counter(
    'background_tasks_total',
    'Total background tasks',
    ['task_type', 'status']
)


# ============================================================================
# Decorators for Automatic Instrumentation
# ============================================================================

def track_http_request(method: str, endpoint: str) -> Callable:
    """Decorator to track HTTP request metrics.
    
    Example:
        @track_http_request("POST", "/api/v1/incidents")
        async def create_incident():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            http_requests_in_progress.labels(method=method, endpoint=endpoint).inc()
            start_time = time.perf_counter()

            try:
                result = await func(*args, **kwargs)
                status = getattr(result, 'status_code', 200)

                http_requests_total.labels(
                    method=method,
                    endpoint=endpoint,
                    status=status
                ).inc()

                return result

            except Exception:
                http_requests_total.labels(
                    method=method,
                    endpoint=endpoint,
                    status=500
                ).inc()
                raise

            finally:
                duration = time.perf_counter() - start_time
                http_request_duration_seconds.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(duration)

                http_requests_in_progress.labels(
                    method=method,
                    endpoint=endpoint
                ).dec()

        return wrapper
    return decorator


def track_cache_operation(operation: str, cache_type: str = "redis") -> Callable:
    """Decorator to track cache operation metrics.
    
    Example:
        @track_cache_operation("get", "redis")
        async def get_from_cache(key):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.perf_counter()

            try:
                result = await func(*args, **kwargs)

                # Track hit/miss
                if operation == "get":
                    if result is not None:
                        cache_hits_total.labels(cache_type=cache_type).inc()
                    else:
                        cache_misses_total.labels(cache_type=cache_type).inc()

                return result

            finally:
                duration = time.perf_counter() - start_time
                cache_operations_duration_seconds.labels(
                    operation=operation,
                    cache_type=cache_type
                ).observe(duration)

        return wrapper
    return decorator


def track_db_query(query_type: str) -> Callable:
    """Decorator to track database query metrics.
    
    Example:
        @track_db_query("select")
        async def get_incidents():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.perf_counter()

            try:
                result = await func(*args, **kwargs)

                db_queries_total.labels(
                    query_type=query_type,
                    status="success"
                ).inc()

                return result

            except Exception:
                db_queries_total.labels(
                    query_type=query_type,
                    status="error"
                ).inc()
                raise

            finally:
                duration = time.perf_counter() - start_time
                db_query_duration_seconds.labels(
                    query_type=query_type
                ).observe(duration)

        return wrapper
    return decorator


def track_ml_prediction(model_type: str) -> Callable:
    """Decorator to track ML prediction metrics.
    
    Example:
        @track_ml_prediction("forecaster")
        async def predict_incidents():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.perf_counter()

            try:
                result = await func(*args, **kwargs)

                ml_predictions_total.labels(model_type=model_type).inc()

                return result

            except Exception as e:
                error_type = type(e).__name__
                ml_prediction_errors_total.labels(
                    model_type=model_type,
                    error_type=error_type
                ).inc()
                raise

            finally:
                duration = time.perf_counter() - start_time
                ml_prediction_duration_seconds.labels(
                    model_type=model_type
                ).observe(duration)

        return wrapper
    return decorator


# ============================================================================
# Metrics Endpoint
# ============================================================================

def get_metrics() -> tuple[bytes, str]:
    """Generate Prometheus metrics in text format.
    
    Returns:
        Tuple of (metrics_bytes, content_type)
    """
    return generate_latest(), CONTENT_TYPE_LATEST


def initialize_metrics(version: str, environment: str) -> None:
    """Initialize application metrics.
    
    Args:
        version: Application version
        environment: Environment (development, staging, production)
    """
    app_info.labels(version=version, environment=environment).set(1)
    logger.info("Prometheus metrics initialized: version=%s, environment=%s", version, environment)
