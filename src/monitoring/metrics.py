"""Prometheus metrics for monitoring application performance and health."""

from typing import Dict, Optional

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class PrometheusMetrics:
    """Centralized Prometheus metrics collection for the application.

    This class provides a unified interface for tracking various application
    metrics including API performance, database operations, cache efficiency,
    authentication events, and security incidents.
    """

    def __init__(
        self, registry: Optional[CollectorRegistry] = None, namespace: str = "security_fabric"
    ) -> None:
        """Initialize Prometheus metrics.

        Args:
            registry: Optional custom Prometheus registry. If None, uses default registry.
            namespace: Metric namespace prefix. Defaults to 'security_fabric'.
        """
        self._registry = registry
        self._namespace = namespace

        # API Request Metrics
        self.api_request_count = Counter(
            name=f"{namespace}_api_requests_total",
            documentation="Total number of API requests",
            labelnames=["method", "endpoint", "status"],
            registry=registry,
        )

        self.api_request_duration = Histogram(
            name=f"{namespace}_api_request_duration_seconds",
            documentation="API request duration in seconds",
            labelnames=["method", "endpoint"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=registry,
        )

        self.api_request_size = Histogram(
            name=f"{namespace}_api_request_size_bytes",
            documentation="API request size in bytes",
            labelnames=["method", "endpoint"],
            buckets=(100, 1000, 10000, 100000, 1000000),
            registry=registry,
        )

        self.api_response_size = Histogram(
            name=f"{namespace}_api_response_size_bytes",
            documentation="API response size in bytes",
            labelnames=["method", "endpoint"],
            buckets=(100, 1000, 10000, 100000, 1000000),
            registry=registry,
        )

        # Database Metrics
        self.db_query_duration = Histogram(
            name=f"{namespace}_db_query_duration_seconds",
            documentation="Database query duration in seconds",
            labelnames=["query_type", "table"],
            buckets=(0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0),
            registry=registry,
        )

        self.db_connection_pool_size = Gauge(
            name=f"{namespace}_db_connection_pool_size",
            documentation="Current database connection pool size",
            registry=registry,
        )

        self.db_connection_pool_available = Gauge(
            name=f"{namespace}_db_connection_pool_available",
            documentation="Available database connections in pool",
            registry=registry,
        )

        # Cache Metrics
        self.cache_hits = Counter(
            name=f"{namespace}_cache_hits_total",
            documentation="Total number of cache hits",
            labelnames=["cache_type", "key_pattern"],
            registry=registry,
        )

        self.cache_misses = Counter(
            name=f"{namespace}_cache_misses_total",
            documentation="Total number of cache misses",
            labelnames=["cache_type", "key_pattern"],
            registry=registry,
        )

        self.cache_size = Gauge(
            name=f"{namespace}_cache_size_bytes",
            documentation="Current cache size in bytes",
            labelnames=["cache_type"],
            registry=registry,
        )

        self.cache_operation_duration = Histogram(
            name=f"{namespace}_cache_operation_duration_seconds",
            documentation="Cache operation duration in seconds",
            labelnames=["operation", "cache_type"],
            buckets=(0.0001, 0.001, 0.01, 0.05, 0.1, 0.5, 1.0),
            registry=registry,
        )

        # Authentication Metrics
        self.auth_attempts = Counter(
            name=f"{namespace}_auth_attempts_total",
            documentation="Total number of authentication attempts",
            labelnames=["auth_type", "status"],
            registry=registry,
        )

        self.auth_success = Counter(
            name=f"{namespace}_auth_success_total",
            documentation="Total number of successful authentications",
            labelnames=["auth_type"],
            registry=registry,
        )

        self.auth_failures = Counter(
            name=f"{namespace}_auth_failures_total",
            documentation="Total number of failed authentications",
            labelnames=["auth_type", "reason"],
            registry=registry,
        )

        self.mfa_verifications = Counter(
            name=f"{namespace}_mfa_verifications_total",
            documentation="Total number of MFA verifications",
            labelnames=["mfa_type", "status"],
            registry=registry,
        )

        self.active_sessions = Gauge(
            name=f"{namespace}_active_sessions",
            documentation="Current number of active user sessions",
            registry=registry,
        )

        # Anomaly Detection Metrics
        self.anomalies_detected = Counter(
            name=f"{namespace}_anomalies_detected_total",
            documentation="Total number of anomalies detected",
            labelnames=["anomaly_type", "severity"],
            registry=registry,
        )

        self.anomaly_score = Histogram(
            name=f"{namespace}_anomaly_score",
            documentation="Anomaly detection score distribution",
            labelnames=["anomaly_type"],
            buckets=(0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0),
            registry=registry,
        )

        self.anomaly_detection_duration = Histogram(
            name=f"{namespace}_anomaly_detection_duration_seconds",
            documentation="Time taken for anomaly detection",
            labelnames=["detector_type"],
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
            registry=registry,
        )

        # SLA Metrics
        self.sla_breaches = Counter(
            name=f"{namespace}_sla_breaches_total",
            documentation="Total number of SLA breaches",
            labelnames=["severity", "incident_type"],
            registry=registry,
        )

        self.sla_compliance_rate = Gauge(
            name=f"{namespace}_sla_compliance_rate",
            documentation="Current SLA compliance rate (0-1)",
            labelnames=["severity"],
            registry=registry,
        )

        self.incident_resolution_time = Histogram(
            name=f"{namespace}_incident_resolution_time_minutes",
            documentation="Time taken to resolve incidents in minutes",
            labelnames=["severity", "incident_type"],
            buckets=(5, 15, 30, 60, 120, 240, 480, 1440),
            registry=registry,
        )

        # Data Ingestion Metrics
        self.events_ingested = Counter(
            name=f"{namespace}_events_ingested_total",
            documentation="Total number of events ingested",
            labelnames=["source", "event_type"],
            registry=registry,
        )

        self.ingestion_duration = Histogram(
            name=f"{namespace}_ingestion_duration_seconds",
            documentation="Event ingestion duration",
            labelnames=["source"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0),
            registry=registry,
        )

        # Circuit Breaker Metrics
        self.circuit_breaker_state = Gauge(
            name=f"{namespace}_circuit_breaker_state",
            documentation="Circuit breaker state (0=closed, 1=open, 2=half-open)",
            labelnames=["service"],
            registry=registry,
        )

        self.circuit_breaker_failures = Counter(
            name=f"{namespace}_circuit_breaker_failures_total",
            documentation="Total number of circuit breaker failures",
            labelnames=["service"],
            registry=registry,
        )

    def track_api_request(
        self, method: str, endpoint: str, status: int, duration: float
    ) -> None:
        """Track an API request.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            status: HTTP status code
            duration: Request duration in seconds
        """
        self.api_request_count.labels(method=method, endpoint=endpoint, status=status).inc()
        self.api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)

    def track_db_query(self, query_type: str, table: str, duration: float) -> None:
        """Track a database query.

        Args:
            query_type: Type of query (SELECT, INSERT, UPDATE, DELETE)
            table: Database table name
            duration: Query duration in seconds
        """
        self.db_query_duration.labels(query_type=query_type, table=table).observe(duration)

    def track_cache_hit(self, cache_type: str, key_pattern: str) -> None:
        """Track a cache hit.

        Args:
            cache_type: Type of cache (redis, memory, etc.)
            key_pattern: Pattern of the cache key
        """
        self.cache_hits.labels(cache_type=cache_type, key_pattern=key_pattern).inc()

    def track_cache_miss(self, cache_type: str, key_pattern: str) -> None:
        """Track a cache miss.

        Args:
            cache_type: Type of cache (redis, memory, etc.)
            key_pattern: Pattern of the cache key
        """
        self.cache_misses.labels(cache_type=cache_type, key_pattern=key_pattern).inc()

    def get_cache_hit_rate(self, cache_type: str, key_pattern: str) -> float:
        """Calculate cache hit rate.

        Args:
            cache_type: Type of cache
            key_pattern: Pattern of the cache key

        Returns:
            Cache hit rate as a float between 0 and 1
        """
        hits = self.cache_hits.labels(cache_type=cache_type, key_pattern=key_pattern)._value.get()
        misses = self.cache_misses.labels(
            cache_type=cache_type, key_pattern=key_pattern
        )._value.get()
        total = hits + misses
        return hits / total if total > 0 else 0.0

    def track_auth_attempt(
        self, auth_type: str, status: str, success: bool, reason: Optional[str] = None
    ) -> None:
        """Track an authentication attempt.

        Args:
            auth_type: Type of authentication (jwt, oauth, mfa, etc.)
            status: Status of the attempt (success, failure)
            success: Whether the authentication was successful
            reason: Optional reason for failure
        """
        self.auth_attempts.labels(auth_type=auth_type, status=status).inc()

        if success:
            self.auth_success.labels(auth_type=auth_type).inc()
        else:
            self.auth_failures.labels(auth_type=auth_type, reason=reason or "unknown").inc()

    def track_anomaly(self, anomaly_type: str, severity: str, score: float) -> None:
        """Track a detected anomaly.

        Args:
            anomaly_type: Type of anomaly detected
            severity: Severity level (low, medium, high, critical)
            score: Anomaly score
        """
        self.anomalies_detected.labels(anomaly_type=anomaly_type, severity=severity).inc()
        self.anomaly_score.labels(anomaly_type=anomaly_type).observe(score)

    def track_sla_breach(self, severity: str, incident_type: str) -> None:
        """Track an SLA breach.

        Args:
            severity: Incident severity level
            incident_type: Type of incident
        """
        self.sla_breaches.labels(severity=severity, incident_type=incident_type).inc()

    def update_sla_compliance(self, severity: str, compliance_rate: float) -> None:
        """Update SLA compliance rate.

        Args:
            severity: Incident severity level
            compliance_rate: Compliance rate (0-1)
        """
        self.sla_compliance_rate.labels(severity=severity).set(compliance_rate)

    def get_metrics_dict(self) -> Dict[str, float]:
        """Get current metrics as a dictionary.

        Returns:
            Dictionary containing current metric values
        """
        return {
            "api_requests_total": sum(
                [s._value.get() for s in self.api_request_count.collect()[0].samples]
            ),
            "cache_hit_rate": self.get_cache_hit_rate("redis", "*"),
            "active_sessions": self.active_sessions._value.get(),
            "anomalies_total": sum(
                [s._value.get() for s in self.anomalies_detected.collect()[0].samples]
            ),
            "sla_breaches_total": sum(
                [s._value.get() for s in self.sla_breaches.collect()[0].samples]
            ),
        }


# Global metrics instance
metrics = PrometheusMetrics()
