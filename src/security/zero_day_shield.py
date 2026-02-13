"""Zero-day protection utilities with circuit breaker and rate limiting."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Optional

from src.config.settings import settings


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker pattern implementation for fault tolerance.

    Prevents cascading failures by opening circuit when failure threshold
    is exceeded and attempting recovery after timeout.
    """

    def __init__(
        self,
        failure_threshold: Optional[int] = None,
        recovery_timeout: Optional[int] = None,
        success_threshold: int = 2,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
            success_threshold: Successful calls needed to close circuit
        """
        self._failure_threshold = failure_threshold or settings.circuit_breaker_failure_threshold
        self._recovery_timeout = recovery_timeout or settings.circuit_breaker_recovery_timeout
        self._success_threshold = success_threshold

        self._failure_count = 0
        self._success_count = 0
        self._state = CircuitState.CLOSED
        self._last_failure_time: Optional[datetime] = None

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    def is_open(self) -> bool:
        """Check if circuit is open."""
        if self._state == CircuitState.OPEN:
            if self._should_attempt_recovery():
                self._state = CircuitState.HALF_OPEN
                return False
            return True
        return False

    def _should_attempt_recovery(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        if not self._last_failure_time:
            return False

        elapsed = (datetime.utcnow() - self._last_failure_time).total_seconds()
        return elapsed >= self._recovery_timeout

    def record_success(self) -> None:
        """Record successful operation."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._success_threshold:
                self._close_circuit()
        else:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record failed operation."""
        self._failure_count += 1
        self._last_failure_time = datetime.utcnow()
        self._success_count = 0

        if self._failure_count >= self._failure_threshold:
            self._open_circuit()

    def _open_circuit(self) -> None:
        """Open circuit due to failures."""
        self._state = CircuitState.OPEN

    def _close_circuit(self) -> None:
        """Close circuit after successful recovery."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0

    def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None


class RateLimiter:
    """Token bucket rate limiter for request throttling."""

    def __init__(self, rate_per_minute: Optional[int] = None, burst: Optional[int] = None):
        """Initialize rate limiter.

        Args:
            rate_per_minute: Number of requests allowed per minute
            burst: Maximum burst size
        """
        self._rate = rate_per_minute or settings.rate_limit_per_minute
        self._burst = burst or settings.rate_limit_burst
        self._buckets: Dict[str, deque] = defaultdict(deque)

    async def is_allowed(self, key: str) -> bool:
        """Check if request is allowed under rate limit.

        Args:
            key: Identifier for rate limit bucket (e.g., user_id, ip_address)

        Returns:
            True if request is allowed, False otherwise
        """
        now = datetime.utcnow()
        bucket = self._buckets[key]

        cutoff_time = now - timedelta(minutes=1)
        while bucket and bucket[0] < cutoff_time:
            bucket.popleft()

        if len(bucket) < self._rate:
            bucket.append(now)
            return True

        return False

    def get_remaining(self, key: str) -> int:
        """Get remaining requests in current window.

        Args:
            key: Identifier for rate limit bucket

        Returns:
            Number of remaining requests
        """
        now = datetime.utcnow()
        bucket = self._buckets[key]

        cutoff_time = now - timedelta(minutes=1)
        while bucket and bucket[0] < cutoff_time:
            bucket.popleft()

        return max(0, self._rate - len(bucket))

    def reset(self, key: str) -> None:
        """Reset rate limit for key.

        Args:
            key: Identifier for rate limit bucket
        """
        if key in self._buckets:
            del self._buckets[key]


class RequestFilter:
    """Request filtering utilities for anomaly detection."""

    def __init__(self):
        """Initialize request filter."""
        self._request_sizes: Dict[str, deque] = defaultdict(deque)
        self._request_counts: Dict[str, int] = defaultdict(int)

    def is_suspicious_size(self, key: str, size: int, max_size: int = 10485760) -> bool:
        """Check if request size is suspicious.

        Args:
            key: Identifier for tracking
            size: Request size in bytes
            max_size: Maximum allowed size in bytes (default 10MB)

        Returns:
            True if size is suspicious, False otherwise
        """
        if size > max_size:
            return True

        bucket = self._request_sizes[key]
        bucket.append(size)

        if len(bucket) > 100:
            bucket.popleft()

        if len(bucket) >= 10:
            avg_size = sum(bucket) / len(bucket)
            if size > avg_size * 3:
                return True

        return False

    def detect_rapid_requests(
        self, key: str, threshold: int = 100, window_seconds: int = 60
    ) -> bool:
        """Detect rapid successive requests.

        Args:
            key: Identifier for tracking
            threshold: Number of requests to trigger detection
            window_seconds: Time window in seconds

        Returns:
            True if rapid requests detected, False otherwise
        """
        self._request_counts[key] += 1

        if self._request_counts[key] >= threshold:
            self._request_counts[key] = 0
            return True

        return False

    def reset_tracking(self, key: str) -> None:
        """Reset tracking data for key.

        Args:
            key: Identifier for tracking
        """
        if key in self._request_sizes:
            del self._request_sizes[key]
        if key in self._request_counts:
            del self._request_counts[key]


class ZeroDayShield:
    """Zero-day protection utilities combining multiple defense mechanisms.

    Provides circuit breaker, rate limiting, and request filtering for
    comprehensive protection against unknown threats.
    """

    def __init__(self):
        """Initialize zero-day shield."""
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._rate_limiter = RateLimiter()
        self._request_filter = RequestFilter()

    def get_circuit_breaker(self, service_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for service.

        Args:
            service_name: Name of service to protect

        Returns:
            CircuitBreaker instance
        """
        if service_name not in self._circuit_breakers:
            self._circuit_breakers[service_name] = CircuitBreaker()
        return self._circuit_breakers[service_name]

    async def check_rate_limit(self, identifier: str) -> bool:
        """Check if request passes rate limit.

        Args:
            identifier: Request identifier (user_id, ip, etc.)

        Returns:
            True if allowed, False if rate limited
        """
        return await self._rate_limiter.is_allowed(identifier)

    def check_request_anomaly(self, identifier: str, request_size: int) -> bool:
        """Check for request anomalies.

        Args:
            identifier: Request identifier
            request_size: Size of request in bytes

        Returns:
            True if anomaly detected, False otherwise
        """
        if self._request_filter.is_suspicious_size(identifier, request_size):
            return True

        if self._request_filter.detect_rapid_requests(identifier):
            return True

        return False

    async def protected_call(self, service_name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection.

        Args:
            service_name: Name of service
            func: Async function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            RuntimeError: If circuit is open
            Exception: Any exception from the function
        """
        breaker = self.get_circuit_breaker(service_name)

        if breaker.is_open():
            raise RuntimeError(f"Circuit breaker open for {service_name}")

        try:
            result = await func(*args, **kwargs)
            breaker.record_success()
            return result
        except Exception as e:
            breaker.record_failure()
            raise e

    def get_rate_limit_remaining(self, identifier: str) -> int:
        """Get remaining rate limit for identifier.

        Args:
            identifier: Request identifier

        Returns:
            Number of remaining requests
        """
        return self._rate_limiter.get_remaining(identifier)

    def reset_circuit_breaker(self, service_name: str) -> None:
        """Reset circuit breaker for service.

        Args:
            service_name: Name of service
        """
        if service_name in self._circuit_breakers:
            self._circuit_breakers[service_name].reset()
