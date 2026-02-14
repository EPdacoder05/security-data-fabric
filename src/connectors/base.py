"""Base connector class for external data source integrations."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ConnectionState(str, Enum):
    """Connection states for circuit breaker pattern."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failures detected, not accepting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker for fault tolerance.

    Implements the circuit breaker pattern to prevent cascading failures
    when external services are unavailable or slow.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2,
    ) -> None:
        """Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            success_threshold: Consecutive successes needed to close circuit
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self.failure_count = 0
        self.success_count = 0
        self.state = ConnectionState.CLOSED
        self.last_failure_time: Optional[datetime] = None

    def record_success(self) -> None:
        """Record a successful operation."""
        self.failure_count = 0

        if self.state == ConnectionState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                logger.info("Circuit breaker closed after successful recovery")
                self.state = ConnectionState.CLOSED
                self.success_count = 0

    def record_failure(self) -> None:
        """Record a failed operation."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)
        self.success_count = 0

        if self.failure_count >= self.failure_threshold:
            if self.state != ConnectionState.OPEN:
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
                self.state = ConnectionState.OPEN

    def can_execute(self) -> bool:
        """Check if operation can be executed.

        Returns:
            True if operation can proceed, False if circuit is open
        """
        if self.state == ConnectionState.CLOSED:
            return True

        if self.state == ConnectionState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.now(timezone.utc) - self.last_failure_time).total_seconds()
                if elapsed >= self.recovery_timeout:
                    logger.info("Circuit breaker entering half-open state for recovery test")
                    self.state = ConnectionState.HALF_OPEN
                    return True
            return False

        # HALF_OPEN state
        return True

    def get_state(self) -> ConnectionState:
        """Get current circuit breaker state.

        Returns:
            Current ConnectionState
        """
        return self.state


class BaseConnector(ABC):
    """Abstract base class for external data source connectors.

    All connector implementations should inherit from this class and
    implement the required abstract methods. Provides built-in support
    for circuit breaker pattern, connection pooling, and error handling.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: int = 30,
        max_retries: int = 3,
        circuit_breaker_enabled: bool = True,
    ) -> None:
        """Initialize base connector.

        Args:
            base_url: Base URL for the API
            api_token: Authentication token
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            circuit_breaker_enabled: Whether to enable circuit breaker
        """
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.max_retries = max_retries

        self._client: Optional[httpx.AsyncClient] = None
        self._circuit_breaker = CircuitBreaker() if circuit_breaker_enabled else None
        self._connected = False

        logger.info(f"Initialized {self.__class__.__name__} connector")

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the data source.

        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the data source."""
        pass

    @abstractmethod
    async def fetch_data(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch data from the data source.

        Args:
            endpoint: API endpoint to fetch from
            params: Optional query parameters

        Returns:
            List of data records
        """
        pass

    @abstractmethod
    async def validate_connection(self) -> bool:
        """Validate that the connection is working.

        Returns:
            True if connection is valid, False otherwise
        """
        pass

    async def _create_client(self) -> httpx.AsyncClient:
        """Create HTTP client with authentication.

        Returns:
            Configured AsyncClient instance
        """
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        return httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
        )

    async def _execute_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """Execute HTTP request with circuit breaker and retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: Optional query parameters
            json_data: Optional JSON body

        Returns:
            HTTP response

        Raises:
            RuntimeError: If circuit breaker is open or max retries exceeded
            httpx.HTTPError: If request fails
        """
        # Check circuit breaker
        if self._circuit_breaker and not self._circuit_breaker.can_execute():
            raise RuntimeError(f"Circuit breaker is open for {self.__class__.__name__}")

        if not self._client:
            self._client = await self._create_client()

        last_exception = None

        for attempt in range(self.max_retries):
            try:
                response = await self._client.request(
                    method=method,
                    url=endpoint,
                    params=params,
                    json=json_data,
                )
                response.raise_for_status()

                # Record success with circuit breaker
                if self._circuit_breaker:
                    self._circuit_breaker.record_success()

                return response

            except httpx.HTTPError as e:
                last_exception = e
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")

                # Record failure with circuit breaker
                if self._circuit_breaker:
                    self._circuit_breaker.record_failure()

                # Don't retry on client errors (4xx)
                if isinstance(e, httpx.HTTPStatusError) and 400 <= e.response.status_code < 500:
                    break

        # All retries failed
        raise RuntimeError(f"Request failed after {self.max_retries} attempts: {last_exception}")

    async def _get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute GET request.

        Args:
            endpoint: API endpoint
            params: Optional query parameters

        Returns:
            Response JSON data
        """
        response = await self._execute_request("GET", endpoint, params=params)
        return response.json()  # type: ignore[no-any-return]

    async def _post(
        self,
        endpoint: str,
        json_data: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute POST request.

        Args:
            endpoint: API endpoint
            json_data: JSON body
            params: Optional query parameters

        Returns:
            Response JSON data
        """
        response = await self._execute_request("POST", endpoint, params=params, json_data=json_data)
        return response.json()  # type: ignore[no-any-return]

    async def _put(
        self,
        endpoint: str,
        json_data: Dict[str, Any],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute PUT request.

        Args:
            endpoint: API endpoint
            json_data: JSON body
            params: Optional query parameters

        Returns:
            Response JSON data
        """
        response = await self._execute_request("PUT", endpoint, params=params, json_data=json_data)
        return response.json()  # type: ignore[no-any-return]

    async def _delete(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute DELETE request.

        Args:
            endpoint: API endpoint
            params: Optional query parameters

        Returns:
            Response JSON data
        """
        response = await self._execute_request("DELETE", endpoint, params=params)
        return response.json()  # type: ignore[no-any-return]

    def is_connected(self) -> bool:
        """Check if connector is connected.

        Returns:
            True if connected, False otherwise
        """
        return self._connected

    def get_circuit_breaker_state(self) -> Optional[ConnectionState]:
        """Get circuit breaker state.

        Returns:
            ConnectionState if circuit breaker enabled, None otherwise
        """
        if self._circuit_breaker:
            return self._circuit_breaker.get_state()
        return None

    async def __aenter__(self) -> "BaseConnector":
        """Async context manager entry.

        Returns:
            Self for use in async with statement
        """
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit.

        Args:
            exc_type: Exception type if error occurred
            exc_val: Exception value if error occurred
            exc_tb: Exception traceback if error occurred
        """
        await self.disconnect()
