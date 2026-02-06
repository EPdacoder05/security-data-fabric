"""
Abstract base class for all data source connectors.
Provides common interface and utilities for Bronze layer ingestion.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)


class ConnectorError(Exception):
    """Base exception for connector errors."""
    pass


class ConnectorConnectionError(ConnectorError):
    """Connection-related errors."""
    pass


class ConnectorAuthError(ConnectorError):
    """Authentication/authorization errors."""
    pass


class ConnectorRateLimitError(ConnectorError):
    """Rate limit exceeded errors."""
    pass


class BaseConnector(ABC):
    """Abstract base class for all data source connectors."""
    
    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
        self._metrics = {
            "fetch_count": 0,
            "error_count": 0,
            "total_latency_ms": 0.0,
        }
        logger.info(f"Initialized {self.name} connector")
    
    async def connect(self) -> bool:
        """
        Establish connection to the data source.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self._client is None:
                headers = self._get_headers()
                self._client = httpx.AsyncClient(
                    base_url=self.base_url,
                    headers=headers,
                    timeout=self.timeout,
                )
                logger.info(f"{self.name} connector established")
            
            # Test connection
            return await self.health_check()
        except Exception as e:
            logger.error(f"{self.name} connection failed: {e}")
            raise ConnectorConnectionError(f"Failed to connect to {self.name}: {e}")
    
    async def disconnect(self):
        """Close connection to the data source."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info(f"{self.name} connector disconnected")
    
    @abstractmethod
    def _get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for API requests.
        
        Returns:
            Dictionary of headers
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the connector is healthy and can communicate with the source.
        
        Returns:
            True if healthy, False otherwise
        """
        pass
    
    @abstractmethod
    async def fetch(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from the data source.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional source-specific parameters
        
        Returns:
            List of raw event dictionaries
        """
        pass
    
    @retry(
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (will be appended to base_url)
            params: Query parameters
            json: JSON body
        
        Returns:
            Response JSON
        """
        if self._client is None:
            await self.connect()
        
        start_time = datetime.now()
        
        try:
            response = await self._client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json,
            )
            response.raise_for_status()
            
            # Update metrics
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            self._metrics["fetch_count"] += 1
            self._metrics["total_latency_ms"] += latency_ms
            
            return response.json()
        
        except httpx.HTTPStatusError as e:
            self._metrics["error_count"] += 1
            
            if e.response.status_code == 401:
                raise ConnectorAuthError(f"Authentication failed for {self.name}")
            elif e.response.status_code == 429:
                raise ConnectorRateLimitError(f"Rate limit exceeded for {self.name}")
            else:
                raise ConnectorError(f"HTTP {e.response.status_code} from {self.name}: {e}")
        
        except httpx.RequestError as e:
            self._metrics["error_count"] += 1
            raise ConnectorConnectionError(f"Request failed for {self.name}: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get connector metrics.
        
        Returns:
            Dictionary of metrics
        """
        avg_latency = (
            self._metrics["total_latency_ms"] / self._metrics["fetch_count"]
            if self._metrics["fetch_count"] > 0
            else 0.0
        )
        
        return {
            "connector": self.name,
            "fetch_count": self._metrics["fetch_count"],
            "error_count": self._metrics["error_count"],
            "error_rate": (
                self._metrics["error_count"] / self._metrics["fetch_count"]
                if self._metrics["fetch_count"] > 0
                else 0.0
            ),
            "avg_latency_ms": round(avg_latency, 2),
        }
    
    def _get_default_time_range(self) -> tuple[datetime, datetime]:
        """Get default time range (last hour)."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        return start_time, end_time
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
