"""Abstract base class for data source connectors."""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

from src.observability import get_logger, metrics

logger = get_logger(__name__)


class BaseConnector(ABC):
    """Abstract base connector for data sources."""

    def __init__(
        self,
        name: str,
        rate_limit_per_minute: int = 60,
        max_retries: int = 3,
    ) -> None:
        """Initialize connector.
        
        Args:
            name: Connector name
            rate_limit_per_minute: Max requests per minute
            max_retries: Maximum retry attempts
        """
        self.name = name
        self.rate_limit_per_minute = rate_limit_per_minute
        self.max_retries = max_retries
        self.connected = False
        self._request_times: List[float] = []
        logger.info(f"Initializing {name} connector")

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to data source.
        
        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to data source."""
        pass

    @abstractmethod
    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch data from source.
        
        Args:
            **kwargs: Source-specific parameters
            
        Returns:
            List of raw events
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if connection is healthy.
        
        Returns:
            True if connection is healthy
        """
        pass

    async def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting."""
        now = asyncio.get_event_loop().time()
        # Remove requests older than 60 seconds
        self._request_times = [t for t in self._request_times if now - t < 60]
        
        if len(self._request_times) >= self.rate_limit_per_minute:
            # Wait until oldest request is 60 seconds old
            wait_time = 60 - (now - self._request_times[0])
            if wait_time > 0:
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self._request_times = self._request_times[1:]
        
        self._request_times.append(now)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def fetch_with_retry(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch data with retry logic.
        
        Args:
            **kwargs: Source-specific parameters
            
        Returns:
            List of raw events
        """
        metrics.start_timer(f"connector_{self.name}_fetch")
        try:
            await self._enforce_rate_limit()
            events = await self.fetch(**kwargs)
            metrics.increment(f"connector_{self.name}_events_ingested", len(events))
            duration = metrics.stop_timer(f"connector_{self.name}_fetch")
            logger.info(
                f"{self.name} fetched {len(events)} events",
                extra={"duration": duration, "event_count": len(events)},
            )
            return events
        except Exception as e:
            metrics.increment(f"connector_{self.name}_errors")
            logger.error(
                f"{self.name} fetch error",
                extra={"error": str(e), "error_type": type(e).__name__},
            )
            raise

    def _create_raw_event(
        self, source_id: str, data: Dict[str, Any], timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Create a standardized raw event.
        
        Args:
            source_id: Source-specific event ID
            data: Raw event data
            timestamp: Event timestamp
            
        Returns:
            Standardized raw event dictionary
        """
        return {
            "source": self.name,
            "source_id": source_id,
            "raw_data": data,
            "timestamp": timestamp or datetime.utcnow(),
        }
