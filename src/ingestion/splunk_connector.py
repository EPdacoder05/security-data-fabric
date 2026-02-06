"""Splunk/OpenSearch connector for log ingestion."""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import httpx

from src.ingestion.base_connector import BaseConnector
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class SplunkConnector(BaseConnector):
    """Splunk REST API / OpenSearch connector."""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        index: str = "security",
    ) -> None:
        """Initialize Splunk connector.
        
        Args:
            url: Splunk instance URL
            token: API token
            index: Index name to query
        """
        super().__init__(name="splunk", rate_limit_per_minute=60)
        self.url = (url or settings.splunk_url or "").rstrip("/")
        self.token = token or settings.splunk_token
        self.index = index or settings.splunk_index
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> bool:
        """Establish connection to Splunk."""
        if not self.url or not self.token:
            logger.warning("Splunk credentials not configured")
            return False

        try:
            self.client = httpx.AsyncClient(
                base_url=self.url,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=30.0,
                verify=False,  # In production, use proper SSL verification
            )
            if await self.health_check():
                self.connected = True
                logger.info("Splunk connector connected")
                return True
            return False
        except Exception as e:
            logger.error(f"Splunk connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close Splunk connection."""
        if self.client:
            await self.client.aclose()
            self.client = None
        self.connected = False
        logger.info("Splunk connector disconnected")

    async def health_check(self) -> bool:
        """Check Splunk connection health."""
        if not self.client:
            return False

        try:
            response = await self.client.get("/services/server/info")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk health check failed: {e}")
            return False

    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch logs from Splunk.
        
        Args:
            **kwargs: Additional parameters
                - query: Search query (default: index={self.index})
                - earliest_time: Start time
                - latest_time: End time
                - max_count: Maximum events to return
                
        Returns:
            List of raw events
        """
        if not self.client:
            raise RuntimeError("Splunk connector not connected")

        query = kwargs.get("query", f"search index={self.index}")
        earliest_time = kwargs.get("earliest_time", "-1h")
        latest_time = kwargs.get("latest_time", "now")
        max_count = kwargs.get("max_count", 1000)

        # Create search job
        search_params = {
            "search": query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_count": max_count,
            "output_mode": "json",
        }

        try:
            # Start search job
            response = await self.client.post("/services/search/jobs", data=search_params)
            response.raise_for_status()
            job_data = response.json()
            job_id = job_data.get("sid")

            if not job_id:
                logger.error("No job ID returned from Splunk search")
                return []

            # Wait for job completion (simplified - in production, use polling)
            import asyncio
            await asyncio.sleep(2)

            # Get results
            results_response = await self.client.get(
                f"/services/search/jobs/{job_id}/results",
                params={"output_mode": "json", "count": max_count},
            )
            results_response.raise_for_status()
            results = results_response.json()

            events = []
            for result in results.get("results", []):
                event = self._create_raw_event(
                    source_id=result.get("_cd", result.get("_time", str(datetime.utcnow()))),
                    data=result,
                    timestamp=datetime.fromtimestamp(float(result.get("_time", 0)))
                    if "_time" in result
                    else None,
                )
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"Splunk fetch error: {e}")
            return []
