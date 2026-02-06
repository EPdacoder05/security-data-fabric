"""PagerDuty connector for event ingestion."""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import httpx

from src.ingestion.base_connector import BaseConnector
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class PagerDutyConnector(BaseConnector):
    """PagerDuty Events API v2 connector."""

    def __init__(
        self,
        api_key: Optional[str] = None,
    ) -> None:
        """Initialize PagerDuty connector.
        
        Args:
            api_key: PagerDuty API key
        """
        super().__init__(name="pagerduty", rate_limit_per_minute=120)
        self.api_key = api_key or settings.pagerduty_api_key
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> bool:
        """Establish connection to PagerDuty."""
        if not self.api_key:
            logger.warning("PagerDuty API key not configured")
            return False

        try:
            self.client = httpx.AsyncClient(
                base_url="https://api.pagerduty.com",
                headers={
                    "Authorization": f"Token token={self.api_key}",
                    "Accept": "application/vnd.pagerduty+json;version=2",
                },
                timeout=30.0,
            )
            if await self.health_check():
                self.connected = True
                logger.info("PagerDuty connector connected")
                return True
            return False
        except Exception as e:
            logger.error(f"PagerDuty connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close PagerDuty connection."""
        if self.client:
            await self.client.aclose()
            self.client = None
        self.connected = False
        logger.info("PagerDuty connector disconnected")

    async def health_check(self) -> bool:
        """Check PagerDuty connection health."""
        if not self.client:
            return False

        try:
            response = await self.client.get("/abilities")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"PagerDuty health check failed: {e}")
            return False

    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch incidents from PagerDuty.
        
        Args:
            **kwargs: Additional parameters
                - since: Start time (default: 1 hour ago)
                - until: End time (default: now)
                - statuses: List of statuses to filter
                - limit: Maximum incidents to fetch
                
        Returns:
            List of raw events
        """
        if not self.client:
            raise RuntimeError("PagerDuty connector not connected")

        until = kwargs.get("until", datetime.utcnow())
        since = kwargs.get("since", until - timedelta(hours=1))
        statuses = kwargs.get("statuses", ["triggered", "acknowledged"])
        limit = kwargs.get("limit", 100)

        params = {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "statuses[]": statuses,
            "limit": limit,
            "time_zone": "UTC",
        }

        try:
            response = await self.client.get("/incidents", params=params)
            response.raise_for_status()
            data = response.json()

            events = []
            for incident in data.get("incidents", []):
                event = self._create_raw_event(
                    source_id=incident.get("id", ""),
                    data=incident,
                    timestamp=datetime.fromisoformat(
                        incident.get("created_at", "").replace("Z", "+00:00")
                    )
                    if incident.get("created_at")
                    else None,
                )
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"PagerDuty fetch error: {e}")
            return []
