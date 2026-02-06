"""Dynatrace connector for metrics and problems ingestion."""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import httpx

from src.ingestion.base_connector import BaseConnector
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class DynatraceConnector(BaseConnector):
    """Dynatrace REST API v2 connector."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_token: Optional[str] = None,
        poll_interval: int = 60,
    ) -> None:
        """Initialize Dynatrace connector.
        
        Args:
            url: Dynatrace environment URL
            api_token: API token
            poll_interval: Polling interval in seconds
        """
        super().__init__(name="dynatrace", rate_limit_per_minute=120)
        self.url = (url or settings.dynatrace_url or "").rstrip("/")
        self.api_token = api_token or settings.dynatrace_api_token
        self.poll_interval = poll_interval or settings.dynatrace_poll_interval
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> bool:
        """Establish connection to Dynatrace."""
        if not self.url or not self.api_token:
            logger.warning("Dynatrace credentials not configured")
            return False

        try:
            self.client = httpx.AsyncClient(
                base_url=self.url,
                headers={"Authorization": f"Api-Token {self.api_token}"},
                timeout=30.0,
            )
            # Test connection
            if await self.health_check():
                self.connected = True
                logger.info("Dynatrace connector connected")
                return True
            return False
        except Exception as e:
            logger.error(f"Dynatrace connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close Dynatrace connection."""
        if self.client:
            await self.client.aclose()
            self.client = None
        self.connected = False
        logger.info("Dynatrace connector disconnected")

    async def health_check(self) -> bool:
        """Check Dynatrace connection health."""
        if not self.client:
            return False

        try:
            response = await self.client.get("/api/v2/metrics")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Dynatrace health check failed: {e}")
            return False

    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch metrics and problems from Dynatrace.
        
        Args:
            **kwargs: Additional parameters
                - metric_selectors: List of metric selectors
                - from_time: Start time (default: now - poll_interval)
                - to_time: End time (default: now)
                
        Returns:
            List of raw events
        """
        if not self.client:
            raise RuntimeError("Dynatrace connector not connected")

        events = []

        # Fetch metrics
        metric_selectors = kwargs.get(
            "metric_selectors",
            [
                "builtin:host.cpu.usage",
                "builtin:host.mem.usage",
                "builtin:host.disk.usedPct",
                "builtin:host.net.trafficPct",
            ],
        )

        to_time = kwargs.get("to_time", datetime.utcnow())
        from_time = kwargs.get("from_time", to_time - timedelta(seconds=self.poll_interval))

        for selector in metric_selectors:
            try:
                metric_events = await self._fetch_metrics(selector, from_time, to_time)
                events.extend(metric_events)
            except Exception as e:
                logger.error(f"Failed to fetch metric {selector}: {e}")

        # Fetch problems
        try:
            problem_events = await self._fetch_problems(from_time, to_time)
            events.extend(problem_events)
        except Exception as e:
            logger.error(f"Failed to fetch problems: {e}")

        return events

    async def _fetch_metrics(
        self, selector: str, from_time: datetime, to_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch specific metric data."""
        if not self.client:
            return []

        params = {
            "metricSelector": selector,
            "from": int(from_time.timestamp() * 1000),
            "to": int(to_time.timestamp() * 1000),
            "resolution": "1m",
        }

        response = await self.client.get("/api/v2/metrics/query", params=params)
        response.raise_for_status()
        data = response.json()

        events = []
        for result in data.get("result", []):
            metric_id = result.get("metricId")
            for data_point in result.get("data", []):
                for timestamp, values in zip(
                    data_point.get("timestamps", []),
                    data_point.get("values", []),
                ):
                    event = self._create_raw_event(
                        source_id=f"{metric_id}_{timestamp}",
                        data={
                            "metric_id": metric_id,
                            "dimensions": data_point.get("dimensions", {}),
                            "value": values,
                            "unit": result.get("unit"),
                        },
                        timestamp=datetime.fromtimestamp(timestamp / 1000),
                    )
                    events.append(event)

        return events

    async def _fetch_problems(
        self, from_time: datetime, to_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch problems (incidents) from Dynatrace."""
        if not self.client:
            return []

        params = {
            "from": int(from_time.timestamp() * 1000),
            "to": int(to_time.timestamp() * 1000),
        }

        response = await self.client.get("/api/v2/problems", params=params)
        response.raise_for_status()
        data = response.json()

        events = []
        for problem in data.get("problems", []):
            event = self._create_raw_event(
                source_id=problem.get("problemId", ""),
                data=problem,
                timestamp=datetime.fromtimestamp(problem.get("startTime", 0) / 1000),
            )
            events.append(event)

        return events
