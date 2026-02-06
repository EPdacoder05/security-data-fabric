"""ServiceNow connector for incident feed."""
from typing import Dict, Any, List, Optional
from datetime import datetime
import httpx
from base64 import b64encode

from src.ingestion.base_connector import BaseConnector
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class ServiceNowConnector(BaseConnector):
    """ServiceNow Table API connector."""

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """Initialize ServiceNow connector.
        
        Args:
            url: ServiceNow instance URL
            username: Username
            password: Password
        """
        super().__init__(name="servicenow", rate_limit_per_minute=60)
        self.url = (url or settings.servicenow_url or "").rstrip("/")
        self.username = username or settings.servicenow_username
        self.password = password or settings.servicenow_password
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> bool:
        """Establish connection to ServiceNow."""
        if not self.url or not self.username or not self.password:
            logger.warning("ServiceNow credentials not configured")
            return False

        try:
            auth = b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.client = httpx.AsyncClient(
                base_url=self.url,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
            if await self.health_check():
                self.connected = True
                logger.info("ServiceNow connector connected")
                return True
            return False
        except Exception as e:
            logger.error(f"ServiceNow connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close ServiceNow connection."""
        if self.client:
            await self.client.aclose()
            self.client = None
        self.connected = False
        logger.info("ServiceNow connector disconnected")

    async def health_check(self) -> bool:
        """Check ServiceNow connection health."""
        if not self.client:
            return False

        try:
            response = await self.client.get("/api/now/table/incident?sysparm_limit=1")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"ServiceNow health check failed: {e}")
            return False

    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch incidents from ServiceNow.
        
        Args:
            **kwargs: Additional parameters
                - table: Table name (default: incident)
                - query: Query filter
                - limit: Maximum records to fetch
                
        Returns:
            List of raw events
        """
        if not self.client:
            raise RuntimeError("ServiceNow connector not connected")

        table = kwargs.get("table", "incident")
        query = kwargs.get("query", "active=true")
        limit = kwargs.get("limit", 100)

        params = {
            "sysparm_query": query,
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        try:
            response = await self.client.get(f"/api/now/table/{table}", params=params)
            response.raise_for_status()
            data = response.json()

            events = []
            for record in data.get("result", []):
                event = self._create_raw_event(
                    source_id=record.get("number", record.get("sys_id", "")),
                    data=record,
                    timestamp=datetime.fromisoformat(
                        record.get("sys_created_on", "").replace(" ", "T")
                    )
                    if record.get("sys_created_on")
                    else None,
                )
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"ServiceNow fetch error: {e}")
            return []
