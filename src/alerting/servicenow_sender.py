"""ServiceNow integration for creating incidents from alerts."""

from base64 import b64encode
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class ServiceNowSender:
    """Create and update incidents in ServiceNow."""

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """Initialize ServiceNow sender.

        Args:
            url: ServiceNow instance URL
            username: ServiceNow username
            password: ServiceNow password
        """
        self.url = (url or settings.servicenow_url or "").rstrip("/")
        self.username = username or settings.servicenow_username
        self.password = password or settings.servicenow_password
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ServiceNowSender":
        """Async context manager entry."""
        if not self.url or not self.username or not self.password:
            raise ValueError("ServiceNow credentials not configured")

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
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    def _map_severity_to_priority(self, severity: int) -> int:
        """Map alert severity to ServiceNow priority.

        Args:
            severity: Severity level (1-5)

        Returns:
            ServiceNow priority (1-5)
        """
        # ServiceNow priority: 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
        priority_map = {
            5: 1,  # Extreme -> Critical
            4: 1,  # Critical -> Critical
            3: 2,  # Error -> High
            2: 3,  # Warning -> Moderate
            1: 4,  # Info -> Low
        }
        return priority_map.get(severity, 3)

    def _map_severity_to_impact(self, severity: int) -> int:
        """Map alert severity to ServiceNow impact.

        Args:
            severity: Severity level (1-5)

        Returns:
            ServiceNow impact (1-3)
        """
        # ServiceNow impact: 1=High, 2=Medium, 3=Low
        impact_map = {
            5: 1,  # Extreme -> High
            4: 1,  # Critical -> High
            3: 2,  # Error -> Medium
            2: 2,  # Warning -> Medium
            1: 3,  # Info -> Low
        }
        return impact_map.get(severity, 2)

    def _map_severity_to_urgency(self, severity: int) -> int:
        """Map alert severity to ServiceNow urgency.

        Args:
            severity: Severity level (1-5)

        Returns:
            ServiceNow urgency (1-3)
        """
        # ServiceNow urgency: 1=High, 2=Medium, 3=Low
        urgency_map = {
            5: 1,  # Extreme -> High
            4: 1,  # Critical -> High
            3: 1,  # Error -> High
            2: 2,  # Warning -> Medium
            1: 3,  # Info -> Low
        }
        return urgency_map.get(severity, 2)

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def create_incident(
        self,
        severity: int,
        title: str,
        description: str,
        alert_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an incident in ServiceNow.

        Args:
            severity: Severity level (1-5)
            title: Incident title (short_description)
            description: Incident description
            alert_id: Unique alert identifier
            metadata: Additional metadata

        Returns:
            Created incident details

        Raises:
            ValueError: If credentials not configured
            httpx.HTTPError: If API request fails
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        # Build work notes with metadata
        work_notes = f"Alert ID: {alert_id}\n\n{description}"
        if metadata:
            work_notes += "\n\nAdditional Information:\n"
            for key, value in metadata.items():
                work_notes += f"- {key}: {value}\n"

        # Build incident payload
        incident_data = {
            "short_description": title[:160],  # ServiceNow limit
            "description": work_notes,
            "priority": self._map_severity_to_priority(severity),
            "impact": self._map_severity_to_impact(severity),
            "urgency": self._map_severity_to_urgency(severity),
            "category": "Security",
            "subcategory": "Security Alert",
            "assignment_group": "Security Operations",
            "caller_id": "Security Data Fabric",
            "contact_type": "Automated Alert",
            "u_alert_id": alert_id,  # Custom field for tracking
        }

        logger.info(f"Creating ServiceNow incident for alert: {alert_id} (severity={severity})")

        try:
            response = await self.client.post(
                "/api/now/table/incident",
                json=incident_data,
            )
            response.raise_for_status()

            result = response.json()
            incident = result.get("result", {})
            incident_number = incident.get("number")
            sys_id = incident.get("sys_id")

            logger.info(
                f"ServiceNow incident created: {incident_number} (sys_id={sys_id}) "
                f"for alert {alert_id}"
            )

            return {
                "success": True,
                "destination": "servicenow",
                "incident_number": incident_number,
                "sys_id": sys_id,
                "alert_id": alert_id,
                "state": incident.get("state"),
                "priority": incident.get("priority"),
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"ServiceNow API error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Failed to create ServiceNow incident: {e}")
            raise

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def update_incident(
        self,
        sys_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update an existing incident in ServiceNow.

        Args:
            sys_id: ServiceNow incident sys_id
            updates: Fields to update

        Returns:
            Updated incident details
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        logger.info(f"Updating ServiceNow incident: {sys_id}")

        try:
            response = await self.client.patch(
                f"/api/now/table/incident/{sys_id}",
                json=updates,
            )
            response.raise_for_status()

            result = response.json()
            incident = result.get("result", {})

            logger.info(f"ServiceNow incident updated: {incident.get('number')}")

            return {
                "success": True,
                "destination": "servicenow",
                "incident_number": incident.get("number"),
                "sys_id": sys_id,
                "state": incident.get("state"),
            }

        except Exception as e:
            logger.error(f"Failed to update ServiceNow incident: {e}")
            raise

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def resolve_incident(self, sys_id: str, resolution_notes: str) -> Dict[str, Any]:
        """Resolve an incident in ServiceNow.

        Args:
            sys_id: ServiceNow incident sys_id
            resolution_notes: Resolution notes

        Returns:
            Updated incident details
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        updates = {
            "state": "6",  # Resolved
            "close_code": "Solved (Permanently)",
            "close_notes": resolution_notes,
        }

        logger.info(f"Resolving ServiceNow incident: {sys_id}")

        return await self.update_incident(sys_id, updates)

    async def find_incident_by_alert_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Find an incident by alert ID.

        Args:
            alert_id: Alert identifier

        Returns:
            Incident details if found, None otherwise
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        try:
            response = await self.client.get(
                "/api/now/table/incident",
                params={
                    "sysparm_query": f"u_alert_id={alert_id}",
                    "sysparm_limit": 1,
                },
            )
            response.raise_for_status()

            result = response.json()
            incidents = result.get("result", [])

            if incidents:
                incident: Dict[str, Any] = incidents[0]
                return incident
            return None

        except Exception as e:
            logger.warning(f"Failed to find incident by alert ID: {e}")
            return None
