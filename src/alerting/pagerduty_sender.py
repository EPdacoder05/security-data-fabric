"""PagerDuty integration for sending alerts."""

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


class PagerDutySender:
    """Send alerts to PagerDuty Events API v2."""

    def __init__(self, integration_key: Optional[str] = None) -> None:
        """Initialize PagerDuty sender.

        Args:
            integration_key: PagerDuty Events API v2 integration key
        """
        self.integration_key = integration_key or settings.pagerduty_integration_key
        self.events_url = "https://events.pagerduty.com/v2/enqueue"
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "PagerDutySender":
        """Async context manager entry."""
        self.client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def send_alert(
        self,
        severity: int,
        title: str,
        description: str,
        alert_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send alert to PagerDuty.

        Args:
            severity: Severity level (1-5)
            title: Alert title
            description: Alert description
            alert_id: Unique alert identifier for deduplication
            metadata: Additional metadata

        Returns:
            Response from PagerDuty API

        Raises:
            ValueError: If integration key not configured
            httpx.HTTPError: If API request fails
        """
        if not self.integration_key:
            raise ValueError("PagerDuty integration key not configured")

        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        # Map severity to PagerDuty severity
        severity_map = {
            1: "info",
            2: "warning",
            3: "error",
            4: "critical",
            5: "critical",
        }
        pd_severity = severity_map.get(severity, "error")

        # Build event payload
        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": alert_id,
            "payload": {
                "summary": title,
                "severity": pd_severity,
                "source": "security-data-fabric",
                "timestamp": datetime.utcnow().isoformat(),
                "custom_details": {
                    "description": description,
                    "severity_level": severity,
                    **(metadata or {}),
                },
            },
        }

        logger.info(f"Sending alert to PagerDuty: {alert_id} (severity={severity})")

        try:
            response = await self.client.post(
                self.events_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            result = response.json()
            logger.info(
                f"PagerDuty alert sent successfully: {alert_id}, "
                f"dedup_key={result.get('dedup_key')}, "
                f"status={result.get('status')}"
            )

            return {
                "success": True,
                "destination": "pagerduty",
                "dedup_key": result.get("dedup_key"),
                "status": result.get("status"),
                "message": result.get("message"),
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"PagerDuty API error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            raise

    async def resolve_alert(self, alert_id: str) -> Dict[str, Any]:
        """Resolve an alert in PagerDuty.

        Args:
            alert_id: Alert identifier to resolve

        Returns:
            Response from PagerDuty API
        """
        if not self.integration_key:
            raise ValueError("PagerDuty integration key not configured")

        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        payload = {
            "routing_key": self.integration_key,
            "event_action": "resolve",
            "dedup_key": alert_id,
        }

        logger.info(f"Resolving PagerDuty alert: {alert_id}")

        try:
            response = await self.client.post(
                self.events_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            result = response.json()
            logger.info(f"PagerDuty alert resolved: {alert_id}")

            return {
                "success": True,
                "destination": "pagerduty",
                "dedup_key": result.get("dedup_key"),
                "status": result.get("status"),
            }

        except Exception as e:
            logger.error(f"Failed to resolve PagerDuty alert: {e}")
            raise
