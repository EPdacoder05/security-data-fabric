"""Slack integration for sending alerts."""

from datetime import datetime
from typing import Any, Dict, List, Optional

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


class SlackSender:
    """Send alerts to Slack via webhook."""

    def __init__(self, webhook_url: Optional[str] = None) -> None:
        """Initialize Slack sender.

        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url or settings.slack_webhook_url
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SlackSender":
        """Async context manager entry."""
        self.client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    def _get_severity_color(self, severity: int) -> str:
        """Get color code based on severity.

        Args:
            severity: Severity level (1-5)

        Returns:
            Hex color code
        """
        color_map = {
            1: "#36a64f",  # Green - Info
            2: "#ffcc00",  # Yellow - Warning
            3: "#ff9900",  # Orange - Error
            4: "#ff0000",  # Red - Critical
            5: "#8b0000",  # Dark Red - Extreme
        }
        return color_map.get(severity, "#808080")

    def _get_severity_emoji(self, severity: int) -> str:
        """Get emoji based on severity.

        Args:
            severity: Severity level (1-5)

        Returns:
            Emoji string
        """
        emoji_map = {
            1: "ℹ️",
            2: "⚠️",
            3: "🔥",
            4: "🚨",
            5: "💀",
        }
        return emoji_map.get(severity, "❓")

    def _get_severity_text(self, severity: int) -> str:
        """Get severity text label.

        Args:
            severity: Severity level (1-5)

        Returns:
            Severity text
        """
        severity_map = {
            1: "INFO",
            2: "WARNING",
            3: "ERROR",
            4: "CRITICAL",
            5: "EXTREME",
        }
        return severity_map.get(severity, "UNKNOWN")

    def _format_blocks(
        self,
        severity: int,
        title: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Format message as Slack blocks.

        Args:
            severity: Severity level
            title: Alert title
            description: Alert description
            metadata: Additional metadata

        Returns:
            List of Slack blocks
        """
        emoji = self._get_severity_emoji(severity)
        severity_text = self._get_severity_text(severity)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Alert: {severity_text}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n{description}",
                },
            },
        ]

        # Add metadata fields if present
        if metadata:
            fields: List[Dict[str, Any]] = []
            for key, value in metadata.items():
                if isinstance(value, (str, int, float, bool)):
                    fields.append(
                        {
                            "type": "mrkdwn",
                            "text": f"*{key.replace('_', ' ').title()}:*\n{value}",
                        }
                    )

            if fields:
                section_block: Dict[str, Any] = {"type": "section", "fields": fields[:10]}
                blocks.append(section_block)  # Slack block structure

        # Add timestamp
        context_block: Dict[str, Any] = {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"⏰ {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                }
            ],
        }
        blocks.append(context_block)

        return blocks

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
        """Send alert to Slack.

        Args:
            severity: Severity level (1-5)
            title: Alert title
            description: Alert description
            alert_id: Unique alert identifier
            metadata: Additional metadata

        Returns:
            Response information

        Raises:
            ValueError: If webhook URL not configured
            httpx.HTTPError: If API request fails
        """
        if not self.webhook_url:
            raise ValueError("Slack webhook URL not configured")

        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        # Add alert ID to metadata
        full_metadata = {**(metadata or {}), "alert_id": alert_id}

        # Build message payload
        payload = {
            "attachments": [
                {
                    "color": self._get_severity_color(severity),
                    "blocks": self._format_blocks(severity, title, description, full_metadata),
                }
            ]
        }

        logger.info(f"Sending alert to Slack: {alert_id} (severity={severity})")

        try:
            response = await self.client.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            logger.info(f"Slack alert sent successfully: {alert_id}")

            return {
                "success": True,
                "destination": "slack",
                "alert_id": alert_id,
                "status_code": response.status_code,
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Slack API error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            raise

    async def send_simple_message(self, message: str) -> Dict[str, Any]:
        """Send a simple text message to Slack.

        Args:
            message: Message text

        Returns:
            Response information
        """
        if not self.webhook_url:
            raise ValueError("Slack webhook URL not configured")

        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        payload = {"text": message}

        logger.info("Sending simple message to Slack")

        try:
            response = await self.client.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()

            return {
                "success": True,
                "destination": "slack",
                "status_code": response.status_code,
            }

        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            raise
