"""GitHub webhook connector for deployment events."""
from typing import Dict, Any, List, Optional
from datetime import datetime
import hmac
import hashlib

from src.ingestion.base_connector import BaseConnector
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)


class GitHubWebhookConnector(BaseConnector):
    """GitHub webhook receiver connector."""

    def __init__(
        self,
        webhook_secret: Optional[str] = None,
    ) -> None:
        """Initialize GitHub webhook connector.
        
        Args:
            webhook_secret: Webhook secret for signature verification
        """
        super().__init__(name="github", rate_limit_per_minute=300)
        self.webhook_secret = webhook_secret or settings.github_webhook_secret
        self.connected = True  # Webhook receiver doesn't need external connection

    async def connect(self) -> bool:
        """Webhook connector is always connected."""
        self.connected = True
        logger.info("GitHub webhook connector initialized")
        return True

    async def disconnect(self) -> None:
        """Webhook connector disconnect."""
        self.connected = False
        logger.info("GitHub webhook connector disconnected")

    async def health_check(self) -> bool:
        """Webhook connector health check."""
        return self.connected

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature.
        
        Args:
            payload: Raw webhook payload
            signature: X-Hub-Signature-256 header value
            
        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning("GitHub webhook secret not configured, skipping verification")
            return True

        if not signature.startswith("sha256="):
            return False

        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature[7:], expected_signature)

    async def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Process GitHub webhook event.
        
        Args:
            **kwargs: Webhook parameters
                - event_type: GitHub event type (e.g., 'push', 'deployment')
                - payload: Webhook payload
                - signature: Signature for verification
                
        Returns:
            List containing the processed event
        """
        event_type = kwargs.get("event_type")
        payload = kwargs.get("payload", {})
        signature = kwargs.get("signature", "")

        if not event_type or not payload:
            logger.error("Missing event_type or payload")
            return []

        # Verify signature if provided
        if signature:
            payload_bytes = kwargs.get("payload_bytes", b"")
            if payload_bytes and not self.verify_signature(payload_bytes, signature):
                logger.error("Invalid GitHub webhook signature")
                return []

        # Extract relevant information based on event type
        event_data = self._process_event(event_type, payload)
        if not event_data:
            return []

        event = self._create_raw_event(
            source_id=event_data.get("id", ""),
            data=event_data,
            timestamp=event_data.get("timestamp"),
        )

        return [event]

    def _process_event(self, event_type: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process specific GitHub event types.
        
        Args:
            event_type: GitHub event type
            payload: Event payload
            
        Returns:
            Processed event data or None
        """
        if event_type == "deployment":
            return self._process_deployment(payload)
        elif event_type == "push":
            return self._process_push(payload)
        elif event_type == "pull_request":
            if payload.get("action") == "closed" and payload.get("pull_request", {}).get("merged"):
                return self._process_pr_merge(payload)
        
        # Return generic event for other types
        return {
            "id": str(payload.get("id", "")),
            "event_type": event_type,
            "repository": payload.get("repository", {}).get("full_name"),
            "sender": payload.get("sender", {}).get("login"),
            "timestamp": datetime.utcnow(),
            "raw_payload": payload,
        }

    def _process_deployment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process deployment event."""
        deployment = payload.get("deployment", {})
        return {
            "id": str(deployment.get("id", "")),
            "event_type": "deployment",
            "repository": payload.get("repository", {}).get("full_name"),
            "environment": deployment.get("environment"),
            "ref": deployment.get("ref"),
            "sha": deployment.get("sha"),
            "creator": deployment.get("creator", {}).get("login"),
            "timestamp": datetime.fromisoformat(
                deployment.get("created_at", "").replace("Z", "+00:00")
            )
            if deployment.get("created_at")
            else datetime.utcnow(),
            "description": deployment.get("description"),
            "payload": deployment.get("payload", {}),
        }

    def _process_push(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process push event."""
        return {
            "id": payload.get("after", ""),
            "event_type": "push",
            "repository": payload.get("repository", {}).get("full_name"),
            "ref": payload.get("ref"),
            "before": payload.get("before"),
            "after": payload.get("after"),
            "commits": payload.get("commits", []),
            "pusher": payload.get("pusher", {}).get("name"),
            "timestamp": datetime.utcnow(),
        }

    def _process_pr_merge(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process pull request merge event."""
        pr = payload.get("pull_request", {})
        return {
            "id": str(pr.get("id", "")),
            "event_type": "pr_merge",
            "repository": payload.get("repository", {}).get("full_name"),
            "pr_number": pr.get("number"),
            "title": pr.get("title"),
            "merged_by": pr.get("merged_by", {}).get("login"),
            "base_ref": pr.get("base", {}).get("ref"),
            "head_ref": pr.get("head", {}).get("ref"),
            "timestamp": datetime.fromisoformat(pr.get("merged_at", "").replace("Z", "+00:00"))
            if pr.get("merged_at")
            else datetime.utcnow(),
        }
