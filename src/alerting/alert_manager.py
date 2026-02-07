"""Central alert management system."""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

from src.alerting.pagerduty_sender import PagerDutySender
from src.alerting.servicenow_sender import ServiceNowSender
from src.alerting.slack_sender import SlackSender
from src.config import settings
from src.observability import get_logger
from src.processing.schema import AlertSchema

logger = get_logger(__name__)


class AlertManager:
    """Central alert management with routing, deduplication, and escalation."""

    def __init__(self) -> None:
        """Initialize alert manager."""
        self.alert_history: Dict[str, Dict[str, Any]] = {}
        self.cooldown_tracker: Dict[str, datetime] = {}
        self.escalation_tracker: Dict[str, Dict[str, Any]] = defaultdict(dict)

        # Destination severity thresholds
        self.severity_thresholds = {
            "slack": 2,  # Warning and above
            "pagerduty": 4,  # Critical and above
            "servicenow": 3,  # Error and above
        }

    def _generate_dedup_key(
        self,
        alert_type: str,
        title: str,
        event_id: Optional[UUID] = None,
    ) -> str:
        """Generate deduplication key for alert.

        Args:
            alert_type: Type of alert
            title: Alert title
            event_id: Associated event ID

        Returns:
            Deduplication key
        """
        # Create key based on alert type and title
        key_parts = [alert_type, title.lower().strip()]
        if event_id:
            key_parts.append(str(event_id))

        return "|".join(key_parts)

    def _is_in_cooldown(self, dedup_key: str) -> bool:
        """Check if alert is in cooldown period.

        Args:
            dedup_key: Deduplication key

        Returns:
            True if in cooldown, False otherwise
        """
        if dedup_key not in self.cooldown_tracker:
            return False

        last_sent = self.cooldown_tracker[dedup_key]
        cooldown_period = timedelta(minutes=settings.alert_cooldown_minutes)

        if datetime.utcnow() - last_sent < cooldown_period:
            logger.debug(f"Alert {dedup_key} is in cooldown period")
            return True

        # Cooldown expired, remove from tracker
        del self.cooldown_tracker[dedup_key]
        return False

    def _should_escalate(self, dedup_key: str, current_severity: int) -> bool:
        """Check if alert should be escalated.

        Args:
            dedup_key: Deduplication key
            current_severity: Current alert severity

        Returns:
            True if should escalate, False otherwise
        """
        if dedup_key not in self.escalation_tracker:
            return False

        previous = self.escalation_tracker[dedup_key]
        previous_severity = previous.get("severity", 0)
        occurrence_count = previous.get("count", 0)

        # Escalate if severity increased
        if current_severity > previous_severity:
            logger.info(
                f"Escalating alert {dedup_key}: severity {previous_severity} -> {current_severity}"
            )
            return True

        # Escalate if repeated occurrence threshold reached
        if occurrence_count >= 3 and current_severity >= 2:
            logger.info(f"Escalating alert {dedup_key} due to {occurrence_count} occurrences")
            return True

        return False

    def _update_escalation_tracker(
        self,
        dedup_key: str,
        severity: int,
        escalated: bool = False,
    ) -> None:
        """Update escalation tracking data.

        Args:
            dedup_key: Deduplication key
            severity: Alert severity
            escalated: Whether alert was escalated
        """
        if dedup_key not in self.escalation_tracker:
            self.escalation_tracker[dedup_key] = {
                "severity": severity,
                "count": 1,
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "escalated": escalated,
            }
        else:
            tracker = self.escalation_tracker[dedup_key]
            tracker["severity"] = max(tracker["severity"], severity)
            tracker["count"] += 1
            tracker["last_seen"] = datetime.utcnow()
            if escalated:
                tracker["escalated"] = True
                tracker["count"] = 1  # Reset count after escalation

    def _determine_destinations(
        self,
        severity: int,
        escalated: bool = False,
        explicit_destinations: Optional[List[str]] = None,
    ) -> Set[str]:
        """Determine which destinations to send alert to.

        Args:
            severity: Alert severity level
            escalated: Whether alert was escalated
            explicit_destinations: Explicitly requested destinations

        Returns:
            Set of destination names
        """
        destinations = set()

        # Use explicit destinations if provided
        if explicit_destinations:
            return set(explicit_destinations)

        # Route based on severity thresholds
        if severity >= self.severity_thresholds["slack"]:
            destinations.add("slack")

        if severity >= self.severity_thresholds["servicenow"]:
            destinations.add("servicenow")

        if severity >= self.severity_thresholds["pagerduty"] or escalated:
            destinations.add("pagerduty")

        return destinations

    async def send_alert(
        self,
        alert_type: str,
        severity: int,
        title: str,
        description: str,
        event_id: Optional[UUID] = None,
        prediction_id: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        destinations: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send alert with routing, deduplication, and escalation.

        Args:
            alert_type: Type of alert
            severity: Severity level (1-5)
            title: Alert title
            description: Alert description
            event_id: Associated event ID
            prediction_id: Associated prediction ID
            metadata: Additional metadata
            destinations: Explicit destinations (overrides routing)

        Returns:
            Alert processing result with delivery status
        """
        alert_id = str(uuid4())
        dedup_key = self._generate_dedup_key(alert_type, title, event_id)

        logger.info(
            f"Processing alert: type={alert_type}, severity={severity}, "
            f"dedup_key={dedup_key}, alert_id={alert_id}"
        )

        # Check deduplication
        if self._is_in_cooldown(dedup_key):
            logger.info(f"Alert deduplicated (cooldown): {dedup_key}")
            return {
                "alert_id": alert_id,
                "dedup_key": dedup_key,
                "status": "deduplicated",
                "reason": "cooldown_period",
                "destinations": [],
            }

        # Check escalation
        escalated = self._should_escalate(dedup_key, severity)
        if escalated:
            # Increase severity for escalated alerts
            original_severity = severity
            severity = min(severity + 1, 5)
            logger.info(f"Alert escalated: {original_severity} -> {severity}")
            metadata = {
                **(metadata or {}),
                "escalated": True,
                "original_severity": original_severity,
            }

        # Determine destinations
        target_destinations = self._determine_destinations(severity, escalated, destinations)

        if not target_destinations:
            logger.warning(f"No destinations for alert: severity={severity}")
            return {
                "alert_id": alert_id,
                "dedup_key": dedup_key,
                "status": "no_destinations",
                "severity": severity,
                "destinations": [],
            }

        # Update tracking
        self.cooldown_tracker[dedup_key] = datetime.utcnow()
        self._update_escalation_tracker(dedup_key, severity, escalated)

        # Send to destinations
        delivery_results = []
        send_tasks = []

        for destination in target_destinations:
            if destination == "pagerduty":
                send_tasks.append(
                    self._send_to_pagerduty(alert_id, severity, title, description, metadata)
                )
            elif destination == "slack":
                send_tasks.append(
                    self._send_to_slack(alert_id, severity, title, description, metadata)
                )
            elif destination == "servicenow":
                send_tasks.append(
                    self._send_to_servicenow(alert_id, severity, title, description, metadata)
                )

        # Execute all sends in parallel
        if send_tasks:
            results = await asyncio.gather(*send_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Failed to send alert: {result}")
                    delivery_results.append(
                        {
                            "success": False,
                            "error": str(result),
                        }
                    )
                elif isinstance(result, dict):
                    delivery_results.append(result)

        # Store in history
        self.alert_history[alert_id] = {
            "alert_id": alert_id,
            "dedup_key": dedup_key,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "event_id": event_id,
            "prediction_id": prediction_id,
            "metadata": metadata,
            "destinations": list(target_destinations),
            "delivery_results": delivery_results,
            "escalated": escalated,
            "timestamp": datetime.utcnow(),
        }

        logger.info(f"Alert sent: {alert_id} to {len(target_destinations)} destinations")

        return {
            "alert_id": alert_id,
            "dedup_key": dedup_key,
            "status": "sent",
            "severity": severity,
            "destinations": list(target_destinations),
            "delivery_results": delivery_results,
            "escalated": escalated,
        }

    async def _send_to_pagerduty(
        self,
        alert_id: str,
        severity: int,
        title: str,
        description: str,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Send alert to PagerDuty.

        Args:
            alert_id: Alert ID
            severity: Severity level
            title: Alert title
            description: Alert description
            metadata: Additional metadata

        Returns:
            Delivery result
        """
        try:
            async with PagerDutySender() as sender:
                return await sender.send_alert(
                    severity=severity,
                    title=title,
                    description=description,
                    alert_id=alert_id,
                    metadata=metadata,
                )
        except Exception as e:
            logger.error(f"PagerDuty send failed: {e}")
            return {
                "success": False,
                "destination": "pagerduty",
                "error": str(e),
            }

    async def _send_to_slack(
        self,
        alert_id: str,
        severity: int,
        title: str,
        description: str,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Send alert to Slack.

        Args:
            alert_id: Alert ID
            severity: Severity level
            title: Alert title
            description: Alert description
            metadata: Additional metadata

        Returns:
            Delivery result
        """
        try:
            async with SlackSender() as sender:
                return await sender.send_alert(
                    severity=severity,
                    title=title,
                    description=description,
                    alert_id=alert_id,
                    metadata=metadata,
                )
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return {
                "success": False,
                "destination": "slack",
                "error": str(e),
            }

    async def _send_to_servicenow(
        self,
        alert_id: str,
        severity: int,
        title: str,
        description: str,
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Send alert to ServiceNow.

        Args:
            alert_id: Alert ID
            severity: Severity level
            title: Alert title
            description: Alert description
            metadata: Additional metadata

        Returns:
            Delivery result
        """
        try:
            async with ServiceNowSender() as sender:
                return await sender.create_incident(
                    severity=severity,
                    title=title,
                    description=description,
                    alert_id=alert_id,
                    metadata=metadata,
                )
        except Exception as e:
            logger.error(f"ServiceNow send failed: {e}")
            return {
                "success": False,
                "destination": "servicenow",
                "error": str(e),
            }

    def get_alert_history(
        self,
        alert_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get alert history.

        Args:
            alert_id: Specific alert ID (optional)
            limit: Maximum number of results

        Returns:
            List of alert history entries
        """
        if alert_id:
            alert = self.alert_history.get(alert_id)
            return [alert] if alert is not None else []

        # Return most recent alerts
        sorted_alerts = sorted(
            self.alert_history.values(),
            key=lambda x: x["timestamp"],
            reverse=True,
        )
        return sorted_alerts[:limit]

    def get_escalation_status(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        """Get escalation status for a deduplication key.

        Args:
            dedup_key: Deduplication key

        Returns:
            Escalation status or None
        """
        return self.escalation_tracker.get(dedup_key)

    def clear_cooldown(self, dedup_key: str) -> bool:
        """Clear cooldown for a deduplication key.

        Args:
            dedup_key: Deduplication key

        Returns:
            True if cooldown was cleared, False if not in cooldown
        """
        if dedup_key in self.cooldown_tracker:
            del self.cooldown_tracker[dedup_key]
            logger.info(f"Cleared cooldown for: {dedup_key}")
            return True
        return False

    def reset_escalation(self, dedup_key: str) -> bool:
        """Reset escalation tracking for a deduplication key.

        Args:
            dedup_key: Deduplication key

        Returns:
            True if escalation was reset, False if not tracked
        """
        if dedup_key in self.escalation_tracker:
            del self.escalation_tracker[dedup_key]
            logger.info(f"Reset escalation for: {dedup_key}")
            return True
        return False
