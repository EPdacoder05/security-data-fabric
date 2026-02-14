"""SLA tracking and breach detection for security incidents."""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SLASeverity(int, Enum):
    """SLA severity levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFORMATIONAL = 5


class SLAStatus(str, Enum):
    """SLA status values."""

    PENDING = "pending"
    MET = "met"
    BREACHED = "breached"
    AT_RISK = "at_risk"


class SLATracker:
    """Track and monitor SLA compliance for security incidents.

    Provides SLA definition, tracking, breach detection, and performance metrics.
    Integrates with database models for persistent SLA tracking.

    Attributes:
        sla_definitions: Dictionary of severity to SLA target times
        warning_threshold: Percentage of SLA time before warning (0-1)
        active_slas: Dictionary of active SLA tracking records
    """

    def __init__(self, warning_threshold: float = 0.8) -> None:
        """Initialize the SLA tracker.

        Args:
            warning_threshold: Percentage of SLA time elapsed before warning (0-1)
        """
        self.sla_definitions = self._load_sla_definitions()
        self.warning_threshold = warning_threshold
        self.active_slas: Dict[str, Dict] = {}

    def _load_sla_definitions(self) -> Dict[int, int]:
        """Load SLA target response times by severity.

        Returns:
            Dictionary mapping severity level to target response time in minutes
        """
        return {
            SLASeverity.CRITICAL: 15,
            SLASeverity.HIGH: 60,
            SLASeverity.MEDIUM: 240,
            SLASeverity.LOW: 1440,
            SLASeverity.INFORMATIONAL: 2880,
        }

    async def start_tracking(
        self, incident_id: str, severity: int, created_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Start tracking SLA for a new incident.

        Args:
            incident_id: Unique incident identifier
            severity: Incident severity level (1-5)
            created_at: Incident creation timestamp. If None, uses current time

        Returns:
            Dictionary with SLA tracking details

        Raises:
            ValueError: If severity is invalid
        """
        if severity not in [s.value for s in SLASeverity]:
            raise ValueError(f"Invalid severity: {severity}")

        if created_at is None:
            created_at = datetime.now(timezone.utc)

        target_minutes = self.sla_definitions[SLASeverity(severity)]
        target_time = created_at + timedelta(minutes=target_minutes)
        warning_time = created_at + timedelta(minutes=int(target_minutes * self.warning_threshold))

        sla_record = {
            "incident_id": incident_id,
            "severity": severity,
            "created_at": created_at,
            "target_response_minutes": target_minutes,
            "target_time": target_time,
            "warning_time": warning_time,
            "status": SLAStatus.PENDING.value,
            "actual_response_minutes": None,
            "resolved_at": None,
        }

        self.active_slas[incident_id] = sla_record

        return sla_record

    async def check_sla_status(
        self, incident_id: str, current_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Check current SLA status for an incident.

        Args:
            incident_id: Unique incident identifier
            current_time: Current timestamp. If None, uses current time

        Returns:
            Dictionary with SLA status and metrics

        Raises:
            KeyError: If incident_id not found in active SLAs
        """
        if incident_id not in self.active_slas:
            raise KeyError(f"Incident {incident_id} not found in active SLAs")

        sla_record = self.active_slas[incident_id]

        if current_time is None:
            current_time = datetime.now(timezone.utc)

        created_at = sla_record["created_at"]
        target_time = sla_record["target_time"]
        warning_time = sla_record["warning_time"]

        elapsed_minutes = (current_time - created_at).total_seconds() / 60
        remaining_minutes = (target_time - current_time).total_seconds() / 60

        if sla_record["resolved_at"]:
            status = (
                SLAStatus.MET if sla_record["status"] == SLAStatus.MET.value else SLAStatus.BREACHED
            )
        elif current_time >= target_time:
            status = SLAStatus.BREACHED
        elif current_time >= warning_time:
            status = SLAStatus.AT_RISK
        else:
            status = SLAStatus.PENDING

        percentage_elapsed = (elapsed_minutes / sla_record["target_response_minutes"]) * 100

        return {
            "incident_id": incident_id,
            "status": status.value,
            "severity": sla_record["severity"],
            "elapsed_minutes": round(elapsed_minutes, 2),
            "remaining_minutes": round(max(0, remaining_minutes), 2),
            "target_minutes": sla_record["target_response_minutes"],
            "percentage_elapsed": round(percentage_elapsed, 2),
            "is_breached": status == SLAStatus.BREACHED,
            "is_at_risk": status == SLAStatus.AT_RISK,
        }

    async def resolve_incident(
        self, incident_id: str, resolved_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Mark incident as resolved and finalize SLA tracking.

        Args:
            incident_id: Unique incident identifier
            resolved_at: Resolution timestamp. If None, uses current time

        Returns:
            Dictionary with final SLA metrics

        Raises:
            KeyError: If incident_id not found in active SLAs
        """
        if incident_id not in self.active_slas:
            raise KeyError(f"Incident {incident_id} not found in active SLAs")

        sla_record = self.active_slas[incident_id]

        if resolved_at is None:
            resolved_at = datetime.now(timezone.utc)

        actual_response_minutes = (resolved_at - sla_record["created_at"]).total_seconds() / 60
        sla_met = actual_response_minutes <= sla_record["target_response_minutes"]

        sla_record["resolved_at"] = resolved_at
        sla_record["actual_response_minutes"] = round(actual_response_minutes, 2)
        sla_record["status"] = SLAStatus.MET.value if sla_met else SLAStatus.BREACHED.value

        return {
            "incident_id": incident_id,
            "sla_met": sla_met,
            "actual_response_minutes": sla_record["actual_response_minutes"],
            "target_response_minutes": sla_record["target_response_minutes"],
            "variance_minutes": round(
                sla_record["actual_response_minutes"] - sla_record["target_response_minutes"], 2
            ),
            "resolved_at": resolved_at.isoformat(),
        }

    async def detect_breaches(
        self, current_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Detect all SLA breaches in active incidents.

        Args:
            current_time: Current timestamp. If None, uses current time

        Returns:
            List of breached incidents with details
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        breaches = []

        for incident_id in list(self.active_slas.keys()):
            sla_status = await self.check_sla_status(incident_id, current_time)

            if sla_status["is_breached"]:
                breaches.append(
                    {
                        "incident_id": incident_id,
                        "severity": sla_status["severity"],
                        "elapsed_minutes": sla_status["elapsed_minutes"],
                        "target_minutes": sla_status["target_minutes"],
                        "breach_time_minutes": sla_status["elapsed_minutes"]
                        - sla_status["target_minutes"],
                    }
                )

        return breaches

    async def get_at_risk_incidents(
        self, current_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get incidents that are at risk of breaching SLA.

        Args:
            current_time: Current timestamp. If None, uses current time

        Returns:
            List of at-risk incidents with details
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        at_risk = []

        for incident_id in list(self.active_slas.keys()):
            sla_record = self.active_slas[incident_id]

            if sla_record["resolved_at"]:
                continue

            sla_status = await self.check_sla_status(incident_id, current_time)

            if sla_status["is_at_risk"] and not sla_status["is_breached"]:
                at_risk.append(
                    {
                        "incident_id": incident_id,
                        "severity": sla_status["severity"],
                        "percentage_elapsed": sla_status["percentage_elapsed"],
                        "remaining_minutes": sla_status["remaining_minutes"],
                    }
                )

        return sorted(at_risk, key=lambda x: x["remaining_minutes"])

    async def get_sla_metrics(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Calculate SLA performance metrics.

        Args:
            start_date: Start of time period. If None, uses all data
            end_date: End of time period. If None, uses current time

        Returns:
            Dictionary with SLA performance metrics
        """
        if end_date is None:
            end_date = datetime.now(timezone.utc)

        resolved_incidents = [
            sla
            for sla in self.active_slas.values()
            if sla["resolved_at"] is not None
            and (start_date is None or sla["created_at"] >= start_date)
            and sla["resolved_at"] <= end_date
        ]

        if not resolved_incidents:
            return {
                "total_incidents": 0,
                "sla_met_count": 0,
                "sla_breached_count": 0,
                "sla_compliance_rate": 0.0,
                "avg_response_time_minutes": 0.0,
            }

        sla_met_count = sum(1 for sla in resolved_incidents if sla["status"] == SLAStatus.MET.value)

        total = len(resolved_incidents)
        compliance_rate = (sla_met_count / total * 100) if total > 0 else 0.0

        avg_response_time = (
            sum(sla["actual_response_minutes"] for sla in resolved_incidents) / total
        )

        metrics_by_severity = {}
        # Explicitly iterate over enum members for CodeQL compatibility
        for severity in list(SLASeverity):
            severity_incidents = [
                sla for sla in resolved_incidents if sla["severity"] == severity.value
            ]

            if severity_incidents:
                met = sum(1 for sla in severity_incidents if sla["status"] == SLAStatus.MET.value)
                metrics_by_severity[severity.name] = {
                    "total": len(severity_incidents),
                    "met": met,
                    "breached": len(severity_incidents) - met,
                    "compliance_rate": round((met / len(severity_incidents)) * 100, 2),
                }

        return {
            "total_incidents": total,
            "sla_met_count": sla_met_count,
            "sla_breached_count": total - sla_met_count,
            "sla_compliance_rate": round(compliance_rate, 2),
            "avg_response_time_minutes": round(avg_response_time, 2),
            "metrics_by_severity": metrics_by_severity,
        }

    async def get_incident_sla(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get SLA tracking record for a specific incident.

        Args:
            incident_id: Unique incident identifier

        Returns:
            SLA tracking record or None if not found
        """
        return self.active_slas.get(incident_id)

    async def update_sla_definition(self, severity: int, target_minutes: int) -> None:
        """Update SLA target time for a severity level.

        Args:
            severity: Severity level (1-5)
            target_minutes: New target response time in minutes

        Raises:
            ValueError: If severity or target_minutes invalid
        """
        if severity not in [s.value for s in SLASeverity]:
            raise ValueError(f"Invalid severity: {severity}")

        if target_minutes <= 0:
            raise ValueError("Target minutes must be positive")

        self.sla_definitions[SLASeverity(severity)] = target_minutes
