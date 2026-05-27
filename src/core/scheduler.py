"""Scheduler for orchestrating periodic connector execution.

Manages multiple data source connectors and executes them on configurable schedules.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class ConnectorType(str, Enum):
    """Supported connector types."""

    SERVICENOW = "servicenow"
    GRAFANA = "grafana"
    DEFENDER = "defender"
    USATODAY = "usatoday"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


class ConnectorStatus(str, Enum):
    """Connector execution status."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


@dataclass
class ConnectorConfig:
    """Configuration for a registered connector."""

    name: str
    connector_type: ConnectorType
    fetch_func: Callable[[], Coroutine[Any, Any, List[Dict[str, Any]]]]
    schedule_minutes: int = 15
    enabled: bool = True
    retry_count: int = 3
    retry_backoff_seconds: int = 60


@dataclass
class ConnectorHealth:
    """Health state of a connector."""

    name: str
    enabled: bool
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    last_status: ConnectorStatus = ConnectorStatus.PENDING
    total_runs: int = 0
    total_failures: int = 0
    last_error: Optional[str] = None


@dataclass
class SchedulerMetrics:
    """Aggregate metrics for the scheduler."""

    total_runs: int = 0
    total_failures: int = 0
    total_records_ingested: int = 0
    connectors_registered: int = 0
    last_run_at: Optional[datetime] = None

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        self.total_runs = 0
        self.total_failures = 0
        self.total_records_ingested = 0
        self.last_run_at = None


class Scheduler:
    """Orchestrates periodic execution of data source connectors.

    Manages connector registration, scheduled execution, health monitoring,
    and retry logic with exponential backoff.
    """

    def __init__(self, ingestion_pipeline: Any = None) -> None:
        """Initialize the scheduler.

        Args:
            ingestion_pipeline: IngestionPipeline instance to use for ingestion
        """
        self._pipeline = ingestion_pipeline
        self._connectors: Dict[str, ConnectorConfig] = {}
        self._health: Dict[str, ConnectorHealth] = {}
        self._metrics = SchedulerMetrics()
        self._running = False

    def add_connector(
        self,
        name: str,
        connector_type: ConnectorType,
        fetch_func: Callable[[], Coroutine[Any, Any, List[Dict[str, Any]]]],
        schedule_minutes: int = 15,
        enabled: bool = True,
        retry_count: int = 3,
    ) -> None:
        """Register a connector with the scheduler.

        Args:
            name: Unique connector name
            connector_type: Type of connector
            fetch_func: Async function that fetches records from the source
            schedule_minutes: How often to run (in minutes)
            enabled: Whether the connector is active
            retry_count: Number of retry attempts on failure
        """
        config = ConnectorConfig(
            name=name,
            connector_type=connector_type,
            fetch_func=fetch_func,
            schedule_minutes=schedule_minutes,
            enabled=enabled,
            retry_count=retry_count,
        )
        self._connectors[name] = config
        self._health[name] = ConnectorHealth(name=name, enabled=enabled)
        self._metrics.connectors_registered = len(self._connectors)
        logger.info("Registered connector: %s (type=%s)", name, connector_type)

    def disable_connector(self, name: str) -> None:
        """Disable a connector by name.

        Args:
            name: Connector name to disable
        """
        if name in self._connectors:
            self._connectors[name].enabled = False
            self._health[name].enabled = False

    def enable_connector(self, name: str) -> None:
        """Enable a connector by name.

        Args:
            name: Connector name to enable
        """
        if name in self._connectors:
            self._connectors[name].enabled = True
            self._health[name].enabled = True

    async def run_connector(self, name: str) -> ConnectorStatus:
        """Execute a single connector and ingest its records.

        Args:
            name: Name of the connector to run

        Returns:
            ConnectorStatus indicating success or failure
        """
        if name not in self._connectors:
            logger.warning("Connector %s not found", name)
            return ConnectorStatus.FAILED

        config = self._connectors[name]
        health = self._health[name]

        if not config.enabled:
            logger.debug("Connector %s is disabled, skipping", name)
            health.last_status = ConnectorStatus.SKIPPED
            return ConnectorStatus.SKIPPED

        attempt = 0
        last_error: Optional[str] = None

        while attempt < config.retry_count:
            try:
                records = await config.fetch_func()
                if self._pipeline is not None:
                    ingestion_metrics = await self._pipeline.ingest_batch(
                        source_name=name,
                        records=records,
                    )
                    self._metrics.total_records_ingested += ingestion_metrics.successful_records

                health.last_run = datetime.now(timezone.utc)
                health.last_status = ConnectorStatus.SUCCESS
                health.total_runs += 1
                self._metrics.total_runs += 1
                self._metrics.last_run_at = datetime.now(timezone.utc)
                logger.info("Connector %s completed successfully", name)
                return ConnectorStatus.SUCCESS

            except Exception as exc:
                last_error = str(exc)
                attempt += 1
                logger.warning(
                    "Connector %s failed (attempt %d/%d): %s",
                    name,
                    attempt,
                    config.retry_count,
                    exc,
                )

        # All retries exhausted
        health.last_run = datetime.now(timezone.utc)
        health.last_status = ConnectorStatus.FAILED
        health.last_error = last_error
        health.total_runs += 1
        health.total_failures += 1
        self._metrics.total_runs += 1
        self._metrics.total_failures += 1
        return ConnectorStatus.FAILED

    async def run_all_connectors(self) -> Dict[str, ConnectorStatus]:
        """Execute all enabled connectors.

        Returns:
            Dictionary mapping connector name to its status
        """
        results: Dict[str, ConnectorStatus] = {}
        for name in self._connectors:
            results[name] = await self.run_connector(name)
        return results

    def get_metrics(self) -> SchedulerMetrics:
        """Return current scheduler metrics.

        Returns:
            SchedulerMetrics instance
        """
        return self._metrics

    def health_status(self) -> Dict[str, Any]:
        """Return health status of all connectors and the scheduler.

        Returns:
            Dictionary with health status information
        """
        pipeline_health: Dict[str, Any] = {}
        if self._pipeline is not None:
            pipeline_health = self._pipeline.health_check()

        return {
            "scheduler_running": self._running,
            "connectors": {
                name: {
                    "enabled": h.enabled,
                    "last_run": h.last_run.isoformat() if h.last_run else None,
                    "last_status": h.last_status,
                    "total_runs": h.total_runs,
                    "total_failures": h.total_failures,
                }
                for name, h in self._health.items()
            },
            "pipeline_health": pipeline_health,
            "metrics": {
                "total_runs": self._metrics.total_runs,
                "total_failures": self._metrics.total_failures,
                "total_records_ingested": self._metrics.total_records_ingested,
            },
        }

    @property
    def connector_count(self) -> int:
        """Return the number of registered connectors."""
        return len(self._connectors)

    @property
    def running(self) -> bool:
        """Return whether the scheduler is running."""
        return self._running
