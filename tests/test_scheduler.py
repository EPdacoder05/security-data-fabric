"""P1 scheduler tests - setup, execution, metrics, health."""

import pytest

from src.core.ingestion_pipeline import IngestionPipeline
from src.core.scheduler import ConnectorStatus, ConnectorType, Scheduler
from src.data.fixtures.mock_grafana_incidents import MOCK_SERVICENOW_INCIDENTS


async def _mock_servicenow_fetch():
    return MOCK_SERVICENOW_INCIDENTS


async def _mock_grafana_fetch():
    return []


async def _failing_fetch():
    raise RuntimeError("API unavailable")


# ---------------------------------------------------------------------------
# TestSchedulerSetup
# ---------------------------------------------------------------------------


class TestSchedulerSetup:
    """Scheduler initialization and connector registration tests."""

    def test_scheduler_initializes_empty(self):
        scheduler = Scheduler()
        assert scheduler.connector_count == 0

    def test_register_connector(self):
        scheduler = Scheduler()
        scheduler.add_connector(
            name="servicenow",
            connector_type=ConnectorType.SERVICENOW,
            fetch_func=_mock_servicenow_fetch,
        )
        assert scheduler.connector_count == 1

    def test_register_multiple_connectors(self):
        scheduler = Scheduler()
        scheduler.add_connector(
            name="servicenow",
            connector_type=ConnectorType.SERVICENOW,
            fetch_func=_mock_servicenow_fetch,
        )
        scheduler.add_connector(
            name="grafana",
            connector_type=ConnectorType.GRAFANA,
            fetch_func=_mock_grafana_fetch,
        )
        assert scheduler.connector_count == 2

    def test_connector_config_stored(self):
        scheduler = Scheduler()
        scheduler.add_connector(
            name="servicenow",
            connector_type=ConnectorType.SERVICENOW,
            fetch_func=_mock_servicenow_fetch,
            schedule_minutes=30,
        )
        config = scheduler._connectors["servicenow"]
        assert config.schedule_minutes == 30
        assert config.connector_type == ConnectorType.SERVICENOW


# ---------------------------------------------------------------------------
# TestSchedulerExecution
# ---------------------------------------------------------------------------


class TestSchedulerExecution:
    """Connector execution tests."""

    @pytest.mark.asyncio
    async def test_run_single_connector_success(self):
        pipeline = IngestionPipeline()
        scheduler = Scheduler(pipeline)
        scheduler.add_connector(
            name="servicenow",
            connector_type=ConnectorType.SERVICENOW,
            fetch_func=_mock_servicenow_fetch,
        )
        status = await scheduler.run_connector("servicenow")
        assert status == ConnectorStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_disabled_connector_skipped(self):
        pipeline = IngestionPipeline()
        scheduler = Scheduler(pipeline)
        scheduler.add_connector(
            name="servicenow",
            connector_type=ConnectorType.SERVICENOW,
            fetch_func=_mock_servicenow_fetch,
            enabled=False,
        )
        status = await scheduler.run_connector("servicenow")
        assert status == ConnectorStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_failing_connector_returns_failed(self):
        scheduler = Scheduler()
        scheduler.add_connector(
            name="broken",
            connector_type=ConnectorType.GENERIC,
            fetch_func=_failing_fetch,
            retry_count=1,
        )
        status = await scheduler.run_connector("broken")
        assert status == ConnectorStatus.FAILED

    @pytest.mark.asyncio
    async def test_run_all_connectors(self):
        pipeline = IngestionPipeline()
        scheduler = Scheduler(pipeline)
        scheduler.add_connector("sn", ConnectorType.SERVICENOW, _mock_servicenow_fetch)
        scheduler.add_connector("gf", ConnectorType.GRAFANA, _mock_grafana_fetch)

        results = await scheduler.run_all_connectors()
        assert results["sn"] == ConnectorStatus.SUCCESS
        assert results["gf"] == ConnectorStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_enable_disable_connector(self):
        scheduler = Scheduler()
        scheduler.add_connector("sn", ConnectorType.SERVICENOW, _mock_servicenow_fetch)
        scheduler.disable_connector("sn")
        status = await scheduler.run_connector("sn")
        assert status == ConnectorStatus.SKIPPED

        scheduler.enable_connector("sn")
        # Now it would run - just verify the config change worked
        assert scheduler._connectors["sn"].enabled is True


# ---------------------------------------------------------------------------
# TestSchedulerMetrics
# ---------------------------------------------------------------------------


class TestSchedulerMetrics:
    """Scheduler metrics tracking tests."""

    def test_metrics_initialized_to_zero(self):
        scheduler = Scheduler()
        m = scheduler.get_metrics()
        assert m.total_runs == 0
        assert m.total_failures == 0
        assert m.total_records_ingested == 0

    def test_metrics_reset(self):
        scheduler = Scheduler()
        m = scheduler.get_metrics()
        m.total_runs = 42
        m.reset()
        assert m.total_runs == 0
        assert m.total_failures == 0


# ---------------------------------------------------------------------------
# TestSchedulerHealth
# ---------------------------------------------------------------------------


class TestSchedulerHealth:
    """Scheduler health status tests."""

    def test_health_status_structure(self):
        scheduler = Scheduler()
        health = scheduler.health_status()
        assert "scheduler_running" in health
        assert "connectors" in health
        assert "metrics" in health

    @pytest.mark.asyncio
    async def test_connector_health_tracks_runs(self):
        pipeline = IngestionPipeline()
        scheduler = Scheduler(pipeline)
        scheduler.add_connector("sn", ConnectorType.SERVICENOW, _mock_servicenow_fetch)
        await scheduler.run_connector("sn")

        health = scheduler.health_status()
        sn_health = health["connectors"]["sn"]
        assert sn_health["total_runs"] == 1
        assert sn_health["last_status"] == ConnectorStatus.SUCCESS


# ---------------------------------------------------------------------------
# TestSchedulerBasics
# ---------------------------------------------------------------------------


class TestSchedulerBasics:
    """Basic registration and type validation tests."""

    def test_registration_count_accurate(self):
        scheduler = Scheduler()
        for i, (name, ct) in enumerate(
            [
                ("sn", ConnectorType.SERVICENOW),
                ("gf", ConnectorType.GRAFANA),
                ("df", ConnectorType.DEFENDER),
                ("ut", ConnectorType.USATODAY),
            ]
        ):
            scheduler.add_connector(name, ct, _mock_grafana_fetch)
            assert scheduler.connector_count == i + 1

    def test_connector_type_stored_correctly(self):
        scheduler = Scheduler()
        scheduler.add_connector("sn", ConnectorType.SERVICENOW, _mock_servicenow_fetch)
        assert scheduler._connectors["sn"].connector_type == ConnectorType.SERVICENOW
