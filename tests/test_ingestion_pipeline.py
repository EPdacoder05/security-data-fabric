"""P1 ingestion pipeline tests - unit + validation tests."""

import pytest

from src.core.ingestion_pipeline import IngestionMetrics, IngestionPipeline, IngestionStatus
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


# ---------------------------------------------------------------------------
# TestMockDataFixtures
# ---------------------------------------------------------------------------


class TestMockDataFixtures:
    """Validate mock data fixture structure."""

    def test_servicenow_fixture_count(self):
        assert len(MOCK_SERVICENOW_INCIDENTS) == 4

    def test_servicenow_has_required_fields(self):
        required = {"number", "short_description", "priority", "state"}
        for record in MOCK_SERVICENOW_INCIDENTS:
            assert required.issubset(record.keys())

    def test_grafana_fixture_count(self):
        assert len(MOCK_GRAFANA_ALERTS) == 4

    def test_grafana_has_required_fields(self):
        required = {"alertname", "state", "severity"}
        for record in MOCK_GRAFANA_ALERTS:
            assert required.issubset(record.keys())

    def test_defender_fixture_count(self):
        assert len(MOCK_DEFENDER_INCIDENTS) == 4

    def test_usatoday_fixture_count(self):
        assert len(MOCK_USATODAY_BREACHES) == 4

    def test_usatoday_has_required_fields(self):
        required = {"id", "title", "breach_type", "records_affected"}
        for record in MOCK_USATODAY_BREACHES:
            assert required.issubset(record.keys())

    def test_all_sources_total_16_records(self):
        total = (
            len(MOCK_SERVICENOW_INCIDENTS)
            + len(MOCK_GRAFANA_ALERTS)
            + len(MOCK_DEFENDER_INCIDENTS)
            + len(MOCK_USATODAY_BREACHES)
        )
        assert total == 16


# ---------------------------------------------------------------------------
# TestIngestionPipelineSuccess
# ---------------------------------------------------------------------------


class TestIngestionPipelineSuccess:
    """Happy path ingestion tests."""

    @pytest.mark.asyncio
    async def test_ingest_servicenow_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4
        assert metrics.failed_records == 0
        assert metrics.quarantined_records == 0

    @pytest.mark.asyncio
    async def test_ingest_grafana_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

    @pytest.mark.asyncio
    async def test_ingest_defender_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

    @pytest.mark.asyncio
    async def test_ingest_usatoday_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("usatoday", MOCK_USATODAY_BREACHES)
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

    @pytest.mark.asyncio
    async def test_metrics_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert (
            metrics.successful_records + metrics.failed_records + metrics.quarantined_records
            <= metrics.total_records
        )

    @pytest.mark.asyncio
    async def test_bronze_count_increments(self):
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert pipeline.get_bronze_record_count() == 4
        await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        assert pipeline.get_bronze_record_count() == 8

    @pytest.mark.asyncio
    async def test_duration_is_positive(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_batch_id_assigned(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch(
            "servicenow", MOCK_SERVICENOW_INCIDENTS, batch_id="test-batch-001"
        )
        assert metrics.batch_id == "test-batch-001"


# ---------------------------------------------------------------------------
# TestIngestionPipelineErrors
# ---------------------------------------------------------------------------


class TestIngestionPipelineErrors:
    """Error handling and quarantine tests."""

    @pytest.mark.asyncio
    async def test_empty_batch_returns_success(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", [])
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.total_records == 0

    @pytest.mark.asyncio
    async def test_non_dict_record_counted_as_quarantined(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", ["not-a-dict", 42])
        assert metrics.quarantined_records == 2
        assert metrics.successful_records == 0

    @pytest.mark.asyncio
    async def test_sql_injection_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"short_description": "'; DROP TABLE incidents; --", "priority": "1"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0

    @pytest.mark.asyncio
    async def test_xss_payload_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"short_description": "<script>alert('xss')</script>", "priority": "1"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1

    @pytest.mark.asyncio
    async def test_partial_status_on_mixed_batch(self):
        pipeline = IngestionPipeline()
        mixed = MOCK_SERVICENOW_INCIDENTS[:2] + [
            {"short_description": "'; DROP TABLE--", "priority": "1"}
        ]
        metrics = await pipeline.ingest_batch("servicenow", mixed)
        assert metrics.status == IngestionStatus.PARTIAL
        assert metrics.successful_records > 0
        assert metrics.quarantined_records > 0

    @pytest.mark.asyncio
    async def test_duplicate_records_not_double_ingested(self):
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        count_after_first = pipeline.get_bronze_record_count()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert pipeline.get_bronze_record_count() == count_after_first
        assert metrics.duplicate_records == 4

    @pytest.mark.asyncio
    async def test_error_messages_captured(self):
        pipeline = IngestionPipeline()
        malicious = [{"query": "'; DROP TABLE users--"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert len(metrics.error_messages) > 0


# ---------------------------------------------------------------------------
# TestIngestionHealth
# ---------------------------------------------------------------------------


class TestIngestionHealth:
    """Pipeline health check tests."""

    def test_health_check_empty_pipeline(self):
        pipeline = IngestionPipeline()
        health = pipeline.health_check()
        assert health["status"] == "healthy"
        assert health["bronze_record_count"] == 0
        assert health["quarantine_count"] == 0

    @pytest.mark.asyncio
    async def test_health_check_after_ingestion(self):
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        health = pipeline.health_check()
        assert health["bronze_record_count"] == 4
        assert health["total_batches"] == 1


# ---------------------------------------------------------------------------
# TestIngestionPerformance
# ---------------------------------------------------------------------------


class TestIngestionPerformance:
    """Performance validation tests."""

    @pytest.mark.asyncio
    async def test_servicenow_ingestion_fast(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.duration_seconds < 5.0

    @pytest.mark.asyncio
    async def test_grafana_ingestion_fast(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        assert metrics.duration_seconds < 5.0

    @pytest.mark.asyncio
    async def test_defender_ingestion_fast(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)
        assert metrics.duration_seconds < 5.0
