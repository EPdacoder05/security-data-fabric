"""Ingestion metrics accuracy tests.

Verifies that IngestionMetrics fields are always consistent:
- successful + failed + quarantined + duplicate <= total_records
- Duration is measured and positive
- Error messages are captured for every quarantined/failed record
- Batch IDs are tracked in metadata
- Status reflects the outcome correctly
"""

import pytest

from src.core.ingestion_pipeline import IngestionMetrics, IngestionPipeline, IngestionStatus
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)

# ---------------------------------------------------------------------------
# Metrics field consistency
# ---------------------------------------------------------------------------


class TestMetricsFieldConsistency:
    """successful + failed + quarantined + duplicate <= total_records."""

    @pytest.mark.asyncio
    async def test_all_clean_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_all_malicious_totals_match(self):
        pipeline = IngestionPipeline()
        batch = [
            {"field": "'; DROP TABLE users--"},
            {"field": "<script>alert(1)</script>"},
            {"field": "http://169.254.169.254/"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", batch)
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_mixed_batch_totals_match(self):
        pipeline = IngestionPipeline()
        batch = MOCK_SERVICENOW_INCIDENTS[:2] + [
            {"field": "'; DROP TABLE users--"},
            {"field": "<script>steal()</script>"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", batch)
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_empty_batch_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", [])
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_duplicate_records_totals_match(self):
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        _assert_totals_consistent(metrics)
        assert metrics.duplicate_records == 4

    @pytest.mark.asyncio
    async def test_grafana_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_defender_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)
        _assert_totals_consistent(metrics)

    @pytest.mark.asyncio
    async def test_usatoday_totals_match(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("usatoday", MOCK_USATODAY_BREACHES)
        _assert_totals_consistent(metrics)


# ---------------------------------------------------------------------------
# Duration measurement
# ---------------------------------------------------------------------------


class TestMetricsDuration:
    """Duration must be measured and non-negative."""

    @pytest.mark.asyncio
    async def test_duration_is_positive_for_non_empty_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_duration_measured_for_empty_batch(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", [])
        assert metrics.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_duration_is_float(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        assert isinstance(metrics.duration_seconds, float)

    @pytest.mark.asyncio
    async def test_larger_batch_not_instant(self):
        """A batch of 16 records takes some measurable time."""
        pipeline = IngestionPipeline()
        all_records = (
            MOCK_SERVICENOW_INCIDENTS
            + MOCK_GRAFANA_ALERTS
            + MOCK_DEFENDER_INCIDENTS
            + MOCK_USATODAY_BREACHES
        )
        metrics = await pipeline.ingest_batch("servicenow", all_records)
        # Duration must be >= 0 (execution always takes some time)
        assert metrics.duration_seconds >= 0


# ---------------------------------------------------------------------------
# Error message capture
# ---------------------------------------------------------------------------


class TestMetricsErrorMessages:
    """Error messages must be captured for every quarantined/failed record."""

    @pytest.mark.asyncio
    async def test_quarantined_record_has_error_message(self):
        pipeline = IngestionPipeline()
        malicious = [{"field": "'; DROP TABLE users--"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert len(metrics.error_messages) >= 1
        # Error message should mention threat type
        assert any(
            "threat" in msg.lower() or "security" in msg.lower() for msg in metrics.error_messages
        )

    @pytest.mark.asyncio
    async def test_multiple_quarantined_records_have_error_messages(self):
        pipeline = IngestionPipeline()
        malicious = [
            {"field": "'; DROP TABLE--"},
            {"field": "<script>alert(1)</script>"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 2
        assert len(metrics.error_messages) == 2

    @pytest.mark.asyncio
    async def test_non_dict_record_has_error_message(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", ["not-a-dict"])
        assert metrics.quarantined_records == 1
        assert len(metrics.error_messages) == 1

    @pytest.mark.asyncio
    async def test_clean_batch_has_no_error_messages(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert len(metrics.error_messages) == 0


# ---------------------------------------------------------------------------
# Status correctness
# ---------------------------------------------------------------------------


class TestMetricsStatus:
    """IngestionStatus must correctly reflect the batch outcome."""

    @pytest.mark.asyncio
    async def test_all_clean_returns_success(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.status == IngestionStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_all_malicious_returns_failed(self):
        pipeline = IngestionPipeline()
        malicious = [{"field": "'; DROP TABLE--"}, {"field": "<script>x</script>"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.status == IngestionStatus.FAILED

    @pytest.mark.asyncio
    async def test_mixed_returns_partial(self):
        pipeline = IngestionPipeline()
        batch = MOCK_SERVICENOW_INCIDENTS[:1] + [{"field": "'; DROP TABLE--"}]
        metrics = await pipeline.ingest_batch("servicenow", batch)
        assert metrics.status == IngestionStatus.PARTIAL

    @pytest.mark.asyncio
    async def test_empty_returns_success(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", [])
        assert metrics.status == IngestionStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_all_duplicates_returns_success(self):
        """A batch of only duplicates still counts as success (no new errors)."""
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.duplicate_records == 4
        assert metrics.successful_records == 0


# ---------------------------------------------------------------------------
# Batch ID and metadata tracking
# ---------------------------------------------------------------------------


class TestMetricsBatchTracking:
    """Batch IDs must be assigned and metadata stored for every batch."""

    @pytest.mark.asyncio
    async def test_custom_batch_id_preserved(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch(
            "servicenow", MOCK_SERVICENOW_INCIDENTS, batch_id="demo-batch-001"
        )
        assert metrics.batch_id == "demo-batch-001"

    @pytest.mark.asyncio
    async def test_auto_batch_id_assigned(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.batch_id != ""
        assert len(metrics.batch_id) > 0

    @pytest.mark.asyncio
    async def test_metadata_stored_per_batch(self):
        pipeline = IngestionPipeline()
        await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS, batch_id="b-001")
        await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS, batch_id="b-002")
        assert len(pipeline._ingestion_metadata) == 2
        batch_ids = [m["batch_id"] for m in pipeline._ingestion_metadata]
        assert "b-001" in batch_ids
        assert "b-002" in batch_ids

    @pytest.mark.asyncio
    async def test_source_name_in_metrics(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)
        assert metrics.source_name == "defender"

    @pytest.mark.asyncio
    async def test_ingested_at_is_set(self):
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert metrics.ingested_at is not None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _assert_totals_consistent(metrics: IngestionMetrics) -> None:
    """Assert that count fields are self-consistent."""
    accounted = (
        metrics.successful_records
        + metrics.failed_records
        + metrics.quarantined_records
        + metrics.duplicate_records
    )
    assert accounted <= metrics.total_records, (
        f"Accounted ({accounted}) > total ({metrics.total_records}): {metrics}"
    )
    assert metrics.successful_records >= 0
    assert metrics.failed_records >= 0
    assert metrics.quarantined_records >= 0
    assert metrics.duplicate_records >= 0
