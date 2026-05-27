"""P1 end-to-end ingestion tests - full pipeline flow."""

import pytest

from src.core.ingestion_pipeline import IngestionPipeline, IngestionStatus
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


class TestIngestionE2E:
    """End-to-end ingestion tests verifying full pipeline flow."""

    @pytest.mark.asyncio
    async def test_servicenow_e2e(self):
        """Full ServiceNow ingestion with validation."""
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)

        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4
        assert metrics.quarantined_records == 0

        records = [r for r in pipeline._bronze_records if r.source_name == "servicenow"]
        assert len(records) == 4
        for r in records:
            assert r.source_name == "servicenow"
            assert r.raw_payload is not None
            assert r.data_hash != ""

    @pytest.mark.asyncio
    async def test_grafana_e2e(self):
        """Full Grafana alert ingestion."""
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)

        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

        records = [r for r in pipeline._bronze_records if r.source_name == "grafana"]
        assert len(records) == 4

    @pytest.mark.asyncio
    async def test_defender_e2e(self):
        """Full Defender incident ingestion."""
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)

        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

    @pytest.mark.asyncio
    async def test_usatoday_e2e(self):
        """Full USA Today breach ingestion."""
        pipeline = IngestionPipeline()
        metrics = await pipeline.ingest_batch("usatoday", MOCK_USATODAY_BREACHES)

        assert metrics.status == IngestionStatus.SUCCESS
        assert metrics.successful_records == 4

    @pytest.mark.asyncio
    async def test_concurrent_source_ingestion(self):
        """Multi-source ingestion in a single pipeline instance."""
        pipeline = IngestionPipeline()

        m1 = await pipeline.ingest_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        m2 = await pipeline.ingest_batch("grafana", MOCK_GRAFANA_ALERTS)
        m3 = await pipeline.ingest_batch("defender", MOCK_DEFENDER_INCIDENTS)
        m4 = await pipeline.ingest_batch("usatoday", MOCK_USATODAY_BREACHES)

        total = pipeline.get_bronze_record_count()
        assert total == 16

        assert m1.successful_records == 4
        assert m2.successful_records == 4
        assert m3.successful_records == 4
        assert m4.successful_records == 4

        health = pipeline.health_check()
        assert health["bronze_record_count"] == 16
        assert health["total_batches"] == 4
