"""Security tests for the ingestion pipeline.

Verifies that the InputValidator catches attack payloads (SQL injection, XSS,
SSRF, command injection, path traversal) and that malicious records are
quarantined before they reach the Bronze layer.
"""

import pytest

from src.core.ingestion_pipeline import IngestionPipeline, IngestionStatus
from src.security.input_validator import InputValidator, ThreatType

# ---------------------------------------------------------------------------
# InputValidator unit tests (no pipeline overhead)
# ---------------------------------------------------------------------------


class TestInputValidatorDirectly:
    """Verify InputValidator detects each threat category."""

    def test_sql_injection_detected(self):
        v = InputValidator()
        assert v.is_sql_injection("'; DROP TABLE incidents; --")

    def test_sql_union_select_detected(self):
        v = InputValidator()
        assert v.is_sql_injection("' UNION SELECT * FROM users--")

    def test_xss_script_tag_detected(self):
        v = InputValidator()
        assert v.is_xss("<script>alert('xss')</script>")

    def test_xss_javascript_protocol_detected(self):
        v = InputValidator()
        assert v.is_xss("javascript:alert(1)")

    def test_ssrf_metadata_endpoint_detected(self):
        v = InputValidator()
        assert v.is_ssrf("http://169.254.169.254/latest/meta-data/")

    def test_ssrf_localhost_detected(self):
        v = InputValidator()
        assert v.is_ssrf("http://localhost/internal-api")

    def test_path_traversal_detected(self):
        v = InputValidator()
        assert v.is_path_traversal("../../etc/passwd")

    def test_clean_text_passes(self):
        v = InputValidator()
        result = v.validate("Normal incident description")
        assert result.is_valid

    def test_validate_returns_threat_details(self):
        v = InputValidator()
        result = v.validate("'; DROP TABLE users--", [ThreatType.SQL_INJECTION])
        assert not result.is_valid
        assert len(result.threats) > 0
        assert result.threats[0]["type"] == ThreatType.SQL_INJECTION.value


# ---------------------------------------------------------------------------
# Pipeline quarantine integration tests
# ---------------------------------------------------------------------------


class TestSQLInjectionQuarantine:
    """SQL injection payloads must be quarantined, not ingested."""

    @pytest.mark.asyncio
    async def test_drop_table_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"short_description": "'; DROP TABLE incidents; --", "priority": "1"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0
        assert pipeline.get_bronze_record_count() == 0
        assert pipeline.get_quarantine_count() == 1

    @pytest.mark.asyncio
    async def test_union_select_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"query": "' UNION SELECT username, password FROM users--"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0

    @pytest.mark.asyncio
    async def test_multiple_sql_injections_all_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [
            {"field": "'; DROP TABLE incidents; --"},
            {"field": "' UNION SELECT * FROM users--"},
            {"field": "1; DELETE FROM events WHERE 1=1"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 3
        assert metrics.successful_records == 0
        assert metrics.status == IngestionStatus.FAILED


class TestXSSQuarantine:
    """XSS payloads must be quarantined."""

    @pytest.mark.asyncio
    async def test_script_tag_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"description": "<script>document.cookie='stolen'</script>"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0

    @pytest.mark.asyncio
    async def test_javascript_protocol_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"url": "javascript:alert('xss')"}]
        metrics = await pipeline.ingest_batch("grafana", malicious)
        assert metrics.quarantined_records == 1

    @pytest.mark.asyncio
    async def test_iframe_injection_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"summary": "<iframe src='http://evil.com'></iframe>"}]
        metrics = await pipeline.ingest_batch("grafana", malicious)
        assert metrics.quarantined_records == 1


class TestSSRFQuarantine:
    """SSRF payloads must be quarantined."""

    @pytest.mark.asyncio
    async def test_metadata_endpoint_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"webhook": "http://169.254.169.254/latest/meta-data/iam/credentials"}]
        metrics = await pipeline.ingest_batch("defender", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0

    @pytest.mark.asyncio
    async def test_localhost_url_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"callback": "http://localhost:8080/admin"}]
        metrics = await pipeline.ingest_batch("defender", malicious)
        assert metrics.quarantined_records == 1

    @pytest.mark.asyncio
    async def test_file_protocol_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"path": "file:///etc/passwd"}]
        metrics = await pipeline.ingest_batch("usatoday", malicious)
        assert metrics.quarantined_records == 1


class TestPathTraversalQuarantine:
    """Path traversal payloads must be quarantined."""

    @pytest.mark.asyncio
    async def test_unix_path_traversal_quarantined(self):
        pipeline = IngestionPipeline()
        malicious = [{"filename": "../../etc/passwd"}]
        metrics = await pipeline.ingest_batch("servicenow", malicious)
        assert metrics.quarantined_records == 1
        assert metrics.successful_records == 0


class TestCleanDataNotQuarantined:
    """Legitimate records must NOT be quarantined."""

    @pytest.mark.asyncio
    async def test_clean_servicenow_record_accepted(self):
        pipeline = IngestionPipeline()
        clean = [
            {
                "number": "INC0099001",
                "short_description": "Server CPU spike detected",
                "priority": "2",
                "state": "1",
                "org_name": "Finance",
            }
        ]
        metrics = await pipeline.ingest_batch("servicenow", clean)
        assert metrics.quarantined_records == 0
        assert metrics.successful_records == 1

    @pytest.mark.asyncio
    async def test_clean_grafana_alert_accepted(self):
        pipeline = IngestionPipeline()
        clean = [
            {
                "alertname": "HighCPUUsage",
                "state": "alerting",
                "severity": "high",
                "summary": "CPU above 90% for 5 minutes",
                "org_name": "IT",
            }
        ]
        metrics = await pipeline.ingest_batch("grafana", clean)
        assert metrics.quarantined_records == 0
        assert metrics.successful_records == 1

    @pytest.mark.asyncio
    async def test_mixed_clean_and_malicious_batch(self):
        """Clean records ingest; malicious ones quarantined; status is PARTIAL."""
        pipeline = IngestionPipeline()
        batch = [
            {
                "number": "INC0099002",
                "short_description": "Disk space alert",
                "priority": "3",
                "state": "1",
                "org_name": "IT",
            },
            {"short_description": "'; DROP TABLE incidents; --", "priority": "1"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", batch)
        assert metrics.successful_records == 1
        assert metrics.quarantined_records == 1
        assert metrics.status == IngestionStatus.PARTIAL

    @pytest.mark.asyncio
    async def test_clean_records_reach_bronze_layer(self):
        """After ingestion, clean records must be present in the Bronze store."""
        pipeline = IngestionPipeline()
        clean = [
            {"number": "INC0099003", "short_description": "Memory warning", "priority": "3",
             "state": "1", "org_name": "Engineering"},
            {"number": "INC0099004", "short_description": "Network latency spike", "priority": "2",
             "state": "1", "org_name": "IT"},
        ]
        metrics = await pipeline.ingest_batch("servicenow", clean)
        assert metrics.successful_records == 2
        assert pipeline.get_bronze_record_count("servicenow") == 2
        # Quarantine must be empty
        assert pipeline.get_quarantine_count() == 0
