"""P2 Silver layer transformer tests (minimal - 8 tests)."""

import pytest

from src.core.transformer import SilverTransformer, mask_pii
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


class TestSilverTransformer:
    """Silver layer transformer tests."""

    def test_transformer_initializes(self):
        t = SilverTransformer()
        assert t.get_incidents() == []
        assert t.get_vulnerabilities() == []
        assert t.get_breaches() == []

    @pytest.mark.asyncio
    async def test_empty_servicenow_batch(self):
        t = SilverTransformer()
        m = await t.transform_batch("servicenow", [])
        assert m.transformed == 0
        assert m.total_input == 0

    @pytest.mark.asyncio
    async def test_empty_grafana_batch(self):
        t = SilverTransformer()
        m = await t.transform_batch("grafana", [])
        assert m.transformed == 0

    @pytest.mark.asyncio
    async def test_empty_defender_batch(self):
        t = SilverTransformer()
        m = await t.transform_batch("defender", [])
        assert m.transformed == 0

    @pytest.mark.asyncio
    async def test_empty_usatoday_batch(self):
        t = SilverTransformer()
        m = await t.transform_batch("usatoday", [])
        assert m.transformed == 0

    @pytest.mark.asyncio
    async def test_pii_masking_in_servicenow(self):
        t = SilverTransformer()
        records = [
            {
                "number": "INC0099999",
                "short_description": "Alert: admin@corp.com login from 192.168.1.50",
                "description": "SSN: 123-45-6789 detected in logs",
                "priority": "2",
                "state": "1",
                "opened_at": "2026-02-20T10:00:00Z",
                "org_name": "Finance",
            }
        ]
        await t.transform_batch("servicenow", records)
        incidents = t.get_incidents()
        assert len(incidents) == 1
        inc = incidents[0]
        assert "admin@corp.com" not in inc.title
        assert "192.168.1.50" not in inc.description
        assert "123-45-6789" not in inc.description

    @pytest.mark.asyncio
    async def test_metrics_structure(self):
        t = SilverTransformer()
        m = await t.transform_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        assert m.source == "servicenow"
        assert m.total_input == 4
        assert m.transformed == 4
        assert m.failed == 0

    @pytest.mark.asyncio
    async def test_all_sources_batch(self):
        t = SilverTransformer()
        await t.transform_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
        await t.transform_batch("grafana", MOCK_GRAFANA_ALERTS)
        await t.transform_batch("defender", MOCK_DEFENDER_INCIDENTS)
        await t.transform_batch("usatoday", MOCK_USATODAY_BREACHES)

        assert len(t.get_incidents()) == 8  # 4 servicenow + 4 grafana
        assert len(t.get_vulnerabilities()) == 4  # 4 defender
        assert len(t.get_breaches()) == 4  # 4 usatoday


class TestPIIMasking:
    """Direct PII masking function tests."""

    def test_email_masked(self):
        result = mask_pii("Contact admin@corp.com for help")
        assert "admin@corp.com" not in result
        assert "[EMAIL REDACTED]" in result

    def test_ip_masked(self):
        result = mask_pii("Source IP: 203.0.113.45 detected")
        assert "203.0.113.45" not in result
        assert "[IP REDACTED]" in result

    def test_ssn_masked(self):
        result = mask_pii("SSN on file: 123-45-6789")
        assert "123-45-6789" not in result
        assert "[SSN REDACTED]" in result

    def test_clean_text_unchanged(self):
        text = "Normal security incident description without PII"
        assert mask_pii(text) == text
