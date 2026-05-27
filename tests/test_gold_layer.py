"""P3 Gold layer aggregation tests."""

import pytest

from src.core.gold_aggregator import GoldAggregator, TrafficLight
from src.core.transformer import SilverTransformer
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


async def _load_silver():
    t = SilverTransformer()
    await t.transform_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
    await t.transform_batch("grafana", MOCK_GRAFANA_ALERTS)
    await t.transform_batch("defender", MOCK_DEFENDER_INCIDENTS)
    await t.transform_batch("usatoday", MOCK_USATODAY_BREACHES)
    return t.get_incidents(), t.get_vulnerabilities(), t.get_breaches()


class TestTrafficLight:
    """Traffic light computation tests."""

    def test_green_when_no_critical(self):
        agg = GoldAggregator()
        light = agg.compute_traffic_light(0, 0, 0.0)
        assert light == TrafficLight.GREEN

    def test_yellow_on_one_critical_incident(self):
        agg = GoldAggregator()
        light = agg.compute_traffic_light(1, 0, 0.0)
        assert light == TrafficLight.YELLOW

    def test_red_on_three_critical_incidents(self):
        agg = GoldAggregator()
        light = agg.compute_traffic_light(3, 0, 0.0)
        assert light == TrafficLight.RED

    def test_red_on_high_breach_risk(self):
        agg = GoldAggregator()
        light = agg.compute_traffic_light(0, 0, 80.0)
        assert light == TrafficLight.RED

    def test_yellow_on_elevated_breach_risk(self):
        agg = GoldAggregator()
        light = agg.compute_traffic_light(0, 0, 50.0)
        assert light == TrafficLight.YELLOW


class TestKPIComputation:
    """KPI computation tests."""

    @pytest.mark.asyncio
    async def test_kpis_computed_for_org(self):
        incidents, vulns, breaches = await _load_silver()
        agg = GoldAggregator()
        kpis = agg.compute_kpis("Finance", incidents, vulns, breaches)
        assert kpis.org_name == "Finance"
        assert kpis.traffic_light in (TrafficLight.GREEN, TrafficLight.YELLOW, TrafficLight.RED)

    @pytest.mark.asyncio
    async def test_kpis_breach_risk_in_range(self):
        incidents, vulns, breaches = await _load_silver()
        agg = GoldAggregator()
        kpis = agg.compute_kpis("Finance", incidents, vulns, breaches)
        assert 0.0 <= kpis.breach_risk_score <= 100.0

    @pytest.mark.asyncio
    async def test_kpis_detection_rate_in_range(self):
        incidents, vulns, breaches = await _load_silver()
        agg = GoldAggregator()
        kpis = agg.compute_kpis("Finance", incidents, vulns, breaches)
        assert 0.0 <= kpis.detection_rate <= 1.0

    @pytest.mark.asyncio
    async def test_aggregate_all_processes_orgs(self):
        incidents, vulns, breaches = await _load_silver()
        agg = GoldAggregator()
        metrics = agg.aggregate_all(incidents, vulns, breaches)
        assert metrics.orgs_processed > 0
        assert metrics.kpis_computed > 0


class TestIncidentTrends:
    """Incident trend computation tests."""

    @pytest.mark.asyncio
    async def test_trends_computed(self):
        incidents, _, _ = await _load_silver()
        agg = GoldAggregator()
        trends = agg.compute_incident_trends(incidents, weeks=2)
        assert isinstance(trends, list)

    @pytest.mark.asyncio
    async def test_empty_incidents_no_trends(self):
        agg = GoldAggregator()
        trends = agg.compute_incident_trends([])
        assert trends == []
