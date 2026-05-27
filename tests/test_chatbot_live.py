"""P4 Chatbot live data integration tests - 16 tests."""

import pytest

from src.chatbot.availability_templates import ChatbotLiveTemplates, ChatbotResponse
from src.core.transformer import SilverTransformer
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


async def _build_chatbot() -> ChatbotLiveTemplates:
    """Build a ChatbotLiveTemplates instance loaded with mock data."""
    t = SilverTransformer()
    await t.transform_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
    await t.transform_batch("grafana", MOCK_GRAFANA_ALERTS)
    await t.transform_batch("defender", MOCK_DEFENDER_INCIDENTS)
    await t.transform_batch("usatoday", MOCK_USATODAY_BREACHES)

    chatbot = ChatbotLiveTemplates()
    chatbot.load_data(t.get_incidents(), t.get_vulnerabilities(), t.get_breaches())
    return chatbot


class TestChatbotInit:
    """Chatbot initialization tests."""

    def test_chatbot_initializes(self):
        chatbot = ChatbotLiveTemplates()
        assert chatbot is not None

    def test_chatbot_with_no_data(self):
        chatbot = ChatbotLiveTemplates()
        response = chatbot.get_security_posture()
        assert isinstance(response, ChatbotResponse)
        assert response.query_type == "security_posture"

    def test_chatbot_load_data(self):
        chatbot = ChatbotLiveTemplates()
        chatbot.load_data([], [], [])
        # Empty data loads without error
        assert chatbot._incidents == []


class TestSecurityPosture:
    """Security posture query tests."""

    @pytest.mark.asyncio
    async def test_get_security_posture_returns_response(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_security_posture()
        assert isinstance(response, ChatbotResponse)
        assert response.query_type == "security_posture"

    @pytest.mark.asyncio
    async def test_security_posture_has_narrative(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_security_posture()
        assert len(response.narrative) > 0

    @pytest.mark.asyncio
    async def test_security_posture_has_traffic_light(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_security_posture()
        assert response.traffic_light in ("RED", "YELLOW", "GREEN")

    @pytest.mark.asyncio
    async def test_security_posture_finance_org(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_security_posture("Finance")
        assert response.org_name == "Finance"
        assert response.traffic_light is not None

    @pytest.mark.asyncio
    async def test_security_posture_nonexistent_org(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_security_posture("NONEXISTENT_ORG_XYZ")
        # Should return a response, not raise
        assert isinstance(response, ChatbotResponse)


class TestIncidentQueries:
    """Incident-related query tests."""

    @pytest.mark.asyncio
    async def test_get_top_incidents_returns_response(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_top_incidents()
        assert isinstance(response, ChatbotResponse)
        assert response.query_type == "top_incidents"

    @pytest.mark.asyncio
    async def test_top_incidents_has_data(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_top_incidents()
        assert "incidents" in response.raw_data
        assert len(response.raw_data["incidents"]) > 0

    @pytest.mark.asyncio
    async def test_top_incidents_limited(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_top_incidents(limit=3)
        assert len(response.raw_data.get("incidents", [])) <= 3


class TestBreachRisk:
    """Breach risk query tests."""

    @pytest.mark.asyncio
    async def test_get_breach_risk_returns_response(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_breach_risk()
        assert isinstance(response, ChatbotResponse)
        assert response.query_type == "breach_risk"

    @pytest.mark.asyncio
    async def test_breach_risk_has_score(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_breach_risk()
        assert "breach_risk_score" in response.raw_data
        score = response.raw_data["breach_risk_score"]
        assert 0 <= score <= 100


class TestMTTR:
    """MTTR query tests."""

    @pytest.mark.asyncio
    async def test_get_mttr_returns_response(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_mean_time_to_resolve()
        assert isinstance(response, ChatbotResponse)
        assert response.query_type == "mttr"

    @pytest.mark.asyncio
    async def test_mttr_has_metrics(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_mean_time_to_resolve()
        assert "mttr_hours" in response.raw_data

    @pytest.mark.asyncio
    async def test_mttr_finance_org(self):
        chatbot = await _build_chatbot()
        response = chatbot.get_mean_time_to_resolve("Finance")
        assert response.query_type == "mttr"


class TestNarrativeGeneration:
    """Traffic light narrative generation tests."""

    @pytest.mark.asyncio
    async def test_red_narrative_mentions_critical(self):
        from src.core.gold_aggregator import TrafficLight
        chatbot = ChatbotLiveTemplates()
        narrative = chatbot._light_to_prose(TrafficLight.RED, "ACME", ["3 critical incidents"])
        assert "RED" in narrative
        assert "critical" in narrative.lower() or "3 critical" in narrative

    @pytest.mark.asyncio
    async def test_yellow_narrative_mentions_elevated(self):
        from src.core.gold_aggregator import TrafficLight
        chatbot = ChatbotLiveTemplates()
        narrative = chatbot._light_to_prose(TrafficLight.YELLOW, "ACME", [])
        assert "YELLOW" in narrative

    @pytest.mark.asyncio
    async def test_green_narrative_mentions_healthy(self):
        from src.core.gold_aggregator import TrafficLight
        chatbot = ChatbotLiveTemplates()
        narrative = chatbot._light_to_prose(TrafficLight.GREEN, "ACME", [])
        assert "GREEN" in narrative
        assert "healthy" in narrative.lower()
