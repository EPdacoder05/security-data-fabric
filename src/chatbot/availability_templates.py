"""Chatbot live data templates for the Security Data Fabric.

Binds live Gold layer KPIs to chatbot responses, generating natural-language
security posture narratives from pre-computed metrics.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.gold_aggregator import GoldAggregator, TrafficLight

logger = logging.getLogger(__name__)


@dataclass
class ChatbotResponse:
    """A structured chatbot response with narrative and raw data."""

    query_type: str
    org_name: Optional[str]
    narrative: str
    traffic_light: Optional[str]
    raw_data: Dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ChatbotLiveTemplates:
    """Generates live chatbot responses from Gold layer KPIs.

    Queries the GoldAggregator for current metrics and renders natural-language
    narratives suitable for director-level reporting.
    """

    def __init__(
        self,
        db_session: Any = None,
        aggregator: Optional[GoldAggregator] = None,
    ) -> None:
        """Initialize the chatbot template engine.

        Args:
            db_session: Database session (optional, for future persistence)
            aggregator: Pre-configured GoldAggregator with Silver data loaded
        """
        self.db = db_session
        self._aggregator = aggregator or GoldAggregator(db_session)
        self._incidents: list = []
        self._vulnerabilities: list = []
        self._breaches: list = []

    def load_data(
        self,
        incidents: list,
        vulnerabilities: list,
        breaches: list,
    ) -> None:
        """Load Silver layer data for querying.

        Args:
            incidents: List of FactIncident records
            vulnerabilities: List of FactVulnerability records
            breaches: List of FactBreach records
        """
        self._incidents = incidents
        self._vulnerabilities = vulnerabilities
        self._breaches = breaches
        # Trigger Gold aggregation
        self._aggregator.aggregate_all(incidents, vulnerabilities, breaches)

    # ------------------------------------------------------------------
    # Traffic light narrative
    # ------------------------------------------------------------------

    def _light_to_prose(self, light: TrafficLight, org_name: str, risk_factors: List[str]) -> str:
        """Convert a traffic light status into a narrative sentence.

        Args:
            light: TrafficLight color
            org_name: Organization name
            risk_factors: List of risk factors driving the status

        Returns:
            Narrative string
        """
        factor_text = "; ".join(risk_factors) if risk_factors else "No critical issues detected"
        if light == TrafficLight.RED:
            return (
                f"{org_name} security posture is RED (critical). "
                f"Immediate action required. Key risks: {factor_text}."
            )
        if light == TrafficLight.YELLOW:
            return (
                f"{org_name} security posture is YELLOW (elevated). "
                f"Monitor closely. Risk factors: {factor_text}."
            )
        return (
            f"{org_name} security posture is GREEN (healthy). "
            f"All metrics within acceptable thresholds."
        )

    # ------------------------------------------------------------------
    # Core query methods
    # ------------------------------------------------------------------

    def get_security_posture(self, org_name: Optional[str] = None) -> ChatbotResponse:
        """Return a security posture summary for an organization.

        Args:
            org_name: Organization name, or None for overall posture

        Returns:
            ChatbotResponse with narrative and traffic light
        """
        kpis = self._aggregator.get_kpis(org_name)

        if not kpis:
            target = org_name or "the organization"
            return ChatbotResponse(
                query_type="security_posture",
                org_name=org_name,
                narrative=f"No security data available for {target}.",
                traffic_light=None,
                raw_data={},
            )

        # Use first org if no specific org requested
        if org_name and org_name in kpis:
            kpi = kpis[org_name]
        else:
            kpi = next(iter(kpis.values()))

        narrative = self._light_to_prose(kpi.traffic_light, kpi.org_name, kpi.risk_factors)
        narrative += (
            f" Open incidents: {kpi.open_incident_count}. "
            f"Critical vulns: {kpi.critical_vuln_count}. "
            f"Breach risk: {kpi.breach_risk_score:.0f}%. "
            f"MTTR: {kpi.mttr_hours:.1f}h."
        )

        return ChatbotResponse(
            query_type="security_posture",
            org_name=kpi.org_name,
            narrative=narrative,
            traffic_light=kpi.traffic_light.value,
            raw_data={
                "open_incident_count": kpi.open_incident_count,
                "critical_vuln_count": kpi.critical_vuln_count,
                "breach_risk_score": kpi.breach_risk_score,
                "mttr_hours": kpi.mttr_hours,
                "detection_rate": kpi.detection_rate,
                "risk_factors": kpi.risk_factors,
            },
        )

    def get_top_incidents(
        self,
        org_name: Optional[str] = None,
        limit: int = 5,
    ) -> ChatbotResponse:
        """Return the top open incidents sorted by severity.

        Args:
            org_name: Optional organization filter
            limit: Maximum number of incidents to return

        Returns:
            ChatbotResponse with incident summary
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        incidents = [
            i
            for i in self._incidents
            if (
                (org_name is None or getattr(i, "org_name", "") == org_name)
                and getattr(i, "status", "") not in ("resolved", "closed")
            )
        ]
        incidents.sort(key=lambda x: severity_order.get(getattr(x, "severity", "MEDIUM"), 2))
        top = incidents[:limit]

        if not top:
            target = f" for {org_name}" if org_name else ""
            return ChatbotResponse(
                query_type="top_incidents",
                org_name=org_name,
                narrative=f"No open incidents found{target}.",
                traffic_light=None,
                raw_data={"incidents": []},
            )

        incident_list = [
            {
                "id": getattr(i, "incident_id", ""),
                "title": getattr(i, "title", ""),
                "severity": getattr(i, "severity", ""),
                "status": getattr(i, "status", ""),
            }
            for i in top
        ]

        target_text = f" for {org_name}" if org_name else ""
        narrative = f"Top {len(top)} open incident(s){target_text}: " + "; ".join(
            f"[{i['severity']}] {i['title'][:60]}" for i in incident_list
        )

        return ChatbotResponse(
            query_type="top_incidents",
            org_name=org_name,
            narrative=narrative,
            traffic_light=None,
            raw_data={"incidents": incident_list},
        )

    def get_breach_risk(self, org_name: Optional[str] = None) -> ChatbotResponse:
        """Return breach risk analysis for an organization.

        Args:
            org_name: Optional organization filter

        Returns:
            ChatbotResponse with breach risk narrative
        """
        kpis = self._aggregator.get_kpis(org_name)

        if not kpis:
            target = org_name or "the organization"
            return ChatbotResponse(
                query_type="breach_risk",
                org_name=org_name,
                narrative=f"No risk data available for {target}.",
                traffic_light=None,
                raw_data={},
            )

        if org_name and org_name in kpis:
            kpi = kpis[org_name]
        else:
            kpi = next(iter(kpis.values()))

        risk = kpi.breach_risk_score
        if risk >= 70:
            level = "HIGH"
            action = "Immediate remediation required."
        elif risk >= 40:
            level = "ELEVATED"
            action = "Prioritize patching and incident response."
        else:
            level = "LOW"
            action = "Continue standard monitoring."

        correlations = self._aggregator.get_correlations()
        corr_text = ""
        if correlations:
            cves = [c.shared_cve for c in correlations if c.shared_cve]
            if cves:
                corr_text = f" Active CVE correlations: {', '.join(cves[:3])}."

        narrative = f"Breach risk for {kpi.org_name}: {risk:.0f}/100 ({level}). {action}{corr_text}"

        return ChatbotResponse(
            query_type="breach_risk",
            org_name=kpi.org_name,
            narrative=narrative,
            traffic_light=kpi.traffic_light.value,
            raw_data={
                "breach_risk_score": risk,
                "risk_level": level,
                "correlations": [
                    {"cve": c.shared_cve, "confidence": c.confidence_score} for c in correlations
                ],
            },
        )

    def get_mean_time_to_resolve(self, org_name: Optional[str] = None) -> ChatbotResponse:
        """Return MTTR metrics for an organization.

        Args:
            org_name: Optional organization filter

        Returns:
            ChatbotResponse with MTTR narrative
        """
        kpis = self._aggregator.get_kpis(org_name)

        if not kpis:
            target = org_name or "the organization"
            return ChatbotResponse(
                query_type="mttr",
                org_name=org_name,
                narrative=f"No MTTR data available for {target}.",
                traffic_light=None,
                raw_data={},
            )

        if org_name and org_name in kpis:
            kpi = kpis[org_name]
        else:
            kpi = next(iter(kpis.values()))

        mttr = kpi.mttr_hours
        if mttr == 0:
            narrative = (
                f"MTTR for {kpi.org_name}: No resolved incidents in dataset. "
                f"MTTD: {kpi.mttd_hours:.1f}h."
            )
        elif mttr <= 4:
            assessment = "excellent"
        elif mttr <= 24:
            assessment = "acceptable"
        else:
            assessment = "needs improvement"

        if mttr > 0:
            narrative = (
                f"MTTR for {kpi.org_name}: {mttr:.1f}h ({assessment}). "
                f"MTTD: {kpi.mttd_hours:.1f}h. "
                f"Detection rate: {kpi.detection_rate * 100:.0f}%."
            )

        return ChatbotResponse(
            query_type="mttr",
            org_name=kpi.org_name,
            narrative=narrative,
            traffic_light=kpi.traffic_light.value,
            raw_data={
                "mttr_hours": mttr,
                "mttd_hours": kpi.mttd_hours,
                "detection_rate": kpi.detection_rate,
            },
        )

    def get_vulnerability_summary(self, org_name: Optional[str] = None) -> ChatbotResponse:
        """Return vulnerability summary for an organization.

        Args:
            org_name: Optional organization filter

        Returns:
            ChatbotResponse with vulnerability narrative
        """
        vulns = [
            v
            for v in self._vulnerabilities
            if (org_name is None or getattr(v, "org_name", "") == org_name)
            and getattr(v, "status", "") not in ("resolved", "closed")
        ]

        if not vulns:
            target = f" for {org_name}" if org_name else ""
            return ChatbotResponse(
                query_type="vulnerability_summary",
                org_name=org_name,
                narrative=f"No open vulnerabilities found{target}.",
                traffic_light=None,
                raw_data={"vulnerabilities": []},
            )

        severity_counts: Dict[str, int] = {}
        for v in vulns:
            sev = getattr(v, "severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        parts = [f"{count} {sev}" for sev, count in sorted(severity_counts.items())]
        target_text = f" for {org_name}" if org_name else ""
        narrative = (
            f"Vulnerability summary{target_text}: {len(vulns)} open. " + ", ".join(parts) + "."
        )

        return ChatbotResponse(
            query_type="vulnerability_summary",
            org_name=org_name,
            narrative=narrative,
            traffic_light=None,
            raw_data={
                "total_open": len(vulns),
                "by_severity": severity_counts,
            },
        )
