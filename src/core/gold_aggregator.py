"""Gold layer aggregation engine for the Security Data Fabric.

Computes executive KPIs, traffic light health status, incident trends,
and cross-source correlations from Silver layer fact tables.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TrafficLight(str, Enum):
    """Executive traffic light health status."""

    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


@dataclass
class IncidentTrend:
    """Weekly incident trend metrics per organization."""

    org_name: str
    week_start: datetime
    total_incidents: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    resolved_count: int
    open_count: int


@dataclass
class ExecutiveKPIs:
    """Executive KPIs for a given organization and time window."""

    org_name: str
    computed_at: datetime
    mttr_hours: float  # Mean Time To Resolve
    mttd_hours: float  # Mean Time To Detect (incident→alert)
    open_incident_count: int
    critical_vuln_count: int
    breach_risk_score: float  # 0-100
    detection_rate: float  # % incidents auto-detected
    traffic_light: TrafficLight
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class CrossSourceCorrelation:
    """Correlation between incidents, vulnerabilities, and breaches."""

    correlation_id: str
    incident_refs: List[str]
    vuln_refs: List[str]
    breach_refs: List[str]
    shared_cve: Optional[str]
    confidence_score: float  # 0.0-1.0
    description: str


@dataclass
class GoldMetrics:
    """Metrics for a Gold aggregation run."""

    computed_at: datetime
    orgs_processed: int = 0
    kpis_computed: int = 0
    correlations_found: int = 0
    errors: List[str] = field(default_factory=list)


class GoldAggregator:
    """Computes Gold layer metrics from Silver fact tables.

    Operates on in-memory Silver data (injected via transformer) without
    requiring a live database, making it schema-agnostic and fully testable.
    """

    # Thresholds for traffic light computation
    RED_CRITICAL_INCIDENTS = 3
    YELLOW_CRITICAL_INCIDENTS = 1
    RED_CRITICAL_VULNS = 5
    YELLOW_CRITICAL_VULNS = 2
    RED_BREACH_RISK = 70.0
    YELLOW_BREACH_RISK = 40.0

    def __init__(self, db_session: Any = None) -> None:
        """Initialize the aggregator.

        Args:
            db_session: Optional database session (not required for in-memory mode)
        """
        self.db = db_session
        self._kpis: Dict[str, ExecutiveKPIs] = {}
        self._trends: List[IncidentTrend] = []
        self._correlations: List[CrossSourceCorrelation] = []

    # ------------------------------------------------------------------
    # Traffic light computation
    # ------------------------------------------------------------------

    def compute_traffic_light(
        self,
        critical_incidents: int,
        critical_vulns: int,
        breach_risk: float,
    ) -> TrafficLight:
        """Determine traffic light color from KPI values.

        Args:
            critical_incidents: Count of open critical incidents
            critical_vulns: Count of unpatched critical vulnerabilities
            breach_risk: Breach risk score (0-100)

        Returns:
            TrafficLight color
        """
        if (
            critical_incidents >= self.RED_CRITICAL_INCIDENTS
            or critical_vulns >= self.RED_CRITICAL_VULNS
            or breach_risk >= self.RED_BREACH_RISK
        ):
            return TrafficLight.RED

        if (
            critical_incidents >= self.YELLOW_CRITICAL_INCIDENTS
            or critical_vulns >= self.YELLOW_CRITICAL_VULNS
            or breach_risk >= self.YELLOW_BREACH_RISK
        ):
            return TrafficLight.YELLOW

        return TrafficLight.GREEN

    # ------------------------------------------------------------------
    # KPI computation
    # ------------------------------------------------------------------

    def compute_kpis(
        self,
        org_name: str,
        incidents: list,
        vulnerabilities: list,
        breaches: list,
    ) -> ExecutiveKPIs:
        """Compute executive KPIs for an organization.

        Args:
            org_name: Organization name
            incidents: List of FactIncident objects for this org
            vulnerabilities: List of FactVulnerability objects for this org
            breaches: List of FactBreach objects for this org

        Returns:
            ExecutiveKPIs with computed values
        """
        now = datetime.now(timezone.utc)

        # MTTR - average hours from created_at to resolved_at
        resolved = [
            i for i in incidents
            if getattr(i, "resolved_at", None) is not None
        ]
        if resolved:
            durations = []
            for inc in resolved:
                delta = inc.resolved_at - inc.created_at
                durations.append(delta.total_seconds() / 3600)
            mttr_hours = sum(durations) / len(durations)
        else:
            mttr_hours = 0.0

        # MTTD - approximated as 30 min default if no separate detection time
        mttd_hours = 0.5 if incidents else 0.0

        # Open incident count
        open_incidents = [
            i for i in incidents
            if getattr(i, "status", "") not in ("resolved", "closed")
        ]
        open_count = len(open_incidents)

        # Critical open incidents
        critical_open = [
            i for i in open_incidents
            if getattr(i, "severity", "") == "CRITICAL"
        ]
        critical_incident_count = len(critical_open)

        # Critical vulns
        critical_vulns = [
            v for v in vulnerabilities
            if getattr(v, "severity", "") == "CRITICAL"
            and getattr(v, "status", "") not in ("resolved", "closed")
        ]
        critical_vuln_count = len(critical_vulns)

        # Breach risk score (0-100)
        # Base: (critical incidents × 15) + (critical vulns × 10) + breach context
        breach_risk = min(
            100.0,
            critical_incident_count * 15.0
            + critical_vuln_count * 10.0
            + len(breaches) * 5.0,
        )

        # Detection rate (auto-detected vs manually found)
        # Simplified: grafana/defender = auto, servicenow = manual
        if incidents:
            auto_detected = sum(
                1 for i in incidents
                if getattr(i, "source", "") in ("grafana", "defender")
            )
            detection_rate = auto_detected / len(incidents)
        else:
            detection_rate = 1.0

        # Traffic light
        light = self.compute_traffic_light(
            critical_incident_count, critical_vuln_count, breach_risk
        )

        risk_factors = []
        if critical_incident_count >= self.RED_CRITICAL_INCIDENTS:
            risk_factors.append(f"{critical_incident_count} critical open incidents")
        if critical_vuln_count >= self.RED_CRITICAL_VULNS:
            risk_factors.append(f"{critical_vuln_count} unpatched critical vulnerabilities")
        if breach_risk >= self.YELLOW_BREACH_RISK:
            risk_factors.append(f"Breach risk score: {breach_risk:.0f}/100")

        kpis = ExecutiveKPIs(
            org_name=org_name,
            computed_at=now,
            mttr_hours=round(mttr_hours, 2),
            mttd_hours=round(mttd_hours, 2),
            open_incident_count=open_count,
            critical_vuln_count=critical_vuln_count,
            breach_risk_score=round(breach_risk, 1),
            detection_rate=round(detection_rate, 3),
            traffic_light=light,
            risk_factors=risk_factors,
        )
        self._kpis[org_name] = kpis
        return kpis

    # ------------------------------------------------------------------
    # Incident trend analysis
    # ------------------------------------------------------------------

    def compute_incident_trends(
        self, incidents: list, weeks: int = 4
    ) -> List[IncidentTrend]:
        """Compute weekly incident trends per organization.

        Args:
            incidents: All FactIncident objects
            weeks: Number of weeks to analyze

        Returns:
            List of IncidentTrend records
        """
        now = datetime.now(timezone.utc)
        trends: List[IncidentTrend] = []

        # Group by org
        orgs: Dict[str, list] = {}
        for inc in incidents:
            org = getattr(inc, "org_name", "Unknown")
            orgs.setdefault(org, []).append(inc)

        for org_name, org_incidents in orgs.items():
            for week_offset in range(weeks):
                week_end = now - timedelta(weeks=week_offset)
                week_start = week_end - timedelta(weeks=1)

                week_incs = [
                    i for i in org_incidents
                    if week_start <= getattr(i, "created_at", now) <= week_end
                ]

                severities = [getattr(i, "severity", "MEDIUM") for i in week_incs]
                statuses = [getattr(i, "status", "open") for i in week_incs]

                trend = IncidentTrend(
                    org_name=org_name,
                    week_start=week_start,
                    total_incidents=len(week_incs),
                    critical_count=severities.count("CRITICAL"),
                    high_count=severities.count("HIGH"),
                    medium_count=severities.count("MEDIUM"),
                    low_count=severities.count("LOW"),
                    resolved_count=sum(1 for s in statuses if s in ("resolved", "closed")),
                    open_count=sum(1 for s in statuses if s not in ("resolved", "closed")),
                )
                trends.append(trend)

        self._trends = trends
        return trends

    # ------------------------------------------------------------------
    # Cross-source correlation
    # ------------------------------------------------------------------

    def find_correlations(
        self,
        incidents: list,
        vulnerabilities: list,
        breaches: list,
    ) -> List[CrossSourceCorrelation]:
        """Identify cross-source correlations (vuln→incident→breach patterns).

        Args:
            incidents: FactIncident records
            vulnerabilities: FactVulnerability records
            breaches: FactBreach records

        Returns:
            List of CrossSourceCorrelation records
        """
        correlations: List[CrossSourceCorrelation] = []

        # Find shared CVEs across vulns and breaches
        cve_to_vulns: Dict[str, list] = {}
        for v in vulnerabilities:
            cve = getattr(v, "cve_id", None)
            if cve:
                cve_to_vulns.setdefault(cve, []).append(v)

        cve_to_breaches: Dict[str, list] = {}
        for b in breaches:
            cve = getattr(b, "cve_exploited", None)
            if cve:
                cve_to_breaches.setdefault(cve, []).append(b)

        shared_cves = set(cve_to_vulns.keys()) & set(cve_to_breaches.keys())

        for cve in shared_cves:
            vuln_refs = [getattr(v, "vuln_id", "") for v in cve_to_vulns[cve]]
            breach_refs = [getattr(b, "breach_id", "") for b in cve_to_breaches[cve]]

            # Find related incidents by keyword match
            inc_refs = [
                getattr(i, "incident_id", "")
                for i in incidents
                if cve.lower() in getattr(i, "description", "").lower()
                or cve.lower() in getattr(i, "title", "").lower()
            ]

            corr = CrossSourceCorrelation(
                correlation_id=f"corr_{cve.lower().replace('-', '_')}",
                incident_refs=inc_refs,
                vuln_refs=vuln_refs,
                breach_refs=breach_refs,
                shared_cve=cve,
                confidence_score=0.85,
                description=(
                    f"CVE {cve} appears in {len(vuln_refs)} vulnerability record(s) "
                    f"and {len(breach_refs)} breach report(s)"
                ),
            )
            correlations.append(corr)

        self._correlations = correlations
        return correlations

    # ------------------------------------------------------------------
    # Aggregate run
    # ------------------------------------------------------------------

    def aggregate_all(
        self,
        incidents: list,
        vulnerabilities: list,
        breaches: list,
    ) -> GoldMetrics:
        """Run all Gold aggregations over provided Silver data.

        Args:
            incidents: All FactIncident records
            vulnerabilities: All FactVulnerability records
            breaches: All FactBreach records

        Returns:
            GoldMetrics summary
        """
        metrics = GoldMetrics(computed_at=datetime.now(timezone.utc))

        # Group by org and compute per-org KPIs
        orgs: Dict[str, Dict[str, list]] = {}
        for inc in incidents:
            org = getattr(inc, "org_name", "Unknown")
            orgs.setdefault(org, {"incidents": [], "vulnerabilities": [], "breaches": []})
            orgs[org]["incidents"].append(inc)

        for vuln in vulnerabilities:
            org = getattr(vuln, "org_name", "Unknown")
            orgs.setdefault(org, {"incidents": [], "vulnerabilities": [], "breaches": []})
            orgs[org]["vulnerabilities"].append(vuln)

        for breach in breaches:
            orgs.setdefault("External", {"incidents": [], "vulnerabilities": [], "breaches": []})
            orgs["External"]["breaches"].append(breach)

        metrics.orgs_processed = len(orgs)

        for org_name, data in orgs.items():
            try:
                self.compute_kpis(
                    org_name=org_name,
                    incidents=data["incidents"],
                    vulnerabilities=data["vulnerabilities"],
                    breaches=data["breaches"],
                )
                metrics.kpis_computed += 1
            except Exception as exc:
                metrics.errors.append(f"KPI error for {org_name}: {exc}")

        # Trends and correlations
        self.compute_incident_trends(incidents)
        correlations = self.find_correlations(incidents, vulnerabilities, breaches)
        metrics.correlations_found = len(correlations)

        logger.info(
            "Gold aggregation complete: %d orgs, %d KPIs, %d correlations",
            metrics.orgs_processed,
            metrics.kpis_computed,
            metrics.correlations_found,
        )
        return metrics

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_kpis(self, org_name: Optional[str] = None) -> Dict[str, ExecutiveKPIs]:
        """Return computed KPIs, optionally filtered by org.

        Args:
            org_name: Optional organization filter

        Returns:
            Dictionary of org_name → ExecutiveKPIs
        """
        if org_name:
            return {k: v for k, v in self._kpis.items() if k == org_name}
        return dict(self._kpis)

    def get_trends(self) -> List[IncidentTrend]:
        """Return computed incident trends."""
        return list(self._trends)

    def get_correlations(self) -> List[CrossSourceCorrelation]:
        """Return discovered cross-source correlations."""
        return list(self._correlations)
