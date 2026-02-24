"""Silver layer transformer: Bronze JSON → normalized fact tables with PII masking.

Transforms raw records from the Bronze layer into structured fact tables,
applying PII masking, severity normalization, and surrogate key generation.
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII masking helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def mask_pii(text: str) -> str:
    """Redact PII (email, IP, SSN, credit card) from a text string.

    Args:
        text: Input text that may contain PII

    Returns:
        Text with PII replaced by redaction markers
    """
    if not isinstance(text, str):
        return text
    text = _EMAIL_RE.sub("[EMAIL REDACTED]", text)
    text = _IP_RE.sub("[IP REDACTED]", text)
    text = _SSN_RE.sub("[SSN REDACTED]", text)
    text = _CC_RE.sub("[CC REDACTED]", text)
    return text


# ---------------------------------------------------------------------------
# Severity / priority normalization
# ---------------------------------------------------------------------------

_SERVICENOW_PRIORITY_MAP = {
    "1": "CRITICAL",
    "2": "HIGH",
    "3": "MEDIUM",
    "4": "LOW",
    "5": "INFO",
}

_DEFENDER_SEVERITY_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
}

_GRAFANA_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "warning": "MEDIUM",
    "info": "INFO",
    "low": "LOW",
}


def normalize_severity(raw_severity: str, source: str) -> str:
    """Map source-specific severity to a canonical level.

    Args:
        raw_severity: Severity value from the source system
        source: Source name (servicenow, defender, grafana, usatoday)

    Returns:
        Canonical severity string: CRITICAL | HIGH | MEDIUM | LOW | INFO
    """
    mapping: Dict[str, str] = {
        "servicenow": _SERVICENOW_PRIORITY_MAP,
        "grafana": _GRAFANA_SEVERITY_MAP,
        "defender": _DEFENDER_SEVERITY_MAP,
    }
    source_map = mapping.get(source, {})
    return source_map.get(raw_severity, "MEDIUM")


# ---------------------------------------------------------------------------
# Fact table dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FactIncident:
    """Normalized incident fact record."""

    incident_id: str
    source: str
    source_ref: str
    org_name: str
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime
    resolved_at: Optional[datetime]
    raw_data_hash: str


@dataclass
class FactVulnerability:
    """Normalized vulnerability fact record."""

    vuln_id: str
    source: str
    source_ref: str
    org_name: str
    title: str
    description: str
    severity: str
    cve_id: Optional[str]
    affected_asset: str
    status: str
    detected_at: datetime
    raw_data_hash: str


@dataclass
class FactBreach:
    """Normalized breach fact record."""

    breach_id: str
    source: str
    source_ref: str
    organization: str
    industry: str
    title: str
    breach_type: str
    records_affected: int
    severity_score: float
    cve_exploited: Optional[str]
    published_at: datetime
    raw_data_hash: str


@dataclass
class TransformationMetrics:
    """Metrics for a single transformation batch."""

    source: str
    batch_id: str
    total_input: int = 0
    transformed: int = 0
    skipped_duplicates: int = 0
    failed: int = 0
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SilverTransformer
# ---------------------------------------------------------------------------


class SilverTransformer:
    """Transforms Bronze raw records into Silver fact tables.

    Supports ServiceNow incidents, Defender incidents/vulnerabilities,
    USA Today breach news, and Grafana alerts.
    """

    def __init__(self, db_session: Any = None) -> None:
        """Initialize the transformer.

        Args:
            db_session: Database session (SQLAlchemy async session or mock)
        """
        self.db = db_session
        self._incidents: List[FactIncident] = []
        self._vulnerabilities: List[FactVulnerability] = []
        self._breaches: List[FactBreach] = []
        self._seen_hashes: set = set()

    def _hash(self, payload: Dict[str, Any]) -> str:
        """Compute a hash for deduplication.

        Args:
            payload: Record payload

        Returns:
            SHA-256 hex digest
        """
        import json

        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()

    def _parse_dt(self, value: Optional[str]) -> Optional[datetime]:
        """Parse an ISO datetime string into a timezone-aware datetime.

        Args:
            value: ISO format datetime string or None

        Returns:
            Parsed datetime (UTC) or None
        """
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Source-specific transformers
    # ------------------------------------------------------------------

    def _transform_servicenow(self, record: Dict[str, Any]) -> Optional[FactIncident]:
        """Transform a ServiceNow incident into FactIncident.

        Args:
            record: Raw ServiceNow record

        Returns:
            FactIncident or None on error
        """
        h = self._hash(record)
        if h in self._seen_hashes:
            return None
        self._seen_hashes.add(h)

        title = mask_pii(record.get("short_description", ""))
        desc = mask_pii(record.get("description", ""))
        severity = normalize_severity(record.get("priority", "3"), "servicenow")

        state_map = {"1": "open", "2": "in_progress", "6": "resolved", "7": "closed"}
        status = state_map.get(record.get("state", "1"), "open")

        return FactIncident(
            incident_id=f"sn_{record.get('number', uuid4())}",
            source="servicenow",
            source_ref=str(record.get("number", "")),
            org_name=record.get("org_name", "Unknown"),
            title=title,
            description=desc,
            severity=severity,
            status=status,
            created_at=self._parse_dt(record.get("opened_at")) or datetime.now(timezone.utc),
            resolved_at=self._parse_dt(record.get("resolved_at")),
            raw_data_hash=h,
        )

    def _transform_grafana(self, record: Dict[str, Any]) -> Optional[FactIncident]:
        """Transform a Grafana alert into FactIncident.

        Args:
            record: Raw Grafana alert record

        Returns:
            FactIncident or None on error
        """
        h = self._hash(record)
        if h in self._seen_hashes:
            return None
        self._seen_hashes.add(h)

        title = mask_pii(record.get("summary", record.get("alertname", "")))
        desc = mask_pii(record.get("description", ""))
        severity = normalize_severity(record.get("severity", "warning"), "grafana")

        state_map = {"alerting": "open", "firing": "open", "resolved": "resolved", "ok": "closed"}
        status = state_map.get(record.get("state", "alerting"), "open")

        return FactIncident(
            incident_id=f"gf_{record.get('alertname', uuid4())}_{uuid4().hex[:8]}",
            source="grafana",
            source_ref=record.get("alertname", ""),
            org_name=record.get("org_name", "Unknown"),
            title=title,
            description=desc,
            severity=severity,
            status=status,
            created_at=self._parse_dt(record.get("startsAt")) or datetime.now(timezone.utc),
            resolved_at=self._parse_dt(record.get("endsAt")),
            raw_data_hash=h,
        )

    def _transform_defender(self, record: Dict[str, Any]) -> Optional[FactVulnerability]:
        """Transform a Defender incident into FactVulnerability.

        Args:
            record: Raw Defender record

        Returns:
            FactVulnerability or None on error
        """
        h = self._hash(record)
        if h in self._seen_hashes:
            return None
        self._seen_hashes.add(h)

        title = mask_pii(record.get("displayName", ""))
        desc = mask_pii(record.get("description", ""))
        severity = normalize_severity(record.get("severity", "Medium"), "defender")

        assets = record.get("impactedAssets", [])
        affected_asset = assets[0].get("id", "unknown") if assets else "unknown"

        status_map = {
            "Active": "open",
            "InProgress": "in_progress",
            "Resolved": "resolved",
        }
        status = status_map.get(record.get("status", "Active"), "open")

        return FactVulnerability(
            vuln_id=f"def_{record.get('incidentId', uuid4())}",
            source="defender",
            source_ref=str(record.get("incidentId", "")),
            org_name=record.get("org_name", "Unknown"),
            title=title,
            description=desc,
            severity=severity,
            cve_id=None,
            affected_asset=affected_asset,
            status=status,
            detected_at=self._parse_dt(record.get("createdTime")) or datetime.now(timezone.utc),
            raw_data_hash=h,
        )

    def _transform_usatoday(self, record: Dict[str, Any]) -> Optional[FactBreach]:
        """Transform a USA Today breach record into FactBreach.

        Args:
            record: Raw USA Today breach record

        Returns:
            FactBreach or None on error
        """
        h = self._hash(record)
        if h in self._seen_hashes:
            return None
        self._seen_hashes.add(h)

        title = mask_pii(record.get("title", ""))

        return FactBreach(
            breach_id=f"ut_{record.get('id', uuid4())}",
            source="usatoday",
            source_ref=str(record.get("id", "")),
            organization=record.get("organization", "Unknown"),
            industry=record.get("industry", "Unknown"),
            title=title,
            breach_type=record.get("breach_type", "Unknown"),
            records_affected=int(record.get("records_affected", 0)),
            severity_score=float(record.get("severity_score", 5.0)),
            cve_exploited=record.get("cve_exploited"),
            published_at=self._parse_dt(record.get("published_at")) or datetime.now(timezone.utc),
            raw_data_hash=h,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def transform_batch(
        self,
        source: str,
        records: List[Dict[str, Any]],
        batch_id: Optional[str] = None,
    ) -> TransformationMetrics:
        """Transform a batch of raw records into Silver fact tables.

        Args:
            source: Source name (servicenow, grafana, defender, usatoday)
            records: List of raw record dictionaries
            batch_id: Optional batch identifier

        Returns:
            TransformationMetrics with counts
        """
        batch_id = batch_id or str(uuid4())
        metrics = TransformationMetrics(
            source=source,
            batch_id=batch_id,
            total_input=len(records),
        )

        transform_map = {
            "servicenow": self._transform_servicenow,
            "grafana": self._transform_grafana,
            "defender": self._transform_defender,
            "usatoday": self._transform_usatoday,
        }

        transform_fn = transform_map.get(source)
        if transform_fn is None:
            metrics.errors.append(f"Unknown source: {source}")
            return metrics

        for record in records:
            try:
                result = transform_fn(record)
                if result is None:
                    metrics.skipped_duplicates += 1
                    continue

                # Store result in the appropriate list
                if isinstance(result, FactIncident):
                    self._incidents.append(result)
                elif isinstance(result, FactVulnerability):
                    self._vulnerabilities.append(result)
                elif isinstance(result, FactBreach):
                    self._breaches.append(result)

                metrics.transformed += 1

            except Exception as exc:
                metrics.failed += 1
                metrics.errors.append(f"Failed to transform record: {exc}")
                logger.warning("Transform error for source %s: %s", source, exc)

        logger.info(
            "Transformed batch %s from %s: %d/%d records",
            batch_id,
            source,
            metrics.transformed,
            metrics.total_input,
        )
        return metrics

    def get_incidents(self) -> List[FactIncident]:
        """Return all transformed incidents."""
        return list(self._incidents)

    def get_vulnerabilities(self) -> List[FactVulnerability]:
        """Return all transformed vulnerabilities."""
        return list(self._vulnerabilities)

    def get_breaches(self) -> List[FactBreach]:
        """Return all transformed breaches."""
        return list(self._breaches)
