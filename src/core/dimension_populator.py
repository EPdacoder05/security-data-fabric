"""Dimension auto-population for the Silver layer.

Auto-populates DimOrganization and DimTime dimension tables from
Silver fact data, enabling surrogate key lookups in Gold queries.
"""

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DimOrganization:
    """Organization dimension record."""

    org_id: int
    org_name: str
    org_code: str
    industry: str = "Unknown"
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DimTime:
    """Time dimension record (one row per calendar date)."""

    date_id: int  # YYYYMMDD integer key
    full_date: date
    year: int
    quarter: int
    month: int
    month_name: str
    week_of_year: int
    day_of_month: int
    day_of_week: int
    day_name: str
    is_weekend: bool


class DimensionPopulator:
    """Manages dimension tables for the Security Data Fabric.

    Maintains in-memory DimOrganization and DimTime stores and provides
    surrogate key lookups for the transformer and aggregator.
    """

    _MONTH_NAMES = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ]
    _DAY_NAMES = [
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
    ]

    def __init__(self) -> None:
        """Initialize dimension stores."""
        self._organizations: Dict[str, DimOrganization] = {}
        self._org_id_counter: int = 1
        self._time_dim: Dict[int, DimTime] = {}
        self._seen_org_names: Set[str] = set()

    # ------------------------------------------------------------------
    # DimOrganization
    # ------------------------------------------------------------------

    def get_or_create_org(
        self, org_name: str, industry: str = "Unknown"
    ) -> DimOrganization:
        """Return existing org dimension row or create a new one.

        Args:
            org_name: Display name of the organization
            industry: Industry classification

        Returns:
            DimOrganization record
        """
        key = org_name.strip().lower()
        if key not in self._organizations:
            code = org_name.upper().replace(" ", "_")[:10]
            self._organizations[key] = DimOrganization(
                org_id=self._org_id_counter,
                org_name=org_name,
                org_code=code,
                industry=industry,
            )
            self._org_id_counter += 1
            logger.debug(
                "Created org dimension: %s (id=%d)",
                org_name,
                self._organizations[key].org_id,
            )
        return self._organizations[key]

    def get_org_id(self, org_name: str) -> Optional[int]:
        """Return the surrogate org_id for an organization name.

        Args:
            org_name: Organization display name

        Returns:
            Integer org_id or None if not found
        """
        key = org_name.strip().lower()
        dim = self._organizations.get(key)
        return dim.org_id if dim else None

    def list_organizations(self) -> List[DimOrganization]:
        """Return all organization dimension records."""
        return list(self._organizations.values())

    # ------------------------------------------------------------------
    # DimTime
    # ------------------------------------------------------------------

    def get_or_create_date(self, dt: datetime) -> DimTime:
        """Return or create a DimTime row for the given datetime.

        Args:
            dt: Datetime to create a dimension row for

        Returns:
            DimTime record
        """
        d = dt.date() if isinstance(dt, datetime) else dt
        date_id = int(d.strftime("%Y%m%d"))

        if date_id not in self._time_dim:
            self._time_dim[date_id] = DimTime(
                date_id=date_id,
                full_date=d,
                year=d.year,
                quarter=(d.month - 1) // 3 + 1,
                month=d.month,
                month_name=self._MONTH_NAMES[d.month - 1],
                week_of_year=d.isocalendar()[1],
                day_of_month=d.day,
                day_of_week=d.weekday(),
                day_name=self._DAY_NAMES[d.weekday()],
                is_weekend=d.weekday() >= 5,
            )
        return self._time_dim[date_id]

    def get_date_id(self, dt: datetime) -> int:
        """Return the integer date_id (YYYYMMDD) for a datetime.

        Args:
            dt: Datetime to get date_id for

        Returns:
            Integer date_id
        """
        dim = self.get_or_create_date(dt)
        return dim.date_id

    def populate_from_incidents(self, incidents: list) -> None:
        """Auto-populate dimensions from a list of FactIncident objects.

        Args:
            incidents: List of FactIncident records
        """
        for inc in incidents:
            self.get_or_create_org(getattr(inc, "org_name", "Unknown"))
            created = getattr(inc, "created_at", None)
            if created:
                self.get_or_create_date(created)

    def populate_from_vulnerabilities(self, vulns: list) -> None:
        """Auto-populate dimensions from a list of FactVulnerability objects.

        Args:
            vulns: List of FactVulnerability records
        """
        for v in vulns:
            self.get_or_create_org(getattr(v, "org_name", "Unknown"))
            detected = getattr(v, "detected_at", None)
            if detected:
                self.get_or_create_date(detected)

    def populate_from_breaches(self, breaches: list) -> None:
        """Auto-populate dimensions from a list of FactBreach objects.

        Args:
            breaches: List of FactBreach records
        """
        for b in breaches:
            published = getattr(b, "published_at", None)
            if published:
                self.get_or_create_date(published)

    def get_stats(self) -> Dict[str, int]:
        """Return dimension population statistics.

        Returns:
            Dictionary with counts of dimension rows
        """
        return {
            "organizations": len(self._organizations),
            "time_entries": len(self._time_dim),
        }
