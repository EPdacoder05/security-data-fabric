"""Risk scoring for assets and services."""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from src.processing.schema import NormalizedEventSchema
from src.observability import get_logger

logger = get_logger(__name__)


@dataclass
class RiskScore:
    """Risk score breakdown for an asset or service."""

    asset_id: str
    asset_type: str  # service, host, application, etc.
    total_score: float  # 0-100
    breakdown: Dict[str, float] = field(default_factory=dict)
    factors: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = ""  # low, medium, high, critical
    recommendations: List[str] = field(default_factory=list)


class RiskScorer:
    """Calculate risk scores for assets and services."""

    def __init__(self) -> None:
        """Initialize risk scorer."""
        # Asset data (in production, loaded from CMDB/database)
        self.asset_data: Dict[str, Dict[str, Any]] = {}
        self.dependency_graph: Dict[str, List[str]] = defaultdict(list)
        logger.info("Initialized risk scorer")

    def score_asset(
        self,
        asset_id: str,
        asset_type: str = "service",
        events: Optional[List[NormalizedEventSchema]] = None,
        lookback_days: int = 30,
    ) -> RiskScore:
        """Calculate risk score for an asset.

        Args:
            asset_id: Asset identifier (service name, host, etc.)
            asset_type: Type of asset
            events: Optional list of events to analyze
            lookback_days: Days of history to consider

        Returns:
            Risk score with breakdown
        """
        breakdown = {}
        factors = {}

        # Factor 1: Anomaly frequency (0-30 points)
        anomaly_score = self._score_anomaly_frequency(
            asset_id, events, lookback_days
        )
        breakdown["anomaly_frequency"] = anomaly_score
        factors["anomaly_count"] = self._count_anomalies(asset_id, events)

        # Factor 2: Incident history (0-30 points)
        incident_score = self._score_incident_history(
            asset_id, events, lookback_days
        )
        breakdown["incident_history"] = incident_score
        factors["incident_count"] = self._count_incidents(asset_id, events)

        # Factor 3: Dependency chain depth (0-20 points)
        dependency_score = self._score_dependency_depth(asset_id)
        breakdown["dependency_depth"] = dependency_score
        factors["dependency_depth"] = self._get_dependency_depth(asset_id)

        # Factor 4: Patch compliance (0-10 points) - placeholder
        patch_score = self._score_patch_compliance(asset_id)
        breakdown["patch_compliance"] = patch_score
        factors["patches_pending"] = 0  # Placeholder

        # Factor 5: Recent activity (0-10 points)
        activity_score = self._score_recent_activity(asset_id, events)
        breakdown["recent_activity"] = activity_score
        factors["recent_events"] = self._count_recent_events(asset_id, events)

        # Calculate total score
        total_score = sum(breakdown.values())
        total_score = min(total_score, 100.0)

        # Determine risk level
        risk_level = self._determine_risk_level(total_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            asset_id, breakdown, factors
        )

        risk_score = RiskScore(
            asset_id=asset_id,
            asset_type=asset_type,
            total_score=round(total_score, 2),
            breakdown=breakdown,
            factors=factors,
            risk_level=risk_level,
            recommendations=recommendations,
        )

        logger.info(
            f"Risk score calculated for {asset_id}: {total_score:.2f}",
            extra={
                "asset_id": asset_id,
                "asset_type": asset_type,
                "risk_score": total_score,
                "risk_level": risk_level,
            },
        )

        return risk_score

    def score_multiple_assets(
        self,
        asset_ids: List[str],
        asset_type: str = "service",
        events: Optional[List[NormalizedEventSchema]] = None,
    ) -> List[RiskScore]:
        """Calculate risk scores for multiple assets.

        Args:
            asset_ids: List of asset identifiers
            asset_type: Type of assets
            events: Optional list of events to analyze

        Returns:
            List of risk scores sorted by total score (descending)
        """
        scores = []
        for asset_id in asset_ids:
            score = self.score_asset(asset_id, asset_type, events)
            scores.append(score)

        # Sort by total score descending
        scores.sort(key=lambda s: s.total_score, reverse=True)

        return scores

    def _score_anomaly_frequency(
        self,
        asset_id: str,
        events: Optional[List[NormalizedEventSchema]],
        lookback_days: int,
    ) -> float:
        """Score based on anomaly frequency.

        Args:
            asset_id: Asset identifier
            events: List of events
            lookback_days: Days to look back

        Returns:
            Anomaly frequency score (0-30)
        """
        if not events:
            return 0.0

        anomaly_count = self._count_anomalies(asset_id, events)

        # Calculate rate per day
        rate = anomaly_count / lookback_days if lookback_days > 0 else 0

        # Score based on rate
        # 0 anomalies = 0 points
        # 1+ per day = 30 points (max)
        score = min(rate * 30, 30.0)

        return round(score, 2)

    def _count_anomalies(
        self, asset_id: str, events: Optional[List[NormalizedEventSchema]]
    ) -> int:
        """Count anomalies for asset.

        Args:
            asset_id: Asset identifier
            events: List of events

        Returns:
            Anomaly count
        """
        if not events:
            return 0

        count = 0
        for event in events:
            if event.event_type != "metric":
                continue

            # Check if event is related to this asset
            if not self._event_matches_asset(event, asset_id):
                continue

            # Check if it's an anomaly (z-score > 2)
            z_score = event.metadata.get("z_score", 0)
            if abs(z_score) >= 2.0:
                count += 1

        return count

    def _score_incident_history(
        self,
        asset_id: str,
        events: Optional[List[NormalizedEventSchema]],
        lookback_days: int,
    ) -> float:
        """Score based on incident history.

        Args:
            asset_id: Asset identifier
            events: List of events
            lookback_days: Days to look back

        Returns:
            Incident history score (0-30)
        """
        if not events:
            return 0.0

        incident_count = self._count_incidents(asset_id, events)

        # Weight by severity
        severity_weighted_count = 0.0
        for event in events or []:
            if event.event_type != "incident":
                continue

            if not self._event_matches_asset(event, asset_id):
                continue

            # Weight by severity: 1=1x, 2=1.5x, 3=2x, 4=2.5x, 5=3x
            weight = 1.0 + (event.severity - 1) * 0.5
            severity_weighted_count += weight

        # Calculate rate
        rate = severity_weighted_count / lookback_days if lookback_days > 0 else 0

        # Score based on rate
        # 0 incidents = 0 points
        # 0.5+ weighted incidents per day = 30 points (max)
        score = min(rate * 60, 30.0)

        return round(score, 2)

    def _count_incidents(
        self, asset_id: str, events: Optional[List[NormalizedEventSchema]]
    ) -> int:
        """Count incidents for asset.

        Args:
            asset_id: Asset identifier
            events: List of events

        Returns:
            Incident count
        """
        if not events:
            return 0

        count = 0
        for event in events:
            if event.event_type != "incident":
                continue

            if self._event_matches_asset(event, asset_id):
                count += 1

        return count

    def _score_dependency_depth(self, asset_id: str) -> float:
        """Score based on dependency chain depth.

        Args:
            asset_id: Asset identifier

        Returns:
            Dependency depth score (0-20)
        """
        depth = self._get_dependency_depth(asset_id)

        # Score based on depth
        # Depth 0 (no dependencies) = 0 points
        # Depth 1-2 = 5 points
        # Depth 3-4 = 10 points
        # Depth 5+ = 20 points (max)
        if depth == 0:
            score = 0.0
        elif depth <= 2:
            score = 5.0
        elif depth <= 4:
            score = 10.0
        else:
            score = 20.0

        return score

    def _get_dependency_depth(self, asset_id: str) -> int:
        """Get dependency chain depth for asset.

        Args:
            asset_id: Asset identifier

        Returns:
            Maximum dependency depth
        """
        if asset_id not in self.dependency_graph:
            return 0

        # BFS to find maximum depth
        visited = set()
        queue = [(asset_id, 0)]
        max_depth = 0

        while queue:
            current, depth = queue.pop(0)

            if current in visited:
                continue

            visited.add(current)
            max_depth = max(max_depth, depth)

            # Add dependencies to queue
            for dep in self.dependency_graph.get(current, []):
                if dep not in visited:
                    queue.append((dep, depth + 1))

        return max_depth

    def _score_patch_compliance(self, asset_id: str) -> float:
        """Score based on patch compliance (placeholder).

        Args:
            asset_id: Asset identifier

        Returns:
            Patch compliance score (0-10)
        """
        # Placeholder implementation
        # In production, this would check:
        # - Number of pending security patches
        # - Age of pending patches
        # - Criticality of patches

        # For now, return a default moderate score
        return 5.0

    def _score_recent_activity(
        self, asset_id: str, events: Optional[List[NormalizedEventSchema]]
    ) -> float:
        """Score based on recent activity.

        Args:
            asset_id: Asset identifier
            events: List of events

        Returns:
            Recent activity score (0-10)
        """
        if not events:
            return 0.0

        recent_count = self._count_recent_events(asset_id, events)

        # Score based on count
        # 0 events = 0 points
        # 10+ events = 10 points (max)
        score = min(recent_count, 10.0)

        return score

    def _count_recent_events(
        self, asset_id: str, events: Optional[List[NormalizedEventSchema]]
    ) -> int:
        """Count recent events (last 24 hours).

        Args:
            asset_id: Asset identifier
            events: List of events

        Returns:
            Recent event count
        """
        if not events:
            return 0

        cutoff = datetime.utcnow() - timedelta(days=1)
        count = 0

        for event in events:
            if event.timestamp < cutoff:
                continue

            if self._event_matches_asset(event, asset_id):
                count += 1

        return count

    def _event_matches_asset(
        self, event: NormalizedEventSchema, asset_id: str
    ) -> bool:
        """Check if event is related to asset.

        Args:
            event: Normalized event
            asset_id: Asset identifier

        Returns:
            True if event matches asset
        """
        # Check various metadata fields
        asset_id_lower = asset_id.lower()

        # Check service field
        if service := event.metadata.get("service"):
            if asset_id_lower in service.lower():
                return True

        # Check entity_id field
        if entity_id := event.metadata.get("entity_id"):
            if asset_id_lower in entity_id.lower():
                return True

        # Check host field
        if host := event.metadata.get("host"):
            if asset_id_lower in host.lower():
                return True

        # Check repository field
        if repo := event.metadata.get("repository"):
            if asset_id_lower in repo.lower():
                return True

        # Check affected_entity field
        if affected := event.metadata.get("affected_entity"):
            if asset_id_lower in affected.lower():
                return True

        return False

    def _determine_risk_level(self, total_score: float) -> str:
        """Determine risk level from total score.

        Args:
            total_score: Total risk score (0-100)

        Returns:
            Risk level label
        """
        if total_score >= 75:
            return "critical"
        elif total_score >= 50:
            return "high"
        elif total_score >= 25:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(
        self,
        asset_id: str,
        breakdown: Dict[str, float],
        factors: Dict[str, Any],
    ) -> List[str]:
        """Generate risk mitigation recommendations.

        Args:
            asset_id: Asset identifier
            breakdown: Risk score breakdown
            factors: Risk factors

        Returns:
            List of recommendations
        """
        recommendations = []

        # Anomaly frequency
        if breakdown.get("anomaly_frequency", 0) > 15:
            recommendations.append(
                "High anomaly frequency detected. Review monitoring thresholds "
                "and investigate performance baselines."
            )

        # Incident history
        if breakdown.get("incident_history", 0) > 15:
            recommendations.append(
                "Frequent incidents detected. Consider implementing additional "
                "monitoring, testing, or stability improvements."
            )

        # Dependency depth
        if breakdown.get("dependency_depth", 0) >= 15:
            recommendations.append(
                "Deep dependency chain detected. Review architecture to reduce "
                "coupling and improve resilience."
            )

        # Recent activity
        if breakdown.get("recent_activity", 0) > 7:
            recommendations.append(
                "High recent activity detected. Ensure adequate monitoring during "
                "this period of change."
            )

        # Default recommendations
        if not recommendations:
            recommendations.append(
                "Continue monitoring asset health and maintain current practices."
            )

        return recommendations

    def set_dependencies(
        self, asset_id: str, dependencies: List[str]
    ) -> None:
        """Set dependencies for an asset.

        Args:
            asset_id: Asset identifier
            dependencies: List of asset IDs this asset depends on
        """
        self.dependency_graph[asset_id] = dependencies
        logger.debug(
            f"Set dependencies for {asset_id}",
            extra={"asset_id": asset_id, "dependency_count": len(dependencies)},
        )

    def get_risk_summary(self, risk_score: RiskScore) -> str:
        """Get human-readable summary of risk score.

        Args:
            risk_score: Risk score result

        Returns:
            Human-readable summary
        """
        lines = []
        lines.append(f"Risk Assessment: {risk_score.asset_id}")
        lines.append(f"Risk Level: {risk_score.risk_level.upper()}")
        lines.append(f"Total Score: {risk_score.total_score:.2f}/100")
        lines.append("")

        lines.append("Score Breakdown:")
        for category, score in risk_score.breakdown.items():
            category_label = category.replace("_", " ").title()
            lines.append(f"  {category_label}: {score:.2f}")

        lines.append("")
        lines.append("Recommendations:")
        for rec in risk_score.recommendations:
            lines.append(f"  • {rec}")

        return "\n".join(lines)
