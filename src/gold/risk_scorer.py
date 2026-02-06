"""
Risk scoring engine.
Composite risk scoring for incidents using CVSS-inspired methodology.
"""
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
import logging
from uuid import UUID

from sqlalchemy import select, and_, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import NormalizedEvent, Incident, EventSeverity, EventState
from src.silver.unified_schema import EventType
from src.config.settings import settings

logger = logging.getLogger(__name__)


class Priority(str, Enum):
    """Incident priority levels."""
    P1 = "P1"  # Critical - Immediate action required
    P2 = "P2"  # High - Action required within hours
    P3 = "P3"  # Medium - Action required within days
    P4 = "P4"  # Low - Action required within weeks
    P5 = "P5"  # Informational - No urgent action


class RiskTrend(str, Enum):
    """Risk trend direction."""
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"


@dataclass
class RiskFactors:
    """Individual risk factor scores."""
    severity_score: float = 0.0
    blast_radius_score: float = 0.0
    sla_impact_score: float = 0.0
    frequency_score: float = 0.0
    mttr_score: float = 0.0
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary."""
        return {
            "severity": self.severity_score,
            "blast_radius": self.blast_radius_score,
            "sla_impact": self.sla_impact_score,
            "frequency": self.frequency_score,
            "mttr": self.mttr_score,
        }


@dataclass
class RiskScore:
    """Complete risk score for an incident."""
    incident_id: UUID
    total_score: float  # 0-100
    priority: Priority
    risk_factors: RiskFactors
    trend: RiskTrend = RiskTrend.STABLE
    recommendation: str = ""
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": str(self.incident_id),
            "total_score": self.total_score,
            "priority": self.priority,
            "risk_factors": self.risk_factors.to_dict(),
            "trend": self.trend,
            "recommendation": self.recommendation,
            "calculated_at": self.calculated_at.isoformat(),
        }


@dataclass
class RiskWeights:
    """Configurable weights for risk factors."""
    severity: float = 0.30
    blast_radius: float = 0.25
    sla_impact: float = 0.20
    frequency: float = 0.15
    mttr: float = 0.10
    
    def __post_init__(self):
        """Validate weights sum to 1.0."""
        total = (
            self.severity + self.blast_radius + self.sla_impact +
            self.frequency + self.mttr
        )
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Weights must sum to 1.0, got {total}")
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary."""
        return {
            "severity": self.severity,
            "blast_radius": self.blast_radius,
            "sla_impact": self.sla_impact,
            "frequency": self.frequency,
            "mttr": self.mttr,
        }


class RiskScorer:
    """
    Risk scoring engine using composite methodology.
    Calculates risk scores on 0-100 scale using multiple factors.
    """
    
    def __init__(self, session: AsyncSession, weights: Optional[RiskWeights] = None):
        self.session = session
        self.weights = weights or RiskWeights()
        
        # Severity to numeric mapping
        self.severity_map = {
            EventSeverity.INFO: 0.25,
            EventSeverity.WARNING: 0.50,
            EventSeverity.CRITICAL: 0.75,
            EventSeverity.EXTREME: 1.00,
        }
        
        # MTTR thresholds (minutes)
        self.mttr_thresholds = {
            "excellent": 15,   # < 15 min
            "good": 60,        # < 1 hour
            "acceptable": 240, # < 4 hours
            "poor": 720,       # < 12 hours
            "critical": float('inf'),
        }
    
    async def calculate_risk_score(
        self,
        incident_id: UUID,
        include_trend: bool = True
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for an incident.
        
        Args:
            incident_id: Incident ID
            include_trend: Calculate risk trend
        
        Returns:
            Complete risk score
        """
        # Fetch incident
        incident = await self._fetch_incident(incident_id)
        if not incident:
            logger.warning(f"Incident not found: {incident_id}")
            raise ValueError(f"Incident {incident_id} not found")
        
        # Calculate individual factors
        factors = RiskFactors()
        
        factors.severity_score = self._calculate_severity_score(incident)
        factors.blast_radius_score = await self._calculate_blast_radius_score(incident)
        factors.sla_impact_score = self._calculate_sla_impact_score(incident)
        factors.frequency_score = await self._calculate_frequency_score(incident)
        factors.mttr_score = await self._calculate_mttr_score(incident)
        
        # Calculate weighted total (0-100 scale)
        total_score = round(
            (factors.severity_score * self.weights.severity +
             factors.blast_radius_score * self.weights.blast_radius +
             factors.sla_impact_score * self.weights.sla_impact +
             factors.frequency_score * self.weights.frequency +
             factors.mttr_score * self.weights.mttr) * 100,
            1
        )
        
        # Determine priority
        priority = self._score_to_priority(total_score, incident.severity)
        
        # Calculate trend if requested
        trend = RiskTrend.STABLE
        if include_trend:
            trend = await self._calculate_risk_trend(incident)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            total_score,
            priority,
            factors,
            incident
        )
        
        risk_score = RiskScore(
            incident_id=incident_id,
            total_score=total_score,
            priority=priority,
            risk_factors=factors,
            trend=trend,
            recommendation=recommendation,
        )
        
        logger.info(
            f"Calculated risk score for incident {incident_id}: "
            f"{total_score}/100 ({priority})"
        )
        
        return risk_score
    
    async def calculate_service_risk(
        self,
        service_name: str,
        lookback_days: int = 30
    ) -> Dict[str, Any]:
        """
        Calculate aggregate risk score for a service.
        
        Args:
            service_name: Service name
            lookback_days: Days to analyze
        
        Returns:
            Service risk metrics
        """
        start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        
        # Get incidents for service
        result = await self.session.execute(
            select(Incident)
            .where(
                and_(
                    Incident.service_name == service_name,
                    Incident.detected_at >= start_time
                )
            )
            .order_by(desc(Incident.detected_at))
        )
        incidents = list(result.scalars().all())
        
        if not incidents:
            return {
                "service_name": service_name,
                "incident_count": 0,
                "avg_risk_score": 0,
                "max_risk_score": 0,
                "priority_distribution": {},
                "trend": RiskTrend.STABLE,
            }
        
        # Calculate scores for all incidents
        scores = []
        priority_counts = {p: 0 for p in Priority}
        
        for incident in incidents[:20]:  # Limit to recent 20
            try:
                score = await self.calculate_risk_score(
                    incident.id,
                    include_trend=False
                )
                scores.append(score.total_score)
                priority_counts[score.priority] += 1
            except Exception as e:
                logger.error(f"Error calculating score for {incident.id}: {e}")
        
        # Calculate aggregate metrics
        avg_score = sum(scores) / len(scores) if scores else 0
        max_score = max(scores) if scores else 0
        
        # Determine overall trend
        trend = self._calculate_score_trend(scores)
        
        return {
            "service_name": service_name,
            "incident_count": len(incidents),
            "avg_risk_score": round(avg_score, 1),
            "max_risk_score": round(max_score, 1),
            "priority_distribution": {
                k.value: v for k, v in priority_counts.items() if v > 0
            },
            "trend": trend,
            "recent_incidents": len(incidents),
        }
    
    def _calculate_severity_score(self, incident: Incident) -> float:
        """
        Calculate severity factor (0.0-1.0).
        Based on incident severity level.
        """
        severity_value = self.severity_map.get(incident.severity, 0.5)
        
        # Enhance if SLA breached
        if incident.sla_breached:
            severity_value = min(1.0, severity_value + 0.15)
        
        return round(severity_value, 2)
    
    async def _calculate_blast_radius_score(self, incident: Incident) -> float:
        """
        Calculate blast radius factor (0.0-1.0).
        Based on number of affected users, services, and entities.
        """
        score = 0.0
        
        # Factor 1: Affected users
        if incident.affected_users:
            # Logarithmic scale: 1000 users = 0.5, 10000 = 0.7, 100000 = 0.9
            user_score = min(1.0, (incident.affected_users / 10000) ** 0.5)
            score += user_score * 0.5
        else:
            score += 0.3  # Default moderate impact
        
        # Factor 2: Number of affected services
        # Count correlated events from different services
        result = await self.session.execute(
            select(func.count(func.distinct(NormalizedEvent.service_name)))
            .where(
                and_(
                    NormalizedEvent.service_name.isnot(None),
                    NormalizedEvent.timestamp >= incident.detected_at - timedelta(
                        minutes=settings.correlation_time_window_minutes
                    ),
                    NormalizedEvent.timestamp <= incident.detected_at + timedelta(
                        minutes=settings.correlation_time_window_minutes
                    )
                )
            )
        )
        service_count = result.scalar() or 1
        
        # More services = higher blast radius
        service_score = min(1.0, service_count / 5)
        score += service_score * 0.5
        
        return round(min(1.0, score), 2)
    
    def _calculate_sla_impact_score(self, incident: Incident) -> float:
        """
        Calculate SLA impact factor (0.0-1.0).
        Based on SLA breach and incident duration.
        """
        score = 0.0
        
        # Factor 1: SLA breach
        if incident.sla_breached:
            score += 0.6
        
        # Factor 2: Incident duration (if resolved)
        if incident.resolved_at and incident.detected_at:
            duration_minutes = (
                incident.resolved_at - incident.detected_at
            ).total_seconds() / 60
            
            # Longer incidents = higher SLA impact
            # 15 min = 0.2, 1 hour = 0.4, 4 hours = 0.7, 12+ hours = 1.0
            duration_score = min(1.0, (duration_minutes / 360) ** 0.7)
            score += duration_score * 0.4
        elif incident.state == EventState.OPEN:
            # Still open = high impact
            score += 0.4
        
        return round(min(1.0, score), 2)
    
    async def _calculate_frequency_score(self, incident: Incident) -> float:
        """
        Calculate frequency factor (0.0-1.0).
        Based on how often similar incidents occur.
        """
        if not incident.service_name:
            return 0.3  # Default moderate frequency
        
        # Look for similar incidents in last 30 days
        lookback = datetime.now(timezone.utc) - timedelta(days=30)
        
        result = await self.session.execute(
            select(func.count(Incident.id))
            .where(
                and_(
                    Incident.service_name == incident.service_name,
                    Incident.severity == incident.severity,
                    Incident.detected_at >= lookback,
                    Incident.id != incident.id
                )
            )
        )
        similar_count = result.scalar() or 0
        
        # More frequent = higher score
        # 0 = 0.1, 1-2 = 0.3, 3-5 = 0.5, 6-10 = 0.7, 10+ = 0.9
        if similar_count == 0:
            score = 0.1
        elif similar_count <= 2:
            score = 0.3
        elif similar_count <= 5:
            score = 0.5
        elif similar_count <= 10:
            score = 0.7
        else:
            score = 0.9
        
        return score
    
    async def _calculate_mttr_score(self, incident: Incident) -> float:
        """
        Calculate MTTR (Mean Time To Resolve) factor (0.0-1.0).
        Based on historical MTTR for similar incidents.
        """
        if not incident.service_name:
            return 0.5  # Default moderate MTTR
        
        # Get historical MTTR for service
        lookback = datetime.now(timezone.utc) - timedelta(days=90)
        
        result = await self.session.execute(
            select(Incident)
            .where(
                and_(
                    Incident.service_name == incident.service_name,
                    Incident.detected_at >= lookback,
                    Incident.resolved_at.isnot(None),
                    Incident.state == EventState.RESOLVED
                )
            )
            .limit(20)
        )
        historical_incidents = list(result.scalars().all())
        
        if not historical_incidents:
            # If current incident is resolved, use its duration
            if incident.resolved_at and incident.detected_at:
                current_mttr = (
                    incident.resolved_at - incident.detected_at
                ).total_seconds() / 60
                return self._mttr_to_score(current_mttr)
            return 0.5  # Default
        
        # Calculate average MTTR
        mttrs = [
            (inc.resolved_at - inc.detected_at).total_seconds() / 60
            for inc in historical_incidents
        ]
        avg_mttr = sum(mttrs) / len(mttrs)
        
        return self._mttr_to_score(avg_mttr)
    
    def _mttr_to_score(self, mttr_minutes: float) -> float:
        """
        Convert MTTR to risk score.
        Lower MTTR = lower risk, higher MTTR = higher risk.
        """
        if mttr_minutes <= self.mttr_thresholds["excellent"]:
            return 0.1
        elif mttr_minutes <= self.mttr_thresholds["good"]:
            return 0.3
        elif mttr_minutes <= self.mttr_thresholds["acceptable"]:
            return 0.5
        elif mttr_minutes <= self.mttr_thresholds["poor"]:
            return 0.7
        else:
            return 0.9
    
    def _score_to_priority(
        self,
        score: float,
        severity: EventSeverity
    ) -> Priority:
        """
        Convert risk score to priority level.
        Also considers incident severity.
        """
        # Force P1 for extreme severity incidents with high score
        if severity == EventSeverity.EXTREME and score >= 60:
            return Priority.P1
        
        # Score-based priority
        if score >= 80:
            return Priority.P1
        elif score >= 60:
            return Priority.P2
        elif score >= 40:
            return Priority.P3
        elif score >= 20:
            return Priority.P4
        else:
            return Priority.P5
    
    async def _calculate_risk_trend(self, incident: Incident) -> RiskTrend:
        """
        Calculate risk trend for an incident.
        Compares recent behavior to historical baseline.
        """
        if not incident.service_name:
            return RiskTrend.STABLE
        
        # Get recent incidents (last 7 days)
        recent_start = datetime.now(timezone.utc) - timedelta(days=7)
        historical_start = datetime.now(timezone.utc) - timedelta(days=30)
        
        result_recent = await self.session.execute(
            select(func.count(Incident.id))
            .where(
                and_(
                    Incident.service_name == incident.service_name,
                    Incident.detected_at >= recent_start
                )
            )
        )
        recent_count = result_recent.scalar() or 0
        
        result_historical = await self.session.execute(
            select(func.count(Incident.id))
            .where(
                and_(
                    Incident.service_name == incident.service_name,
                    Incident.detected_at >= historical_start,
                    Incident.detected_at < recent_start
                )
            )
        )
        historical_count = result_historical.scalar() or 0
        
        # Calculate weekly rates
        recent_rate = recent_count / 1  # 1 week
        historical_rate = historical_count / 3 if historical_count > 0 else 0  # 3 weeks avg
        
        # Determine trend
        if historical_rate == 0:
            return RiskTrend.STABLE
        
        ratio = recent_rate / historical_rate
        
        if ratio >= 1.5:
            return RiskTrend.INCREASING
        elif ratio <= 0.67:
            return RiskTrend.DECREASING
        else:
            return RiskTrend.STABLE
    
    def _calculate_score_trend(self, scores: List[float]) -> RiskTrend:
        """Calculate trend from list of scores."""
        if len(scores) < 3:
            return RiskTrend.STABLE
        
        # Compare first half to second half
        mid = len(scores) // 2
        first_half_avg = sum(scores[:mid]) / mid
        second_half_avg = sum(scores[mid:]) / (len(scores) - mid)
        
        if second_half_avg > first_half_avg * 1.2:
            return RiskTrend.INCREASING
        elif second_half_avg < first_half_avg * 0.8:
            return RiskTrend.DECREASING
        else:
            return RiskTrend.STABLE
    
    def _generate_recommendation(
        self,
        total_score: float,
        priority: Priority,
        factors: RiskFactors,
        incident: Incident
    ) -> str:
        """Generate actionable recommendation based on risk analysis."""
        recommendations = []
        
        # Priority-based recommendations
        if priority == Priority.P1:
            recommendations.append(
                "IMMEDIATE ACTION REQUIRED: Engage incident response team."
            )
        elif priority == Priority.P2:
            recommendations.append(
                "HIGH PRIORITY: Assign to on-call engineer within 1 hour."
            )
        
        # Factor-specific recommendations
        if factors.blast_radius_score >= 0.7:
            recommendations.append(
                "High blast radius detected. Consider enabling circuit breakers "
                "and notifying affected teams."
            )
        
        if factors.frequency_score >= 0.7:
            recommendations.append(
                "Recurring issue detected. Schedule root cause analysis "
                "and implement preventive measures."
            )
        
        if factors.mttr_score >= 0.7:
            recommendations.append(
                "High MTTR historically. Consider improving runbooks "
                "and automation."
            )
        
        if factors.sla_impact_score >= 0.6:
            recommendations.append(
                "SLA impact detected. Escalate to management and prepare "
                "customer communication."
            )
        
        # Default recommendation
        if not recommendations:
            recommendations.append(
                "Monitor incident and follow standard response procedures."
            )
        
        return " ".join(recommendations)
    
    async def _fetch_incident(self, incident_id: UUID) -> Optional[Incident]:
        """Fetch incident by ID."""
        result = await self.session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        return result.scalar_one_or_none()


def get_default_weights() -> RiskWeights:
    """Get default risk weights."""
    return RiskWeights()


def create_custom_weights(
    severity: float,
    blast_radius: float,
    sla_impact: float,
    frequency: float,
    mttr: float
) -> RiskWeights:
    """
    Create custom risk weights.
    
    Args:
        severity: Weight for severity (0.0-1.0)
        blast_radius: Weight for blast radius (0.0-1.0)
        sla_impact: Weight for SLA impact (0.0-1.0)
        frequency: Weight for frequency (0.0-1.0)
        mttr: Weight for MTTR (0.0-1.0)
    
    Returns:
        Custom risk weights (will validate sum = 1.0)
    """
    return RiskWeights(
        severity=severity,
        blast_radius=blast_radius,
        sla_impact=sla_impact,
        frequency=frequency,
        mttr=mttr,
    )
