"""SLA tracking for security incidents."""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from enum import IntEnum

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import SLATracking, NormalizedEvent

logger = logging.getLogger(__name__)


class SeverityLevel(IntEnum):
    """Incident severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class SLATracker:
    """Track and report on SLA compliance for incidents."""
    
    # SLA targets in minutes
    SLA_TARGETS = {
        SeverityLevel.EMERGENCY: 120,  # 2 hours
        SeverityLevel.CRITICAL: 120,   # 2 hours
        SeverityLevel.HIGH: 480,       # 8 hours
        SeverityLevel.MEDIUM: 1440,    # 24 hours
        SeverityLevel.LOW: 4320,       # 72 hours
    }
    
    async def track_incident(
        self,
        db: AsyncSession,
        incident_id: str,
        severity: int,
        detected_at: datetime
    ) -> Dict[str, Any]:
        """Start tracking SLA for a new incident.
        
        Args:
            db: Database session
            incident_id: Unique incident identifier
            severity: Severity level (1-5)
            detected_at: When incident was detected
            
        Returns:
            SLA tracking record
        """
        severity_level = SeverityLevel(severity)
        target_minutes = self.SLA_TARGETS.get(severity_level, self.SLA_TARGETS[SeverityLevel.LOW])
        
        sla_record = SLATracking(
            incident_id=incident_id,
            severity=severity,
            target_response_minutes=target_minutes,
            created_at=detected_at
        )
        
        db.add(sla_record)
        await db.commit()
        
        logger.info(
            "SLA tracking started: incident=%s, severity=%d, target=%dm",
            incident_id,
            severity,
            target_minutes
        )
        
        return {
            "incident_id": incident_id,
            "severity": severity,
            "target_response_minutes": target_minutes,
            "breach_at": (detected_at + timedelta(minutes=target_minutes)).isoformat()
        }
    
    async def record_response(
        self,
        db: AsyncSession,
        incident_id: str,
        responded_at: datetime
    ) -> Dict[str, Any]:
        """Record when incident was responded to.
        
        Args:
            db: Database session
            incident_id: Incident identifier
            responded_at: When response occurred
            
        Returns:
            Updated SLA record with compliance status
        """
        # Get SLA record
        result = await db.execute(
            select(SLATracking).where(SLATracking.incident_id == incident_id)
        )
        sla_record = result.scalar_one_or_none()
        
        if not sla_record:
            logger.warning("SLA record not found for incident: %s", incident_id)
            return {"error": "SLA record not found"}
        
        # Calculate response time
        response_minutes = int((responded_at - sla_record.created_at).total_seconds() / 60)
        
        # Check if SLA was met
        sla_met = response_minutes <= sla_record.target_response_minutes
        
        # Update record
        sla_record.actual_response_minutes = response_minutes
        sla_record.sla_met = sla_met
        
        if not sla_met:
            # Calculate breach time
            breach_time = sla_record.created_at + timedelta(
                minutes=sla_record.target_response_minutes
            )
            sla_record.breached_at = breach_time
        
        await db.commit()
        
        logger.info(
            "SLA response recorded: incident=%s, response_time=%dm, target=%dm, met=%s",
            incident_id,
            response_minutes,
            sla_record.target_response_minutes,
            sla_met
        )
        
        return {
            "incident_id": incident_id,
            "actual_response_minutes": response_minutes,
            "target_response_minutes": sla_record.target_response_minutes,
            "sla_met": sla_met,
            "breach_minutes": max(0, response_minutes - sla_record.target_response_minutes)
        }
    
    async def record_resolution(
        self,
        db: AsyncSession,
        incident_id: str,
        resolved_at: datetime
    ) -> bool:
        """Record when incident was resolved.
        
        Args:
            db: Database session
            incident_id: Incident identifier
            resolved_at: When incident was resolved
            
        Returns:
            True if recorded successfully
        """
        result = await db.execute(
            select(SLATracking).where(SLATracking.incident_id == incident_id)
        )
        sla_record = result.scalar_one_or_none()
        
        if not sla_record:
            return False
        
        sla_record.resolved_at = resolved_at
        await db.commit()
        
        logger.info("SLA resolution recorded: incident=%s", incident_id)
        return True
    
    async def get_incident_sla(
        self,
        db: AsyncSession,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get SLA status for a specific incident.
        
        Args:
            db: Database session
            incident_id: Incident identifier
            
        Returns:
            SLA status or None if not found
        """
        result = await db.execute(
            select(SLATracking).where(SLATracking.incident_id == incident_id)
        )
        sla_record = result.scalar_one_or_none()
        
        if not sla_record:
            return None
        
        return {
            "incident_id": sla_record.incident_id,
            "severity": sla_record.severity,
            "target_response_minutes": sla_record.target_response_minutes,
            "actual_response_minutes": sla_record.actual_response_minutes,
            "sla_met": sla_record.sla_met,
            "breached_at": sla_record.breached_at.isoformat() if sla_record.breached_at else None,
            "resolved_at": sla_record.resolved_at.isoformat() if sla_record.resolved_at else None,
            "created_at": sla_record.created_at.isoformat()
        }
    
    async def get_sla_compliance_report(
        self,
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate SLA compliance report for a time period.
        
        Args:
            db: Database session
            start_date: Report start date (default: 30 days ago)
            end_date: Report end date (default: now)
            
        Returns:
            Compliance report with metrics by severity
        """
        if start_date is None:
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if end_date is None:
            end_date = datetime.utcnow()
        
        # Query SLA records
        result = await db.execute(
            select(SLATracking)
            .where(and_(
                SLATracking.created_at >= start_date,
                SLATracking.created_at <= end_date
            ))
        )
        sla_records = result.scalars().all()
        
        # Calculate metrics by severity
        severity_metrics = {}
        
        for severity_level in SeverityLevel:
            severity_records = [r for r in sla_records if r.severity == severity_level.value]
            
            if not severity_records:
                continue
            
            total = len(severity_records)
            met = sum(1 for r in severity_records if r.sla_met)
            breached = total - met
            
            # Calculate average response time
            response_times = [
                r.actual_response_minutes
                for r in severity_records
                if r.actual_response_minutes is not None
            ]
            avg_response = sum(response_times) / len(response_times) if response_times else 0
            
            severity_metrics[severity_level.name] = {
                "total_incidents": total,
                "sla_met": met,
                "sla_breached": breached,
                "compliance_rate": met / total if total > 0 else 0,
                "target_minutes": self.SLA_TARGETS[severity_level],
                "avg_response_minutes": avg_response
            }
        
        # Calculate overall metrics
        total_incidents = len(sla_records)
        total_met = sum(1 for r in sla_records if r.sla_met)
        overall_compliance = total_met / total_incidents if total_incidents > 0 else 0
        
        return {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "overall": {
                "total_incidents": total_incidents,
                "sla_met": total_met,
                "sla_breached": total_incidents - total_met,
                "compliance_rate": overall_compliance
            },
            "by_severity": severity_metrics,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    async def get_breached_slas(
        self,
        db: AsyncSession,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent SLA breaches.
        
        Args:
            db: Database session
            limit: Maximum number of breaches to return
            
        Returns:
            List of breached SLAs
        """
        result = await db.execute(
            select(SLATracking)
            .where(SLATracking.sla_met == False)  # noqa: E712
            .order_by(SLATracking.breached_at.desc())
            .limit(limit)
        )
        breached_records = result.scalars().all()
        
        breaches = []
        for record in breached_records:
            breach_minutes = (
                record.actual_response_minutes - record.target_response_minutes
                if record.actual_response_minutes
                else 0
            )
            
            breaches.append({
                "incident_id": record.incident_id,
                "severity": record.severity,
                "target_minutes": record.target_response_minutes,
                "actual_minutes": record.actual_response_minutes,
                "breach_minutes": breach_minutes,
                "breached_at": record.breached_at.isoformat() if record.breached_at else None,
                "created_at": record.created_at.isoformat()
            })
        
        return breaches


# Global SLA tracker instance
_sla_tracker: Optional[SLATracker] = None


def get_sla_tracker() -> SLATracker:
    """Get or create global SLA tracker instance."""
    global _sla_tracker
    if _sla_tracker is None:
        _sla_tracker = SLATracker()
    return _sla_tracker
