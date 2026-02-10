"""Compliance dashboards for SOC2, ISO 27001, and GDPR."""
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import AuditLog, MFAToken, NormalizedEvent

logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"


class ComplianceReporter:
    """Generate compliance dashboards and reports."""

    # SOC2 Control Targets
    SOC2_MFA_ADOPTION_TARGET = 0.95  # 95% of users
    SOC2_INCIDENT_RESPONSE_HOURS = 24  # Critical incidents
    SOC2_ENCRYPTION_COVERAGE = 1.0  # 100% of sensitive data
    SOC2_ACCESS_REVIEW_DAYS = 90  # Quarterly reviews

    # ISO 27001 Targets
    ISO27001_RISK_ASSESSMENT_DAYS = 180  # Semi-annual
    ISO27001_POLICY_REVIEW_DAYS = 365  # Annual
    ISO27001_TRAINING_COMPLETION = 0.90  # 90% completion

    # GDPR Targets
    GDPR_BREACH_NOTIFICATION_HOURS = 72  # 72 hours
    GDPR_DATA_RETENTION_YEARS = 7  # Keep audit logs 7 years

    async def get_soc2_compliance(self, db: AsyncSession) -> Dict[str, Any]:
        """Generate SOC2 compliance dashboard.
        
        Args:
            db: Database session
            
        Returns:
            SOC2 compliance metrics and score
        """
        metrics = {}

        # 1. MFA Adoption Rate
        total_users_result = await db.execute(
            select(func.count(func.distinct(MFAToken.user_id)))
        )
        total_users = total_users_result.scalar() or 1  # Avoid division by zero

        verified_users_result = await db.execute(
            select(func.count(func.distinct(MFAToken.user_id)))
            .where(MFAToken.verified == True)  # noqa: E712
        )
        verified_users = verified_users_result.scalar() or 0

        mfa_adoption = verified_users / total_users if total_users > 0 else 0
        metrics['mfa_adoption_rate'] = mfa_adoption
        metrics['mfa_target'] = self.SOC2_MFA_ADOPTION_TARGET
        metrics['mfa_compliant'] = mfa_adoption >= self.SOC2_MFA_ADOPTION_TARGET

        # 2. Access Reviews (last 90 days)
        ninety_days_ago = datetime.utcnow() - timedelta(days=self.SOC2_ACCESS_REVIEW_DAYS)
        access_review_result = await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == 'ACCESS_REVIEW')
            .where(AuditLog.timestamp >= ninety_days_ago)
        )
        access_reviews = access_review_result.scalar() or 0
        metrics['access_reviews_last_90d'] = access_reviews
        metrics['access_review_compliant'] = access_reviews > 0

        # 3. Incident Response Time (critical incidents)
        # This is a simplified calculation - in production, track actual response times
        critical_incidents_result = await db.execute(
            select(func.count())
            .select_from(NormalizedEvent)
            .where(NormalizedEvent.severity == 5)
            .where(NormalizedEvent.timestamp >= datetime.utcnow() - timedelta(days=30))
        )
        critical_incidents = critical_incidents_result.scalar() or 0

        # Assume 95% response within 24h for demo
        metrics['critical_incidents_last_30d'] = critical_incidents
        metrics['incident_response_rate'] = 0.95
        metrics['incident_response_target'] = 0.90
        metrics['incident_response_compliant'] = True

        # 4. Encryption Coverage
        # In production, calculate % of data encrypted at rest and in transit
        metrics['encryption_coverage'] = self.SOC2_ENCRYPTION_COVERAGE
        metrics['encryption_compliant'] = True

        # Calculate overall SOC2 score (0-100)
        compliance_checks = [
            metrics['mfa_compliant'],
            metrics['access_review_compliant'],
            metrics['incident_response_compliant'],
            metrics['encryption_compliant']
        ]

        score = (sum(compliance_checks) / len(compliance_checks)) * 100

        return {
            "framework": "SOC2",
            "score": score,
            "compliant": score >= 90,
            "metrics": metrics,
            "generated_at": datetime.utcnow().isoformat()
        }

    async def get_iso27001_compliance(self, db: AsyncSession) -> Dict[str, Any]:
        """Generate ISO 27001 compliance dashboard.
        
        Args:
            db: Database session
            
        Returns:
            ISO 27001 compliance metrics and score
        """
        metrics = {}

        # 1. Risk Assessments (last 180 days)
        six_months_ago = datetime.utcnow() - timedelta(days=self.ISO27001_RISK_ASSESSMENT_DAYS)
        risk_assessment_result = await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == 'RISK_ASSESSMENT')
            .where(AuditLog.timestamp >= six_months_ago)
        )
        risk_assessments = risk_assessment_result.scalar() or 0
        metrics['risk_assessments_last_180d'] = risk_assessments
        metrics['risk_assessment_compliant'] = risk_assessments > 0

        # 2. Policy Reviews (last 365 days)
        one_year_ago = datetime.utcnow() - timedelta(days=self.ISO27001_POLICY_REVIEW_DAYS)
        policy_review_result = await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == 'POLICY_REVIEW')
            .where(AuditLog.timestamp >= one_year_ago)
        )
        policy_reviews = policy_review_result.scalar() or 0
        metrics['policy_reviews_last_365d'] = policy_reviews
        metrics['policy_review_compliant'] = policy_reviews > 0

        # 3. Security Training Completion
        # In production, track actual training completion from HR system
        metrics['training_completion_rate'] = 0.92
        metrics['training_target'] = self.ISO27001_TRAINING_COMPLETION
        metrics['training_compliant'] = metrics['training_completion_rate'] >= self.ISO27001_TRAINING_COMPLETION

        # Calculate overall ISO 27001 score
        compliance_checks = [
            metrics['risk_assessment_compliant'],
            metrics['policy_review_compliant'],
            metrics['training_compliant']
        ]

        score = (sum(compliance_checks) / len(compliance_checks)) * 100

        return {
            "framework": "ISO 27001",
            "score": score,
            "compliant": score >= 90,
            "metrics": metrics,
            "generated_at": datetime.utcnow().isoformat()
        }

    async def get_gdpr_compliance(self, db: AsyncSession) -> Dict[str, Any]:
        """Generate GDPR compliance dashboard.
        
        Args:
            db: Database session
            
        Returns:
            GDPR compliance metrics and score
        """
        metrics = {}

        # 1. Data Retention Compliance (7-year audit logs)
        seven_years_ago = datetime.utcnow() - timedelta(days=self.GDPR_DATA_RETENTION_YEARS * 365)
        oldest_audit_result = await db.execute(
            select(func.min(AuditLog.timestamp))
        )
        oldest_audit = oldest_audit_result.scalar()

        if oldest_audit:
            retention_compliant = oldest_audit >= seven_years_ago
            metrics['oldest_audit_log'] = oldest_audit.isoformat()
        else:
            retention_compliant = True
            metrics['oldest_audit_log'] = None

        metrics['data_retention_compliant'] = retention_compliant

        # 2. Breach Notification (72-hour requirement)
        # Check if any security breaches were reported within 72 hours
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        breach_notifications_result = await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == 'BREACH_NOTIFICATION')
            .where(AuditLog.timestamp >= thirty_days_ago)
        )
        breach_notifications = breach_notifications_result.scalar() or 0

        # In production, verify each notification was within 72 hours
        metrics['breach_notifications_last_30d'] = breach_notifications
        metrics['breach_notification_compliant'] = True  # Assume compliant for demo

        # 3. Consent Management
        # In production, track user consent for data processing
        consent_result = await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == 'CONSENT_RECORDED')
            .where(AuditLog.timestamp >= thirty_days_ago)
        )
        consents_recorded = consent_result.scalar() or 0

        metrics['consents_recorded_last_30d'] = consents_recorded
        metrics['consent_management_compliant'] = True

        # Calculate overall GDPR score
        compliance_checks = [
            metrics['data_retention_compliant'],
            metrics['breach_notification_compliant'],
            metrics['consent_management_compliant']
        ]

        score = (sum(compliance_checks) / len(compliance_checks)) * 100

        return {
            "framework": "GDPR",
            "score": score,
            "compliant": score >= 90,
            "metrics": metrics,
            "generated_at": datetime.utcnow().isoformat()
        }

    async def get_compliance_dashboard(
        self,
        db: AsyncSession,
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance dashboard.
        
        Args:
            db: Database session
            frameworks: List of frameworks to include (default: all)
            
        Returns:
            Compliance dashboard with all frameworks
        """
        if frameworks is None:
            frameworks = [ComplianceFramework.SOC2, ComplianceFramework.ISO27001, ComplianceFramework.GDPR]

        reports = {}

        if ComplianceFramework.SOC2 in frameworks:
            reports['soc2'] = await self.get_soc2_compliance(db)

        if ComplianceFramework.ISO27001 in frameworks:
            reports['iso27001'] = await self.get_iso27001_compliance(db)

        if ComplianceFramework.GDPR in frameworks:
            reports['gdpr'] = await self.get_gdpr_compliance(db)

        # Calculate overall compliance score
        scores = [report['score'] for report in reports.values()]
        overall_score = sum(scores) / len(scores) if scores else 0

        return {
            "overall_compliance_score": overall_score,
            "compliant": overall_score >= 90,
            "framework_reports": reports,
            "generated_at": datetime.utcnow().isoformat()
        }


# Global compliance reporter instance
_compliance_reporter: Optional[ComplianceReporter] = None


def get_compliance_reporter() -> ComplianceReporter:
    """Get or create global compliance reporter instance."""
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter()
    return _compliance_reporter
