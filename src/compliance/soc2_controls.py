"""SOC2 compliance control mappings and validation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4


class TrustServiceCriteria(str, Enum):
    """SOC2 Trust Service Criteria categories."""

    COMMON_CRITERIA = "CC"  # Common Criteria
    AVAILABILITY = "A"  # Availability
    CONFIDENTIALITY = "C"  # Confidentiality
    PROCESSING_INTEGRITY = "PI"  # Processing Integrity
    PRIVACY = "P"  # Privacy


class ControlStatus(str, Enum):
    """Control implementation and testing status."""

    NOT_IMPLEMENTED = "not_implemented"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    TESTED = "tested"
    FAILED = "failed"


@dataclass
class SOC2Control:
    """Represents a single SOC2 control.

    Attributes:
        control_id: Unique control identifier (e.g., CC6.1)
        criteria: Trust Service Criteria category
        title: Control title
        description: Detailed control description
        implementation_details: How the control is implemented
        status: Current control status
        owner: Person or team responsible for the control
        evidence_required: List of required evidence types
        test_frequency: How often the control should be tested
        last_tested: Date of last control test
        last_test_result: Result of last test
        next_test_due: Date when next test is due
    """

    control_id: str
    criteria: TrustServiceCriteria
    title: str
    description: str
    implementation_details: str = ""
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    owner: str = ""
    evidence_required: List[str] = field(default_factory=list)
    test_frequency: str = "quarterly"  # daily, weekly, monthly, quarterly, annually
    last_tested: Optional[datetime] = None
    last_test_result: Optional[str] = None
    next_test_due: Optional[datetime] = None
    automated: bool = False
    related_systems: List[str] = field(default_factory=list)


@dataclass
class ControlEvidence:
    """Evidence collected for a control.

    Attributes:
        evidence_id: Unique evidence identifier
        control_id: Associated control ID
        evidence_type: Type of evidence (logs, screenshot, document, etc.)
        description: Description of the evidence
        collected_at: When evidence was collected
        collected_by: Who collected the evidence
        file_path: Path to evidence file (if applicable)
        metadata: Additional evidence metadata
    """

    evidence_id: UUID = field(default_factory=uuid4)
    control_id: str = ""
    evidence_type: str = ""
    description: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collected_by: str = ""
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SOC2Controls:
    """SOC2 control management and compliance tracking.

    This class provides methods to manage SOC2 controls, validate
    implementations, and collect evidence for compliance audits.
    """

    def __init__(self) -> None:
        """Initialize SOC2 controls manager with predefined controls."""
        self.controls: Dict[str, SOC2Control] = {}
        self.evidence: Dict[str, List[ControlEvidence]] = {}
        self._initialize_controls()

    def _initialize_controls(self) -> None:
        """Initialize standard SOC2 controls."""
        # Common Criteria - Control Environment
        self.add_control(
            SOC2Control(
                control_id="CC1.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Organization demonstrates commitment to integrity and ethical values",
                description="Entity demonstrates commitment to integrity and ethical values",
                evidence_required=["code_of_conduct", "ethics_training_records"],
            )
        )

        # Common Criteria - Communication and Information
        self.add_control(
            SOC2Control(
                control_id="CC2.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Information security policies communicated",
                description="Entity communicates information security policies to authorized users",
                evidence_required=["policy_documents", "training_records", "acknowledgments"],
            )
        )

        # Common Criteria - Risk Assessment
        self.add_control(
            SOC2Control(
                control_id="CC3.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Risk assessment process",
                description=(
                    "Entity specifies objectives with sufficient clarity to enable "
                    "identification and assessment of risks"
                ),
                evidence_required=["risk_assessments", "risk_register"],
            )
        )

        # Common Criteria - Monitoring Activities
        self.add_control(
            SOC2Control(
                control_id="CC4.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Performance monitoring",
                description="Entity monitors system performance and alerts on deviations",
                evidence_required=["monitoring_dashboards", "alert_logs", "incident_reports"],
                automated=True,
                related_systems=["prometheus", "grafana", "pagerduty"],
            )
        )

        # Common Criteria - Control Activities
        self.add_control(
            SOC2Control(
                control_id="CC5.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Change management",
                description="Entity implements change management process for system modifications",
                evidence_required=["change_tickets", "approval_records", "deployment_logs"],
            )
        )

        # Common Criteria - Logical and Physical Access Controls
        self.add_control(
            SOC2Control(
                control_id="CC6.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Logical access controls",
                description=(
                    "Entity implements logical access security measures to protect against "
                    "threats from sources outside its system boundaries"
                ),
                evidence_required=[
                    "access_logs",
                    "authentication_logs",
                    "mfa_enrollment_records",
                    "failed_login_attempts",
                ],
                automated=True,
                related_systems=["okta", "auth_service"],
            )
        )

        self.add_control(
            SOC2Control(
                control_id="CC6.2",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Data encryption",
                description=(
                    "Entity uses encryption to protect data during transmission and at rest"
                ),
                evidence_required=[
                    "encryption_configuration",
                    "key_rotation_logs",
                    "tls_certificates",
                ],
                automated=True,
                related_systems=["azure_keyvault", "encryption_service"],
            )
        )

        self.add_control(
            SOC2Control(
                control_id="CC6.6",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Audit logging",
                description="Entity implements audit logging for security events and data access",
                evidence_required=["audit_logs", "log_retention_policy", "log_reviews"],
                automated=True,
                related_systems=["audit_log_service"],
            )
        )

        # Common Criteria - System Operations
        self.add_control(
            SOC2Control(
                control_id="CC7.1",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Anomaly detection",
                description="Entity detects and acts upon anomalies in system operations",
                evidence_required=[
                    "anomaly_detection_logs",
                    "alert_configurations",
                    "incident_responses",
                ],
                automated=True,
                related_systems=["anomaly_detector", "ml_service"],
            )
        )

        self.add_control(
            SOC2Control(
                control_id="CC7.2",
                criteria=TrustServiceCriteria.COMMON_CRITERIA,
                title="Security incident management",
                description="Entity identifies, reports, and acts upon security incidents",
                evidence_required=[
                    "incident_tickets",
                    "incident_response_plans",
                    "post_incident_reviews",
                ],
            )
        )

        # Availability
        self.add_control(
            SOC2Control(
                control_id="A1.1",
                criteria=TrustServiceCriteria.AVAILABILITY,
                title="System availability monitoring",
                description="Entity monitors system availability and performance",
                evidence_required=["uptime_reports", "performance_metrics", "sla_reports"],
                automated=True,
                related_systems=["prometheus", "sla_tracker"],
            )
        )

        self.add_control(
            SOC2Control(
                control_id="A1.2",
                criteria=TrustServiceCriteria.AVAILABILITY,
                title="Incident response procedures",
                description="Entity has procedures to respond to system availability issues",
                evidence_required=[
                    "runbooks",
                    "incident_response_times",
                    "escalation_procedures",
                ],
            )
        )

        # Confidentiality
        self.add_control(
            SOC2Control(
                control_id="C1.1",
                criteria=TrustServiceCriteria.CONFIDENTIALITY,
                title="Data classification",
                description="Entity identifies and classifies confidential information",
                evidence_required=["data_classification_policy", "data_inventory"],
            )
        )

        self.add_control(
            SOC2Control(
                control_id="C1.2",
                criteria=TrustServiceCriteria.CONFIDENTIALITY,
                title="Access restrictions",
                description="Entity restricts access to confidential information",
                evidence_required=[
                    "access_control_lists",
                    "rbac_configuration",
                    "access_reviews",
                ],
                automated=True,
            )
        )

        # Processing Integrity
        self.add_control(
            SOC2Control(
                control_id="PI1.1",
                criteria=TrustServiceCriteria.PROCESSING_INTEGRITY,
                title="Data validation",
                description="Entity validates input data for accuracy and completeness",
                evidence_required=["validation_rules", "error_logs", "data_quality_reports"],
                automated=True,
                related_systems=["input_validator"],
            )
        )

        # Privacy
        self.add_control(
            SOC2Control(
                control_id="P1.1",
                criteria=TrustServiceCriteria.PRIVACY,
                title="Privacy notice",
                description="Entity provides notice of privacy practices",
                evidence_required=["privacy_policy", "user_consent_records"],
            )
        )

    def add_control(self, control: SOC2Control) -> None:
        """Add a control to the manager.

        Args:
            control: SOC2Control instance to add
        """
        self.controls[control.control_id] = control
        if control.control_id not in self.evidence:
            self.evidence[control.control_id] = []

    def get_control(self, control_id: str) -> Optional[SOC2Control]:
        """Get a control by ID.

        Args:
            control_id: Control identifier

        Returns:
            SOC2Control instance or None if not found
        """
        return self.controls.get(control_id)

    def get_controls_by_criteria(self, criteria: TrustServiceCriteria) -> List[SOC2Control]:
        """Get all controls for a specific criteria.

        Args:
            criteria: Trust Service Criteria category

        Returns:
            List of controls matching the criteria
        """
        return [c for c in self.controls.values() if c.criteria == criteria]

    def update_control_status(
        self,
        control_id: str,
        status: ControlStatus,
        tested_at: Optional[datetime] = None,
        test_result: Optional[str] = None,
    ) -> bool:
        """Update control status and test results.

        Args:
            control_id: Control identifier
            status: New control status
            tested_at: When the control was tested
            test_result: Result of the test

        Returns:
            True if update was successful, False otherwise
        """
        control = self.get_control(control_id)
        if not control:
            return False

        control.status = status
        if tested_at:
            control.last_tested = tested_at
        if test_result:
            control.last_test_result = test_result

        return True

    def add_evidence(self, evidence: ControlEvidence) -> None:
        """Add evidence for a control.

        Args:
            evidence: ControlEvidence instance to add
        """
        if evidence.control_id not in self.evidence:
            self.evidence[evidence.control_id] = []
        self.evidence[evidence.control_id].append(evidence)

    def get_evidence(self, control_id: str) -> List[ControlEvidence]:
        """Get all evidence for a control.

        Args:
            control_id: Control identifier

        Returns:
            List of evidence for the control
        """
        return self.evidence.get(control_id, [])

    def validate_control(self, control_id: str) -> Dict[str, Any]:
        """Validate a control's implementation.

        Args:
            control_id: Control identifier

        Returns:
            Dictionary containing validation results
        """
        control = self.get_control(control_id)
        if not control:
            return {"valid": False, "error": "Control not found"}

        issues = []
        warnings = []

        # Check if control is implemented
        if control.status == ControlStatus.NOT_IMPLEMENTED:
            issues.append("Control is not implemented")

        # Check if control has owner
        if not control.owner:
            warnings.append("Control has no assigned owner")

        # Check if evidence is collected
        evidence_list = self.get_evidence(control_id)
        missing_evidence = set(control.evidence_required) - {e.evidence_type for e in evidence_list}
        if missing_evidence:
            issues.append(f"Missing required evidence: {', '.join(missing_evidence)}")

        # Check if control was recently tested
        if control.last_tested is None:
            warnings.append("Control has never been tested")

        return {
            "valid": len(issues) == 0,
            "control_id": control_id,
            "status": control.status.value,
            "issues": issues,
            "warnings": warnings,
            "evidence_count": len(evidence_list),
        }

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate a comprehensive compliance report.

        Returns:
            Dictionary containing compliance report data
        """
        total_controls = len(self.controls)
        status_counts = dict.fromkeys(ControlStatus, 0)

        for control in self.controls.values():
            status_counts[control.status] += 1

        # Count controls by criteria
        criteria_counts = dict.fromkeys(TrustServiceCriteria, 0)
        for control in self.controls.values():
            criteria_counts[control.criteria] += 1

        # Calculate compliance percentage
        compliant_controls = (
            status_counts[ControlStatus.IMPLEMENTED] + status_counts[ControlStatus.TESTED]
        )
        compliance_percentage = (
            (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        )

        # Identify controls needing attention
        needs_attention = []
        for control in self.controls.values():
            validation = self.validate_control(control.control_id)
            if not validation["valid"] or validation["warnings"]:
                needs_attention.append(
                    {
                        "control_id": control.control_id,
                        "title": control.title,
                        "issues": validation["issues"],
                        "warnings": validation["warnings"],
                    }
                )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_controls": total_controls,
            "compliance_percentage": round(compliance_percentage, 2),
            "status_breakdown": {status.value: count for status, count in status_counts.items()},
            "criteria_breakdown": {
                criteria.value: count for criteria, count in criteria_counts.items()
            },
            "controls_needing_attention": needs_attention,
            "automated_controls": sum(1 for c in self.controls.values() if c.automated),
        }

    def get_automated_control_ids(self) -> List[str]:
        """Get list of automated control IDs.

        Returns:
            List of control IDs that can be automatically validated
        """
        return [c.control_id for c in self.controls.values() if c.automated]
