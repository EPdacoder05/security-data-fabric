"""Compliance reporting for SOC2, ISO27001, GDPR, HIPAA, PCI-DSS, and NIST."""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    NIST = "NIST"


class ComplianceStatus(str, Enum):
    """Compliance status values."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


class ComplianceReporter:
    """Compliance reporting and gap analysis for multiple frameworks.

    Supports SOC2, ISO27001, GDPR, HIPAA, PCI-DSS, and NIST frameworks.
    Provides compliance status tracking, gap analysis, and report generation.

    Attributes:
        framework: Active compliance framework
        controls: Dictionary of control requirements
        audit_data: Historical audit data
    """

    def __init__(self, framework: ComplianceFramework) -> None:
        """Initialize the compliance reporter.

        Args:
            framework: Compliance framework to use for reporting
        """
        self.framework = framework
        self.controls = self._load_controls(framework)
        self.audit_data: List[Dict] = []

    def _load_controls(self, framework: ComplianceFramework) -> Dict[str, Dict]:
        """Load control requirements for specified framework.

        Args:
            framework: Compliance framework

        Returns:
            Dictionary of control ID to control details
        """
        controls = {
            ComplianceFramework.SOC2: self._get_soc2_controls(),
            ComplianceFramework.ISO27001: self._get_iso27001_controls(),
            ComplianceFramework.GDPR: self._get_gdpr_controls(),
            ComplianceFramework.HIPAA: self._get_hipaa_controls(),
            ComplianceFramework.PCI_DSS: self._get_pci_dss_controls(),
            ComplianceFramework.NIST: self._get_nist_controls(),
        }
        return controls.get(framework, {})

    def _get_soc2_controls(self) -> Dict[str, Dict]:
        """Get SOC2 Trust Service Criteria controls."""
        return {
            "CC1.1": {
                "name": "Control Environment",
                "description": "Organization demonstrates commitment to integrity and ethical values",
                "category": "Common Criteria",
                "required": True,
            },
            "CC2.1": {
                "name": "Communication and Information",
                "description": "Information security policies communicated to personnel",
                "category": "Common Criteria",
                "required": True,
            },
            "CC3.1": {
                "name": "Risk Assessment",
                "description": "Entity identifies and assesses risks",
                "category": "Common Criteria",
                "required": True,
            },
            "CC6.1": {
                "name": "Logical and Physical Access",
                "description": "Entity implements controls to prevent unauthorized access",
                "category": "Common Criteria",
                "required": True,
            },
            "CC7.2": {
                "name": "System Monitoring",
                "description": "Entity monitors system components",
                "category": "Common Criteria",
                "required": True,
            },
        }

    def _get_iso27001_controls(self) -> Dict[str, Dict]:
        """Get ISO27001 controls."""
        return {
            "A.5.1": {
                "name": "Information Security Policies",
                "description": "Management direction for information security",
                "category": "Organizational",
                "required": True,
            },
            "A.6.1": {
                "name": "Internal Organization",
                "description": "Assignment of information security responsibilities",
                "category": "Organizational",
                "required": True,
            },
            "A.9.1": {
                "name": "Access Control Policy",
                "description": "Business requirements for access control",
                "category": "Access Control",
                "required": True,
            },
            "A.12.1": {
                "name": "Operational Procedures",
                "description": "Documented operating procedures",
                "category": "Operations",
                "required": True,
            },
            "A.16.1": {
                "name": "Incident Management",
                "description": "Management of information security incidents",
                "category": "Incident Management",
                "required": True,
            },
        }

    def _get_gdpr_controls(self) -> Dict[str, Dict]:
        """Get GDPR requirements."""
        return {
            "Art.5": {
                "name": "Data Processing Principles",
                "description": "Lawfulness, fairness, transparency of data processing",
                "category": "Principles",
                "required": True,
            },
            "Art.25": {
                "name": "Data Protection by Design",
                "description": "Privacy by design and default",
                "category": "Technical",
                "required": True,
            },
            "Art.32": {
                "name": "Security of Processing",
                "description": "Appropriate technical and organizational measures",
                "category": "Security",
                "required": True,
            },
            "Art.33": {
                "name": "Breach Notification",
                "description": "Notification of data breach to supervisory authority",
                "category": "Breach Management",
                "required": True,
            },
            "Art.35": {
                "name": "Data Protection Impact Assessment",
                "description": "DPIA for high-risk processing",
                "category": "Risk Assessment",
                "required": True,
            },
        }

    def _get_hipaa_controls(self) -> Dict[str, Dict]:
        """Get HIPAA Security Rule requirements."""
        return {
            "164.308(a)(1)": {
                "name": "Security Management Process",
                "description": "Implement policies to prevent unauthorized access to ePHI",
                "category": "Administrative",
                "required": True,
            },
            "164.308(a)(3)": {
                "name": "Workforce Security",
                "description": "Ensure workforce members have appropriate access",
                "category": "Administrative",
                "required": True,
            },
            "164.310(a)(1)": {
                "name": "Facility Access Controls",
                "description": "Limit physical access to ePHI",
                "category": "Physical",
                "required": True,
            },
            "164.312(a)(1)": {
                "name": "Access Control",
                "description": "Implement technical policies to allow only authorized access",
                "category": "Technical",
                "required": True,
            },
            "164.312(e)(1)": {
                "name": "Transmission Security",
                "description": "Protect ePHI transmitted over networks",
                "category": "Technical",
                "required": True,
            },
        }

    def _get_pci_dss_controls(self) -> Dict[str, Dict]:
        """Get PCI-DSS requirements."""
        return {
            "1.1": {
                "name": "Firewall Configuration",
                "description": "Establish and implement firewall configuration standards",
                "category": "Network Security",
                "required": True,
            },
            "2.1": {
                "name": "Default Passwords",
                "description": "Always change vendor defaults",
                "category": "Configuration",
                "required": True,
            },
            "8.1": {
                "name": "User Identification",
                "description": "Assign unique ID to each person with access",
                "category": "Access Control",
                "required": True,
            },
            "10.1": {
                "name": "Audit Trails",
                "description": "Implement audit trails for all access",
                "category": "Monitoring",
                "required": True,
            },
            "11.1": {
                "name": "Wireless Access",
                "description": "Test for presence of wireless access points",
                "category": "Testing",
                "required": True,
            },
        }

    def _get_nist_controls(self) -> Dict[str, Dict]:
        """Get NIST 800-53 controls."""
        return {
            "AC-2": {
                "name": "Account Management",
                "description": "Manage system accounts",
                "category": "Access Control",
                "required": True,
            },
            "AU-2": {
                "name": "Audit Events",
                "description": "Define auditable events",
                "category": "Audit",
                "required": True,
            },
            "IR-4": {
                "name": "Incident Handling",
                "description": "Implement incident handling capability",
                "category": "Incident Response",
                "required": True,
            },
            "RA-5": {
                "name": "Vulnerability Scanning",
                "description": "Scan for vulnerabilities",
                "category": "Risk Assessment",
                "required": True,
            },
            "SC-7": {
                "name": "Boundary Protection",
                "description": "Monitor and control communications at system boundaries",
                "category": "System Communications",
                "required": True,
            },
        }

    async def check_compliance(
        self, control_id: str, evidence: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Check compliance status for a specific control.

        Args:
            control_id: Control identifier
            evidence: Optional evidence data for compliance verification

        Returns:
            Dictionary with compliance check results
        """
        if control_id not in self.controls:
            return {
                "control_id": control_id,
                "status": ComplianceStatus.NOT_APPLICABLE,
                "message": f"Control {control_id} not found in {self.framework.value}",
            }

        control = self.controls[control_id]

        status = ComplianceStatus.COMPLIANT if evidence else ComplianceStatus.NON_COMPLIANT

        return {
            "control_id": control_id,
            "control_name": control["name"],
            "status": status.value,
            "category": control["category"],
            "evidence_provided": evidence is not None,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    async def generate_compliance_report(
        self, control_statuses: Dict[str, ComplianceStatus]
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance report.

        Args:
            control_statuses: Dictionary mapping control IDs to their compliance status

        Returns:
            Comprehensive compliance report
        """
        total_controls = len(self.controls)
        compliant_count = sum(
            1 for status in control_statuses.values() if status == ComplianceStatus.COMPLIANT
        )
        non_compliant_count = sum(
            1 for status in control_statuses.values() if status == ComplianceStatus.NON_COMPLIANT
        )
        partial_count = sum(
            1 for status in control_statuses.values() if status == ComplianceStatus.PARTIAL
        )

        compliance_percentage = (
            (compliant_count / total_controls * 100) if total_controls > 0 else 0
        )

        return {
            "framework": self.framework.value,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_controls": total_controls,
                "compliant": compliant_count,
                "non_compliant": non_compliant_count,
                "partial": partial_count,
                "compliance_percentage": round(compliance_percentage, 2),
            },
            "controls": [
                {
                    "control_id": control_id,
                    "name": control["name"],
                    "category": control["category"],
                    "status": control_statuses.get(
                        control_id, ComplianceStatus.NOT_APPLICABLE
                    ).value,
                    "required": control["required"],
                }
                for control_id, control in self.controls.items()
            ],
        }

    async def perform_gap_analysis(
        self, control_statuses: Dict[str, ComplianceStatus]
    ) -> Dict[str, Any]:
        """Perform gap analysis to identify non-compliant controls.

        Args:
            control_statuses: Dictionary mapping control IDs to their compliance status

        Returns:
            Gap analysis report with remediation priorities
        """
        gaps = []

        for control_id, control in self.controls.items():
            status = control_statuses.get(control_id, ComplianceStatus.NON_COMPLIANT)

            if status in [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIAL]:
                priority = "HIGH" if control["required"] else "MEDIUM"

                gaps.append(
                    {
                        "control_id": control_id,
                        "name": control["name"],
                        "category": control["category"],
                        "status": status.value,
                        "priority": priority,
                        "description": control["description"],
                    }
                )

        gaps.sort(key=lambda x: (x["priority"] == "HIGH", x["control_id"]), reverse=True)

        return {
            "framework": self.framework.value,
            "analysis_date": datetime.now(timezone.utc).isoformat(),
            "total_gaps": len(gaps),
            "high_priority": sum(1 for g in gaps if g["priority"] == "HIGH"),
            "medium_priority": sum(1 for g in gaps if g["priority"] == "MEDIUM"),
            "gaps": gaps,
        }

    async def track_compliance_over_time(self, control_id: str, status: ComplianceStatus) -> None:
        """Track compliance status changes over time.

        Args:
            control_id: Control identifier
            status: Current compliance status
        """
        self.audit_data.append(
            {
                "control_id": control_id,
                "status": status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    async def get_compliance_history(self, control_id: str, days: int = 30) -> List[Dict]:
        """Get compliance status history for a control.

        Args:
            control_id: Control identifier
            days: Number of days of history to retrieve

        Returns:
            List of historical compliance status records
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        history = [
            record
            for record in self.audit_data
            if record["control_id"] == control_id
            and datetime.fromisoformat(record["timestamp"]) >= cutoff_date
        ]

        return sorted(history, key=lambda x: x["timestamp"], reverse=True)
