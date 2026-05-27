"""Mock data fixtures for Security Data Fabric testing.

Realistic mock data based on actual production patterns (phq-vm-fin-01 DNS failure scenario).
"""

# ServiceNow mock incidents (4 records)
MOCK_SERVICENOW_INCIDENTS = [
    {
        "number": "INC0087431",
        "short_description": "DNS resolution failure on financial servers",
        "description": (
            "Multiple containers unable to resolve phq-vm-fin-01. "
            "Cascading DNS failures."
        ),
        "priority": "1",
        "state": "2",
        "assigned_to": "john.doe@company.com",
        "opened_at": "2026-02-20T08:30:00Z",
        "resolved_at": None,
        "category": "network",
        "subcategory": "dns",
        "affected_ci": "phq-vm-fin-01",
        "org_name": "Finance",
    },
    {
        "number": "INC0087432",
        "short_description": "Load balancer health checks failing",
        "description": "ALB health checks timing out due to DNS cascading from phq-vm-fin-01.",
        "priority": "2",
        "state": "2",
        "assigned_to": "jane.smith@company.com",
        "opened_at": "2026-02-20T09:00:00Z",
        "resolved_at": None,
        "category": "network",
        "subcategory": "load_balancer",
        "affected_ci": "pex-alb-prod-01",
        "org_name": "Finance",
    },
    {
        "number": "INC0087433",
        "short_description": "OpenSSL CVE-2025-12349 unpatched on 3 finance servers",
        "description": (
            "Critical vulnerability detected on pex-docker-01, "
            "pex-docker-02, pex-docker-03."
        ),
        "priority": "2",
        "state": "1",
        "assigned_to": "sec.team@company.com",
        "opened_at": "2026-02-19T14:00:00Z",
        "resolved_at": None,
        "category": "security",
        "subcategory": "vulnerability",
        "affected_ci": "pex-docker-01",
        "org_name": "Finance",
    },
    {
        "number": "INC0087434",
        "short_description": "Suspicious login attempt from external IP",
        "description": "Failed login attempts detected from 203.0.113.45 targeting admin accounts.",
        "priority": "3",
        "state": "6",
        "assigned_to": "sec.team@company.com",
        "opened_at": "2026-02-18T11:00:00Z",
        "resolved_at": "2026-02-18T13:30:00Z",
        "category": "security",
        "subcategory": "authentication",
        "affected_ci": "vpn-gateway-01",
        "org_name": "IT",
    },
]

# Grafana alert mock data (4 records - based on real phq-vm-fin-01 scenario)
MOCK_GRAFANA_ALERTS = [
    {
        "alertname": "HighDNSResolutionFailureRate",
        "state": "alerting",
        "severity": "critical",
        "summary": "DNS resolution failure rate >50% on finance cluster",
        "description": "phq-vm-fin-01 decommissioned but still referenced in 3 Docker configs",
        "instance": "pex-docker-01:9090",
        "job": "finance-cluster-monitoring",
        "startsAt": "2026-02-20T08:25:00Z",
        "endsAt": None,
        "org_name": "Finance",
        "metric_value": "0.87",
    },
    {
        "alertname": "LoadBalancerHealthCheckFailing",
        "state": "alerting",
        "severity": "high",
        "summary": "ALB health checks failing - cascade from DNS failure",
        "description": (
            "pex-alb-prod-01 cannot reach backend targets due to DNS "
            "resolution failures"
        ),
        "instance": "pex-alb-prod-01:9090",
        "job": "load-balancer-monitoring",
        "startsAt": "2026-02-20T08:35:00Z",
        "endsAt": None,
        "org_name": "Finance",
        "metric_value": "0.0",
    },
    {
        "alertname": "ContainerRestartStorm",
        "state": "alerting",
        "severity": "high",
        "summary": "Container restart rate >10/minute on pex-docker cluster",
        "description": (
            "Docker containers entering crash loop due to DNS-dependent "
            "service failures"
        ),
        "instance": "pex-docker-02:9090",
        "job": "container-monitoring",
        "startsAt": "2026-02-20T08:40:00Z",
        "endsAt": None,
        "org_name": "Finance",
        "metric_value": "15.3",
    },
    {
        "alertname": "OpenSSLVulnerabilityDetected",
        "state": "alerting",
        "severity": "critical",
        "summary": "CVE-2025-12349 detected on 3 production servers",
        "description": (
            "Critical OpenSSL vulnerability on pex-docker-01, 02, 03 "
            "requires immediate patching"
        ),
        "instance": "pex-docker-03:9090",
        "job": "vulnerability-scanning",
        "startsAt": "2026-02-19T14:00:00Z",
        "endsAt": None,
        "org_name": "Finance",
        "metric_value": "9.8",
    },
]

# Microsoft Defender mock incidents (4 records)
MOCK_DEFENDER_INCIDENTS = [
    {
        "incidentId": "DEF-2026-001234",
        "displayName": "Ransomware activity detected on finance workstation",
        "severity": "High",
        "status": "Active",
        "createdTime": "2026-02-21T10:00:00Z",
        "lastUpdateTime": "2026-02-21T10:30:00Z",
        "classification": "TruePositive",
        "category": "Malware",
        "impactedAssets": [{"type": "User", "id": "finance-user-01"}],
        "description": "Suspicious file encryption activity consistent with ransomware behavior",
        "assignedTo": "soc-tier2@company.com",
        "org_name": "Finance",
    },
    {
        "incidentId": "DEF-2026-001235",
        "displayName": "Lateral movement detected - credential theft attempt",
        "severity": "Medium",
        "status": "InProgress",
        "createdTime": "2026-02-20T16:00:00Z",
        "lastUpdateTime": "2026-02-21T08:00:00Z",
        "classification": "TruePositive",
        "category": "CredentialTheft",
        "impactedAssets": [{"type": "Device", "id": "corp-laptop-0234"}],
        "description": "LSASS memory dump detected, possible credential harvesting",
        "assignedTo": "soc-tier1@company.com",
        "org_name": "IT",
    },
    {
        "incidentId": "DEF-2026-001236",
        "displayName": "Suspicious PowerShell execution",
        "severity": "Low",
        "status": "Resolved",
        "createdTime": "2026-02-19T09:00:00Z",
        "lastUpdateTime": "2026-02-19T11:00:00Z",
        "classification": "FalsePositive",
        "category": "SuspiciousActivity",
        "impactedAssets": [{"type": "Device", "id": "dev-workstation-05"}],
        "description": (
            "Encoded PowerShell command flagged - confirmed legitimate "
            "DevOps automation"
        ),
        "assignedTo": "soc-tier1@company.com",
        "org_name": "Engineering",
    },
    {
        "incidentId": "DEF-2026-001237",
        "displayName": "Data exfiltration attempt blocked",
        "severity": "High",
        "status": "Active",
        "createdTime": "2026-02-22T14:00:00Z",
        "lastUpdateTime": "2026-02-22T14:15:00Z",
        "classification": "TruePositive",
        "category": "DataExfiltration",
        "impactedAssets": [{"type": "User", "id": "contractor-user-88"}],
        "description": "Large data transfer to external IP blocked by DLP policy",
        "assignedTo": "soc-tier2@company.com",
        "org_name": "Finance",
    },
]

# USA Today breach news mock data (4 records)
MOCK_USATODAY_BREACHES = [
    {
        "id": "BREACH-2026-0445",
        "title": "Major healthcare provider reports data breach affecting 2.1M patients",
        "published_at": "2026-02-21T12:00:00Z",
        "organization": "HealthFirst Medical Group",
        "industry": "Healthcare",
        "records_affected": 2100000,
        "breach_type": "Ransomware",
        "data_types_exposed": ["PHI", "SSN", "Financial"],
        "cve_exploited": "CVE-2025-12349",
        "attack_vector": "Unpatched OpenSSL vulnerability",
        "source_url": "https://example.com/breach-healthfirst",
        "severity_score": 9.8,
    },
    {
        "id": "BREACH-2026-0446",
        "title": "Regional bank suffers credential stuffing attack",
        "published_at": "2026-02-20T18:00:00Z",
        "organization": "Midwest Community Bank",
        "industry": "Financial Services",
        "records_affected": 45000,
        "breach_type": "CredentialStuffing",
        "data_types_exposed": ["Account Numbers", "PII"],
        "cve_exploited": None,
        "attack_vector": "Reused credentials from previous breach",
        "source_url": "https://example.com/breach-mcb",
        "severity_score": 7.5,
    },
    {
        "id": "BREACH-2026-0447",
        "title": "Tech company discloses supply chain attack via compromised dependency",
        "published_at": "2026-02-19T09:00:00Z",
        "organization": "CloudTech Solutions",
        "industry": "Technology",
        "records_affected": 380000,
        "breach_type": "SupplyChain",
        "data_types_exposed": ["API Keys", "Source Code", "Customer Data"],
        "cve_exploited": "CVE-2025-11872",
        "attack_vector": "Malicious npm package injected into CI/CD pipeline",
        "source_url": "https://example.com/breach-cloudtech",
        "severity_score": 8.9,
    },
    {
        "id": "BREACH-2026-0448",
        "title": "Insurance company reports DNS hijacking incident",
        "published_at": "2026-02-18T15:00:00Z",
        "organization": "SecureLife Insurance",
        "industry": "Insurance",
        "records_affected": 12000,
        "breach_type": "DNSHijacking",
        "data_types_exposed": ["Policy Numbers", "Contact Info"],
        "cve_exploited": None,
        "attack_vector": "DNS infrastructure compromise via decommissioned server references",
        "source_url": "https://example.com/breach-securelife",
        "severity_score": 6.2,
    },
]

# Convenience: all mock data by source
ALL_MOCK_DATA = {
    "servicenow": MOCK_SERVICENOW_INCIDENTS,
    "grafana": MOCK_GRAFANA_ALERTS,
    "defender": MOCK_DEFENDER_INCIDENTS,
    "usatoday": MOCK_USATODAY_BREACHES,
}
