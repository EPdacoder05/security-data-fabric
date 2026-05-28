# Deployment Logistics Runbook

## Purpose
Operational checklist for moving from code-complete to production-ready.

---

## Phase 0 — Pre-Flight

- [ ] Confirm pilot scope (systems, teams, KPI owner)
- [ ] Confirm AWS account/region and budget tag assignments
- [ ] Confirm ServiceNow/Grafana/PagerDuty credentials are available and scoped
- [ ] Confirm OIDC provider config (Azure AD/Okta client ID, callback URIs)
- [ ] Confirm incident escalation policy mapping with PagerDuty owner
- [ ] Confirm deployment lane ownership with DevOps/Platform

---

## Phase 1 — Environment Bring-Up

- [ ] Terraform apply for `dev` — no errors
- [ ] Build and push container images to ECR
- [ ] ECS services show healthy task count
- [ ] DB migrations complete (`alembic upgrade head`)
- [ ] Health checks pass (`/health`, `/metrics`)

---

## Phase 2 — Integration Wiring

- [ ] ServiceNow connector validated (read scope; confirm write/update scope if approved)
- [ ] Grafana/OpenSearch ingestion validated (historical pull window confirmed)
- [ ] PagerDuty route tests validated (alert → route → team mapping confirmed)
- [ ] Baseline data ingestion running through Bronze → Silver → Gold layers

---

## Phase 3 — Security + Governance

- [ ] All secrets in AWS Secrets Manager (zero plaintext in env or config)
- [ ] IAM policy review complete (least privilege per service)
- [ ] TLS certificates installed; rotation policy documented
- [ ] Audit logging validated (write path + read path coverage)
- [ ] Data retention policy validated (CloudWatch logs, RDS snapshots, S3)

---

## Phase 4 — Pilot Execution

- [ ] 30-day baseline period locked and KPI owner confirmed
- [ ] Predictor alert threshold tuned (default: 80% confidence)
- [ ] On-call playbook reviewed and signed off
- [ ] Director/CISO dashboard reviewed and signed off

---

## Phase 5 — Production Cutover

- [ ] Stage soak test complete (minimum 72-hour clean run)
- [ ] Prod Terraform apply complete — no drift
- [ ] Rollout window approved and communicated
- [ ] Hypercare schedule staffed (first 2 weeks; daily check-in)
- [ ] KPI reporting started (weekly cadence from week 1)

---

## Rollback Procedure

1. ECS: roll back task definition to previous revision via console or CLI
2. DB: restore from latest RDS snapshot (RPO depends on backup frequency)
3. Connectors: disable polling jobs in ECS; ServiceNow write scope can be revoked independently
4. Notify KPI owner and incident management lead of rollback and root cause

---

## Contacts

| Role | Responsibility |
|---|---|
| Platform/DevOps | IaC execution, ECR, ECS |
| Security Engineering | Auth, secrets, IAM policy review |
| ITSM Owner | ServiceNow workflow approvals |
| Incident Management | PagerDuty routing validation |
| KPI Owner | Baseline lock, pilot outcome reporting |
