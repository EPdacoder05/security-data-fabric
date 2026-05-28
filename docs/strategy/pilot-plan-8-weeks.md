# Pilot Plan — 8 Weeks

## Objective
Move from zero to production-ready in 8 weeks with validated KPIs and executive sign-off.

---

## Timeline

### Weeks 1–2 — Non-Prod Deploy + First Demo
- Deploy non-prod stack (Terraform `dev`)
- Validate connectors with controlled/synthetic data
- Deliver first live demo: chatbot query + executive indicator view
- Confirm baseline KPI owner and 30-day baseline start

### Weeks 3–4 — Live Connectors + Baseline Lock
- Enable live ServiceNow / Grafana / PagerDuty ingestion
- Lock 30-day baseline metrics (MTTD, MTTR, MI volume)
- Begin early KPI instrumentation
- Tune predictor confidence threshold (default: 80%)

### Weeks 5–6 — Hardening + Validation
- Production security hardening (IAM review, secrets audit, TLS)
- Pen-test / security validation pass
- Operational runbook rehearsal with on-call team
- Stage soak test (72-hour clean run target)

### Weeks 7–8 — Production Rollout + Hypercare
- Production Terraform apply
- Hypercare: daily check-ins, on-call staffed
- KPI weekly reporting starts
- Executive readout with early outcome data

---

## Entry Criteria

| Criterion | Owner |
|---|---|
| API credentials approved and available | ITSM + Observability + IAM teams |
| DevOps deployment lane confirmed | Platform/DevOps |
| Named KPI owner assigned | Program sponsor |
| Pager escalation policy mapping agreed | Incident Management |

---

## Exit Criteria

| Criterion | Validation |
|---|---|
| Stable ingestion (Bronze → Silver → Gold) | No pipeline errors for 72+ hours |
| Alert-to-owner routing validated | End-to-end test with PagerDuty team |
| ServiceNow automation validated | Auto-create/update confirmed (or deferred if write scope not approved) |
| KPI dashboard live | Director/CISO sign-off |
| Production-readiness scorecard complete | Week 8 review |

---

## Success Scorecard

| KPI | Baseline (Day 0) | Target (Day 90) |
|---|---|---|
| MTTD | Measured | -70% reduction (detectable trajectories) |
| MTTR | Measured | Materially reduced |
| Major incident duration | Measured | -15% |
| Pager response time | Measured | <3 min average |
| Audit prep effort | Measured | -50% |
| Predictor false positive rate | — | <10% |
