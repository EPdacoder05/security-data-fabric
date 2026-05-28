# Cost Model — Security Data Fabric + Incident Predictor

## Purpose
Provide a transparent cost model for planning, approvals, and executive review.

## Cost Summary

### Base Case (expected steady-state)
- **Monthly:** ~$704
- **Annual:** ~$8,448

### Peak/Storm Case (incident-heavy months)
- **Monthly:** up to ~$1,200
- **Annualized worst-month equivalent:** ~$12,000

### Budgeted Program Ask (includes delivery/risk buffer + ops overhead)
- **Annual program envelope:** ~$35,000

---

## Cost Components (Estimated)

| Component | Monthly (Base) | Monthly (Peak) | Notes |
|---|---:|---:|---|
| ECS/Fargate compute (API + jobs + predictor) | $50 | $250 | Scales with load and polling intensity |
| RDS PostgreSQL (with pgvector, Multi-AZ) | $120 | $220 | Storage + IOPS growth in peak |
| Redis/ElastiCache | $15 | $40 | Session/cache + rate limiting |
| ALB + data processing | $25 | $70 | Request volume dependent |
| CloudWatch logs/metrics | $30 | $120 | Higher during incident storms |
| S3 backup/snapshots | $20 | $60 | Retention + versioning |
| KMS/API security services | $10 | $25 | Key operations + encryption |
| Data transfer | $40 | $120 | Cross-AZ/API egress variability |
| AI usage (Bedrock/OpenAI fallback) | $5–$10 | $40 | 95% template SQL, 5% AI fallback |
| Contingency buffer | $389 | $255 | Covers unknowns |

**Base total:** ~$704/mo  
**Peak total:** up to ~$1,200/mo

---

## Why Program Ask Is Higher Than Infra Baseline

The $35K/year is not just cloud infra. It includes:

1. Incremental cloud + integration overhead
2. Security hardening and compliance evidence
3. Connector maintenance + schema drift handling
4. On-call readiness and production operations
5. Delivery risk buffer and change management

---

## Pricing Positioning (Executive)

- Comparable observability-only enterprise spend can approach ~$36K/year
- This stack includes:
  - Predictive detection
  - Cross-source graph correlation
  - ServiceNow/PagerDuty automation
  - Executive/CISO reporting layer

---

## Cost Governance

- Monthly budget alert at **80%**, hard alert at **95%**
- Tagging strategy:
  - `CostCenter=SecurityFabric`
  - `Env=prod|stage|dev`
  - `Service=sdf-api|predictor|etl|db`
- Monthly cost review in operations cadence
