# ROI and Incident Economics

## Objective
Quantify financial impact reduction from earlier detection and faster root-cause identification.

## Incident Cost Framework

For each major incident, estimate:

1. **Productivity Loss** = impacted users × downtime hours × loaded hourly rate
2. **Engineering Response** = responders × response/recovery hours × loaded hourly rate
3. **Escalation Overhead** = bridge time + management coordination
4. **Risk/Compliance Buffer** = SLA/reputation/compliance impact

### Example Conservative Incident

| Factor | Estimate |
|---|---|
| Productivity loss | $21,000 |
| Engineering response | $5,440 |
| Risk/SLA/compliance | $5,000–$15,000 |
| **Total** | **~$42K–$50K** |

---

## Value Thesis

If the platform prevents or materially reduces even **1 major incident/year**, it can offset the full annual program spend.

---

## KPI Targets (90-day post go-live)

| KPI | Baseline | Target |
|---|---|---|
| MTTD | ~4.2 hours | 6–20 min (detectable trajectories) |
| MTTR | ~45 minutes | Materially reduced via pre-correlated root-cause graph |
| Major incident duration | Current | -15% |
| Pager response time | Current | <3 min average |
| Audit prep effort | Current | -50% |

---

## Baseline Requirement (Before Pilot)

Capture 30 days of:

- ServiceNow incident open/resolve timestamps
- PagerDuty response time
- MI volume/severity breakdown
- Audit prep effort (self-reported/team-tracked)

---

## Reporting Cadence

| Milestone | Deliverable |
|---|---|
| Week 2 | First demo metrics |
| Week 4 | Initial live connector metrics |
| Week 8 | Production-readiness scorecard |
| Day 90 | ROI outcome review |
