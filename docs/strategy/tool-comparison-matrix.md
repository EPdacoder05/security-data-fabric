# Tool Comparison Matrix

## Context
Side-by-side comparison of three investigation and alerting paths:

1. **Grafana Manual** — current state; operator-driven threshold alerting
2. **Datadog Enterprise** — commercial observability platform
3. **Combined Stack** — Security Data Fabric + Incident Predictor

---

## Comparison

| Capability | Grafana Manual | Datadog Enterprise | Combined Stack |
|---|---|---|---|
| **Detection** | Threshold/manual signal only | Threshold + anomaly surfacing | Predictive anomaly detection (trajectory-aware) |
| **Root-cause investigation** | Human-driven; may require re-investigation | Better telemetry; operator-driven correlation | Pre-computed cross-source graph correlation |
| **Second investigation needed?** | Often yes | Sometimes | Designed to minimize |
| **Historical context** | Limited cross-tool continuity | Better within platform | Cross-source semantic + relational history |
| **Alert routing** | Policy-driven; often broad | Route-capable | Context-aware routing to likely owning team |
| **ServiceNow auto-update** | Manual unless separately integrated | Requires separate integration | Built-in workflow target (auto-create/update) |
| **CISO/Director view** | Not primary design goal | Dashboards require training | Traffic-light + narrative outputs, board-ready |
| **Predictive capability** | Basic threshold/alerting | Watchdog-style anomaly detection | Forecast + confidence + trend extrapolation |
| **Estimated annual cost** | Low incremental | ~new enterprise contract | ~program envelope, using existing cloud estate |
| **What you still don't get** | No automated cross-source RCA | No guaranteed ITSM + executive narrative layer | Requires connector credentials + baseline period |

---

## Bottom Line

The combined stack is positioned as **predictive + correlation + executive intelligence** — not just observability.

It does not replace Grafana, Datadog, ServiceNow, or PagerDuty. It sits above them to surface signal that no single tool exposes on its own.

---

## Decision Criteria

| If you need... | Recommended path |
|---|---|
| Cost-minimal alerting only | Grafana Manual |
| Full observability with vendor support | Datadog Enterprise |
| Predictive detection + RCA + exec narrative + ITSM automation | Combined Stack |
