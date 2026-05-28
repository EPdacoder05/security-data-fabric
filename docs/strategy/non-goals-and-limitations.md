# Non-Goals and Limitations

## Purpose
Set clear expectations to prevent scope creep and misaligned delivery commitments.

---

## Non-Goals

This platform is **not** intended to:

- **Replace** ServiceNow, PagerDuty, or Grafana — it sits above them
- **Become a full SIEM** — log ingestion and compliance event management are out of scope unless explicitly added
- **Guarantee prediction** for sudden binary failures with no observable trajectory (e.g., power cut, hard disk failure with no prior SMART data)
- **Eliminate all manual investigation** — the platform reduces, not eliminates, analyst involvement
- **Provide legal or regulatory certification** out of the box — compliance frameworks (SOC2, HIPAA, PCI) require additional controls and evidence collection beyond what is automated here

---

## Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| Predictions require quality/timely metrics | Gaps in source data reduce predictor accuracy | Monitor connector health; alert on ingestion lag |
| Schema changes in source APIs break Silver-layer mappings | Data pipeline stall until mapping updated | Quarterly schema review; integration tests on connector endpoints |
| Cross-source confidence depends on connector completeness | Low coverage = lower correlation quality | Prioritize high-value connectors in pilot scope |
| Executive narrative quality depends on data coverage + RBAC design | Incomplete role mapping degrades view quality | UAT sign-off on role mapping before go-live |
| No real-time streaming (current) | Data freshness up to ~5 min lag | Acceptable for most incident detection use cases; streaming can be added in Phase 8 |

---

## Risk Controls in Place

- Quarantine invalid/malformed records — no silent data loss
- Alert confidence thresholds prevent low-confidence pages
- Chatbot/query layer runs on read-only DB role
- Strong audit logging on all data access and API calls
- Access controlled by 8-level RBAC (no self-escalation)
