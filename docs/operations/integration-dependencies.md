# Integration Dependencies

## Overview
Lists all external systems, their required access scopes, and ownership contacts needed to bring the Security Data Fabric into production.

---

## External Systems

### 1. ServiceNow
- **Access:** REST API (basic auth or OAuth 2.0)
- **Tables:** `incident`, `change_request`, `cmdb_ci`
- **Minimum scope:** Read (incident + change records)
- **Optional scope:** Write/update (auto-create and auto-update incident records)
- **Owner:** ITSM Platform Team
- **Risk:** Approval for write scope may require change-board sign-off

### 2. Grafana / OpenSearch
- **Access:** Grafana HTTP API (API token) or OpenSearch REST
- **Data:** Metrics, events, alert history
- **Historical pull:** Configurable window (default: 30 days)
- **Owner:** Platform Observability Team
- **Risk:** Large historical pulls may hit API rate limits; schedule during off-peak

### 3. PagerDuty
- **Access:** PagerDuty API (API token)
- **Scope:** Read incidents/alerts; write for auto-escalation (if enabled)
- **Routing keys:** One per service/team mapping
- **Owner:** Incident Management Team
- **Risk:** Escalation policy changes must be coordinated to avoid duplicate pages

### 4. Identity Provider (Azure AD / Okta)
- **Access:** OIDC / OAuth 2.0
- **Required:** Client ID, client secret, PKCE settings, callback URIs
- **Group-to-role mapping:** Must align with 8-level RBAC model
- **Owner:** Identity & Access Management Team
- **Risk:** Role mapping mismatches can block analyst/responder access at launch

---

## Dependency Owners

| Dependency | Owner | Approval Required |
|---|---|---|
| ServiceNow API credentials | ITSM Platform | Yes — write scope requires CAB |
| Grafana/OpenSearch token | Platform Observability | Standard request |
| PagerDuty API + routing keys | Incident Management | Standard request |
| OIDC client config | IAM Team | Standard request |
| AWS deployment lane | DevOps/Platform | Yes — prod Terraform execution |

---

## Dependency Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Credential approval delays | Medium | Request all credentials in Week 1 of pilot |
| API throttling on historical pull | Medium | Rate-limited polling with exponential backoff |
| Schema drift in source APIs | Low-Medium | Silver-layer mapping reviewed quarterly |
| Role mapping mismatches | Medium | UAT sign-off before prod cutover |
| Write scope denial (ServiceNow) | Low | Platform operates read-only if not approved; auto-update deferred |
