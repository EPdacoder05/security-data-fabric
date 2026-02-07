# Integration Guide

Step-by-step guide for integrating data sources with Security Data Fabric.

## Prerequisites

- SDF instance running (via Docker Compose or deployed)
- API access credentials
- Source system credentials

## General Integration Steps

1. Obtain API credentials from source system
2. Configure environment variables
3. Test connectivity
4. Configure polling/webhooks
5. Verify data ingestion

## Dynatrace Integration

### 1. Generate API Token

1. Log in to Dynatrace
2. Go to **Settings → Integration → Dynatrace API**
3. Generate token with permissions:
   - `metrics.read`
   - `problems.read`
   - `entities.read`
4. Copy token

### 2. Configure SDF

```bash
# Add to .env
DYNATRACE_URL=https://your-environment.live.dynatrace.com
DYNATRACE_API_TOKEN=dt0c01.ABC123...
DYNATRACE_POLL_INTERVAL=60
```

### 3. Test Connection

```bash
curl -X GET http://localhost:8000/connectors/dynatrace/health
```

### 4. Data Collected

- Host metrics (CPU, memory, disk, network)
- Application metrics
- Problems (incidents)
- Entity relationships

## Splunk Integration

### 1. Generate Token

1. Log in to Splunk
2. Go to **Settings → Tokens**
3. Create new token
4. Copy token

### 2. Configure SDF

```bash
# Add to .env
SPLUNK_URL=https://your-splunk.com:8089
SPLUNK_TOKEN=your-token
SPLUNK_INDEX=security
```

### 3. Configure Search Query

Default query: `search index=security`

Customize in API call:
```json
{
  "query": "search index=security sourcetype=access_combined error"
}
```

### 4. Data Collected

- Security logs
- Application logs
- Access logs
- Custom search results

## ServiceNow Integration

### 1. Create Integration User

1. Create dedicated user: `sdf_integration`
2. Assign roles:
   - `itil`
   - `rest_api_explorer`

### 2. Configure SDF

```bash
# Add to .env
SERVICENOW_URL=https://your-instance.service-now.com
SERVICENOW_USERNAME=sdf_integration
SERVICENOW_PASSWORD=your-password
```

### 3. Test Connection

```bash
curl -X GET http://localhost:8000/connectors/servicenow/health
```

### 4. Data Collected

- Incidents
- Change requests
- CMDB configuration items
- Problem records

## PagerDuty Integration

### 1. Generate API Key

1. Go to **Integrations → API Access Keys**
2. Create new key (read-write)
3. Copy key

### 2. Generate Integration Key

1. Go to **Services**
2. Select service
3. Add integration → **API v2**
4. Copy integration key

### 3. Configure SDF

```bash
# Add to .env
PAGERDUTY_API_KEY=your-api-key
PAGERDUTY_INTEGRATION_KEY=your-integration-key
```

### 4. Data Collected

- Incidents
- Alert events
- On-call schedules
- Escalation policies

## GitHub Webhooks

### 1. Configure Webhook

1. Go to repository **Settings → Webhooks**
2. Add webhook:
   - **Payload URL**: `https://your-sdf.com/ingest/github/webhook`
   - **Content type**: `application/json`
   - **Secret**: Generate strong secret
   - **Events**: Select:
     - Deployments
     - Pushes
     - Pull requests

### 2. Configure SDF

```bash
# Add to .env
GITHUB_WEBHOOK_SECRET=your-webhook-secret
```

### 3. Test Webhook

Send test delivery from GitHub webhook settings.

### 4. Data Collected

- Deployment events
- Push events
- Pull request merges
- Repository activity

## Slack Notifications (Outbound)

### 1. Create Incoming Webhook

1. Go to **https://api.slack.com/apps**
2. Create new app
3. Enable **Incoming Webhooks**
4. Add webhook to workspace
5. Copy webhook URL

### 2. Configure SDF

```bash
# Add to .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### 3. Test Alert

```bash
curl -X POST http://localhost:8000/alerts/test \
  -H "Content-Type: application/json" \
  -d '{"destination": "slack"}'
```

## Verification Checklist

After integrating each source:

- [ ] Health check returns 200 OK
- [ ] Events appear in Bronze layer (`GET /events/raw`)
- [ ] Events normalized in Silver layer
- [ ] Events enriched in Gold layer
- [ ] Search returns results
- [ ] Dashboard shows new data source

## Troubleshooting

### Connection Timeouts

```bash
# Increase timeout in connector
CONNECTOR_TIMEOUT=60
```

### Rate Limiting

```bash
# Adjust rate limits
DYNATRACE_RATE_LIMIT=120  # requests per minute
```

### SSL Certificate Errors

```bash
# For testing only - disable SSL verification
SSL_VERIFY=false
```

**Production**: Install proper certificates

### Authentication Errors

1. Verify credentials are correct
2. Check user permissions
3. Verify token hasn't expired
4. Check firewall rules

### No Data Ingested

1. Check connector logs: `docker-compose logs app`
2. Verify query/filter settings
3. Check source system has data
4. Verify time zone settings

## Monitoring Integration Health

### Dashboard

```bash
GET /dashboard/connectors
```

Response shows:
- Connector status
- Last successful fetch
- Error rate
- Events ingested (24h)

### Metrics

```bash
GET /metrics
```

Key metrics:
- `connector_dynatrace_events_ingested`
- `connector_dynatrace_errors`
- `connector_dynatrace_fetch_duration`

## Best Practices

1. **Use dedicated service accounts** - Don't use personal accounts
2. **Rotate credentials regularly** - Every 90 days
3. **Least privilege** - Only grant necessary permissions
4. **Monitor error rates** - Alert on high error rates
5. **Test in staging first** - Verify integration before production
6. **Document customizations** - Track any custom queries or filters

## Advanced Configuration

### Custom Metric Selectors (Dynatrace)

```python
# In API call
{
  "metric_selectors": [
    "builtin:host.cpu.usage",
    "builtin:service.response.time",
    "builtin:apps.web.actionCount.load"
  ]
}
```

### Custom Splunk Queries

```python
# In API call
{
  "query": "search index=security earliest=-1h | stats count by source",
  "earliest_time": "-1h",
  "latest_time": "now"
}
```

### ServiceNow Custom Tables

```python
# In API call
{
  "table": "problem",
  "query": "active=true^priority<=2"
}
```

## Support

For integration issues:
1. Check logs: `docker-compose logs -f app`
2. Review API documentation: http://localhost:8000/docs
3. Open GitHub issue with:
   - Source system
   - Error message
   - Configuration (redact credentials)
