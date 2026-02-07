# API Reference

Complete API endpoint documentation for Security Data Fabric.

## Base URL

```
http://localhost:8000
```

## Authentication

Most endpoints require JWT authentication. Include token in header:

```http
Authorization: Bearer <your-jwt-token>
```

Get token from your authentication provider.

## Health & Monitoring

### GET /health

Basic health check.

**Response**: 200 OK
```json
{
  "status": "healthy",
  "timestamp": "2024-02-06T12:00:00Z"
}
```

### GET /ready

Readiness check with database connectivity.

**Response**: 200 OK (ready) or 503 Service Unavailable

## Data Ingestion

### POST /ingest/{source}

Manually ingest an event.

**Parameters**:
- `source` (path): Source name (dynatrace, splunk, servicenow, pagerduty, github)

**Request Body**:
```json
{
  "source_id": "event-123",
  "raw_data": {
    "metric_id": "cpu.usage",
    "value": 85.5
  }
}
```

**Response**: 201 Created

### POST /ingest/github/webhook

GitHub webhook receiver.

**Headers**:
- `X-Hub-Signature-256`: GitHub webhook signature
- `X-GitHub-Event`: Event type

**Request Body**: GitHub webhook payload

**Response**: 200 OK

## Search

### POST /search

Semantic search for events.

**Request Body**:
```json
{
  "query": "CPU spike related to deployment",
  "limit": 10,
  "min_similarity": 0.5,
  "filters": {
    "source": "dynatrace",
    "severity": 4
  }
}
```

**Response**: 200 OK
```json
[
  {
    "event_id": "uuid",
    "score": 0.87,
    "title": "CPU Usage Anomaly",
    "timestamp": "2024-02-06T12:00:00Z",
    "source": "dynatrace",
    "severity": 4
  }
]
```

### GET /search/recent

Get recent events.

**Query Parameters**:
- `limit` (optional): Maximum results (default: 50)
- `hours` (optional): Time window in hours (default: 24)

**Response**: 200 OK - Array of events

### GET /search/similar/{event_id}

Find similar events.

**Parameters**:
- `event_id` (path): Event UUID

**Query Parameters**:
- `limit` (optional): Maximum results (default: 10)

**Response**: 200 OK - Array of similar events

## Predictions

### GET /predictions/active

Get active predictions.

**Query Parameters**:
- `severity` (optional): Filter by severity (1-5)
- `limit` (optional): Maximum results (default: 50)

**Response**: 200 OK
```json
[
  {
    "id": "uuid",
    "prediction_type": "cpu_exhaustion",
    "target_metric": "cpu.usage",
    "current_value": 85.5,
    "predicted_value": 95.0,
    "time_to_breach": 360,
    "confidence": 0.87,
    "severity": 4
  }
]
```

### GET /predictions/history

Get prediction history.

**Query Parameters**:
- `limit` (optional): Maximum results (default: 100)
- `offset` (optional): Pagination offset

**Response**: 200 OK - Array of historical predictions

### GET /predictions/{id}

Get specific prediction.

**Parameters**:
- `id` (path): Prediction UUID

**Response**: 200 OK - Prediction details

## Dashboard

### GET /dashboard/overview

CISO dashboard overview.

**Response**: 200 OK
```json
{
  "total_events": 15234,
  "total_events_24h": 1523,
  "active_incidents": 5,
  "resolved_incidents_24h": 12,
  "active_predictions": 8,
  "critical_predictions": 2,
  "average_risk_score": 35.5,
  "high_risk_assets": 3,
  "top_event_sources": {
    "dynatrace": 6543,
    "splunk": 5432
  },
  "severity_distribution": {
    "critical": 45,
    "high": 123
  }
}
```

### GET /dashboard/risk-scores

Asset risk scores.

**Query Parameters**:
- `min_risk` (optional): Minimum risk score (0-100)
- `limit` (optional): Maximum results

**Response**: 200 OK - Array of asset risk scores

### GET /dashboard/timeline/{incident_id}

Incident timeline.

**Parameters**:
- `incident_id` (path): Incident identifier

**Response**: 200 OK - Timeline details

## Incidents

### GET /incidents

List incidents.

**Query Parameters**:
- `status` (optional): Filter by status (open, closed)
- `severity` (optional): Filter by severity (1-5)
- `limit` (optional): Maximum results
- `offset` (optional): Pagination offset

**Response**: 200 OK
```json
[
  {
    "id": "uuid",
    "incident_id": "INC-2024-001",
    "title": "Production API Degradation",
    "start_time": "2024-02-06T12:00:00Z",
    "end_time": "2024-02-06T12:45:00Z"
  }
]
```

### GET /incidents/{id}/timeline

Detailed incident timeline.

**Parameters**:
- `id` (path): Incident UUID

**Response**: 200 OK
```json
{
  "incident_id": "INC-2024-001",
  "title": "Production API Degradation",
  "start_time": "2024-02-06T12:00:00Z",
  "end_time": "2024-02-06T12:45:00Z",
  "events": [
    {
      "timestamp": "2024-02-06T12:00:00Z",
      "event_type": "deployment",
      "source": "github",
      "description": "Deploy api-service v2.1.0",
      "severity": 2
    },
    {
      "timestamp": "2024-02-06T12:05:00Z",
      "event_type": "metric",
      "source": "dynatrace",
      "description": "CPU spike 45% → 85% (Z=4.2)",
      "severity": 4
    }
  ],
  "root_cause": {
    "event_id": "uuid",
    "description": "Deployment to production",
    "confidence": 0.87
  }
}
```

## Error Responses

All endpoints may return:

### 400 Bad Request
```json
{
  "detail": "Invalid request parameters"
}
```

### 401 Unauthorized
```json
{
  "detail": "Invalid or missing authentication token"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 429 Too Many Requests
```json
{
  "detail": "Rate limit exceeded. Try again in 60 seconds."
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error",
  "request_id": "uuid"
}
```

## Rate Limits

- **Default**: 60 requests/minute per IP
- **Authenticated**: 300 requests/minute per user
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## Pagination

Endpoints supporting pagination use:
- `limit`: Number of results (max: 100)
- `offset`: Skip N results

Response includes:
```json
{
  "data": [...],
  "total": 1523,
  "limit": 50,
  "offset": 0
}
```

## Interactive Documentation

Visit `http://localhost:8000/docs` for interactive Swagger UI documentation.
