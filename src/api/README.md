# Security Data Fabric API Documentation

## Overview

The Security Data Fabric API provides a unified REST interface for security operations, incident management, predictive analytics, and semantic search. Built with FastAPI, it offers high performance, automatic OpenAPI documentation, and production-ready features.

## Base URL

```
http://localhost:8000
```

## Architecture

### Middleware Stack (Outer to Inner)
1. **Security Headers** - HSTS, CSP, X-Frame-Options, etc.
2. **Rate Limiting** - 100 requests per 60 seconds per client
3. **Timing** - Response time tracking
4. **Structured Logging** - JSON logs with request correlation
5. **Request ID** - UUID per request
6. **CORS** - Configurable cross-origin resource sharing

### Dependencies
- **Database**: Async PostgreSQL with pgvector
- **Cache**: Redis for rate limiting and caching
- **ML Models**: Lazy-loaded embedding, anomaly detection, forecasting
- **Authentication**: Optional API key validation

## Quick Start

### Starting the API

```bash
# Development mode with auto-reload
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Interactive Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI Schema**: http://localhost:8000/openapi.json

## Endpoints

### Health & Monitoring

#### `GET /health`
Liveness check - returns 200 if service is running.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-02-07T10:30:00Z",
  "service": "security-data-fabric",
  "version": "0.1.0"
}
```

#### `GET /ready`
Readiness check - verifies dependencies are available.

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2024-02-07T10:30:00Z",
  "checks": {
    "database": "healthy",
    "redis": "healthy"
  },
  "service": "security-data-fabric",
  "version": "0.1.0"
}
```

#### `GET /version`
Version and feature information.

**Response:**
```json
{
  "service": "security-data-fabric",
  "version": "0.1.0",
  "environment": "development",
  "debug": false,
  "features": {
    "ml_predictions": true,
    "semantic_search": true,
    "auto_ticketing": false
  }
}
```

---

### Incident Management

#### `GET /api/v1/incidents`
List incidents with filtering and pagination.

**Query Parameters:**
- `state` (optional): Filter by state (open, acknowledged, resolved, closed)
- `severity` (optional): Filter by severity (info, warning, critical, extreme)
- `service_name` (optional): Filter by service name
- `team` (optional): Filter by team
- `limit` (default: 50, max: 500): Results per page
- `offset` (default: 0): Pagination offset

**Example:**
```bash
curl "http://localhost:8000/api/v1/incidents?state=open&severity=critical&limit=10"
```

**Response:**
```json
[
  {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "incident_number": "INC-000001",
    "title": "Payment Service Outage",
    "severity": "critical",
    "state": "open",
    "service_name": "payment-api",
    "detected_at": "2024-02-07T10:00:00Z",
    "risk_score": 8.5,
    "sla_breached": false
  }
]
```

#### `GET /api/v1/incidents/{incident_id}`
Get detailed information for a specific incident.

**Example:**
```bash
curl http://localhost:8000/api/v1/incidents/123e4567-e89b-12d3-a456-426614174000
```

#### `GET /api/v1/incidents/{incident_id}/timeline`
Get correlated timeline of events related to an incident.

**Query Parameters:**
- `lookback_hours` (default: 24, max: 168): Hours to look back

**Example:**
```bash
curl "http://localhost:8000/api/v1/incidents/123e4567-e89b-12d3-a456-426614174000/timeline?lookback_hours=48"
```

**Response:**
```json
{
  "incident_id": "123e4567-e89b-12d3-a456-426614174000",
  "entries": [
    {
      "timestamp": "2024-02-07T09:50:00Z",
      "event_type": "deployment",
      "source": "github",
      "severity": "info",
      "title": "Deployment: payment-api v2.1.0",
      "service_name": "payment-api"
    },
    {
      "timestamp": "2024-02-07T10:00:00Z",
      "event_type": "error_rate_spike",
      "source": "dynatrace",
      "severity": "critical",
      "title": "Error rate spike detected",
      "service_name": "payment-api"
    }
  ],
  "total_events": 15,
  "time_range": {
    "start": "2024-02-07T08:00:00Z",
    "end": "2024-02-07T10:30:00Z"
  }
}
```

#### `GET /api/v1/incidents/{incident_id}/root-cause`
Perform root cause analysis for an incident.

**Example:**
```bash
curl http://localhost:8000/api/v1/incidents/123e4567-e89b-12d3-a456-426614174000/root-cause
```

**Response:**
```json
{
  "incident_id": "123e4567-e89b-12d3-a456-426614174000",
  "root_cause": "Deployment: payment-api v2.1.0",
  "confidence": 0.92,
  "candidates": [
    {
      "event_id": "...",
      "cause_type": "deployment",
      "confidence": 0.92,
      "title": "Deployment: payment-api v2.1.0",
      "evidence": ["Temporal proximity", "Service correlation"]
    }
  ],
  "analysis_timestamp": "2024-02-07T10:30:00Z"
}
```

#### `POST /api/v1/incidents`
Manually create an incident.

**Request Body:**
```json
{
  "title": "Database connection failures",
  "description": "Multiple services reporting connection timeouts",
  "severity": "critical",
  "service_name": "user-api",
  "team": "platform",
  "tags": {"environment": "production"}
}
```

**Response:** `201 Created` with incident details

---

### ML Predictions

#### `GET /api/v1/predictions`
List predictions with filtering.

**Query Parameters:**
- `prediction_type` (optional): cpu_exhaustion, memory_exhaustion, disk_full, etc.
- `entity_id` (optional): Filter by entity
- `entity_type` (optional): Filter by entity type
- `is_active` (optional): Active predictions only
- `anomaly_only` (optional): Show only anomalies
- `min_confidence` (default: 0.0): Minimum confidence score
- `limit` (default: 50): Results per page
- `offset` (default: 0): Pagination offset

**Example:**
```bash
curl "http://localhost:8000/api/v1/predictions?is_active=true&min_confidence=0.7"
```

#### `GET /api/v1/predictions/active`
Get high-confidence active predictions.

**Query Parameters:**
- `min_confidence` (default: 0.7): Minimum confidence threshold
- `limit` (default: 20): Maximum results

**Example:**
```bash
curl "http://localhost:8000/api/v1/predictions/active?min_confidence=0.8"
```

**Response:**
```json
[
  {
    "id": "...",
    "prediction_type": "cpu_exhaustion",
    "entity_id": "HOST-12345",
    "entity_name": "prod-app-01",
    "current_value": 82.5,
    "predicted_value": 98.0,
    "threshold_value": 90.0,
    "eta_minutes": 45,
    "confidence_score": 0.87,
    "explanation": "CPU usage trending upward, expected to breach threshold",
    "is_active": true
  }
]
```

#### `POST /api/v1/predictions/analyze`
Trigger predictive analysis (async).

**Request Body:**
```json
{
  "entity_ids": ["HOST-12345", "HOST-67890"],
  "lookback_hours": 24
}
```

**Response:** `202 Accepted`
```json
{
  "status": "accepted",
  "message": "Analysis scheduled for 2 entities",
  "entities_analyzed": 2,
  "timestamp": "2024-02-07T10:30:00Z"
}
```

---

### Semantic Search

#### `POST /api/v1/search`
Natural language semantic search across events, incidents, and predictions.

**Request Body:**
```json
{
  "query": "database connection failures in production",
  "max_results": 10,
  "similarity_threshold": 0.5,
  "time_range_hours": 24
}
```

**Example Queries:**
- "Show me all database connection failures in the last 24 hours"
- "What caused the payment service outage?"
- "Find high severity incidents related to authentication"
- "Memory leaks in production environment"

**Response:**
```json
{
  "query": "database connection failures in production",
  "results": [
    {
      "id": "...",
      "result_type": "event",
      "title": "Database connection timeout",
      "description": "Connection to postgres failed after 30s",
      "similarity_score": 0.92,
      "timestamp": "2024-02-07T10:15:00Z",
      "source": "splunk",
      "severity": "critical",
      "service_name": "user-api"
    }
  ],
  "total_results": 5,
  "search_time_ms": 245.8
}
```

---

### Dashboard Analytics

#### `GET /api/v1/dashboard/overview`
CISO dashboard with summary statistics.

**Query Parameters:**
- `hours` (default: 24, max: 168): Time range for metrics

**Example:**
```bash
curl "http://localhost:8000/api/v1/dashboard/overview?hours=24"
```

**Response:**
```json
{
  "timestamp": "2024-02-07T10:30:00Z",
  "time_range_hours": 24,
  "incidents": {
    "total": 15,
    "by_severity": {
      "critical": 3,
      "warning": 8,
      "info": 4
    },
    "by_state": {
      "open": 5,
      "acknowledged": 6,
      "resolved": 4
    }
  },
  "events": {
    "total": 1250,
    "by_severity": {
      "critical": 45,
      "warning": 320,
      "info": 885
    }
  },
  "predictions": {
    "total": 8,
    "active": 5,
    "anomalies": 3
  },
  "top_affected_services": [
    {
      "service_name": "payment-api",
      "incident_count": 4,
      "avg_risk_score": 7.8
    }
  ]
}
```

#### `GET /api/v1/dashboard/risk-trend`
Risk score trends over time.

**Query Parameters:**
- `hours` (default: 168, max: 720): Total time range
- `interval_hours` (default: 24, max: 24): Interval between data points

**Example:**
```bash
curl "http://localhost:8000/api/v1/dashboard/risk-trend?hours=168&interval_hours=24"
```

**Response:**
```json
{
  "time_range_hours": 168,
  "data_points": [
    {
      "timestamp": "2024-02-01T00:00:00Z",
      "avg_risk_score": 6.5,
      "incident_count": 12,
      "high_severity_count": 3
    }
  ],
  "summary": {
    "total_incidents": 84,
    "avg_risk_score": 6.8,
    "total_high_severity": 18,
    "data_point_count": 7
  }
}
```

---

### Data Ingestion

#### `POST /api/v1/ingest/{source}`
Manually ingest an event from a specified source.

**Supported Sources:**
- dynatrace
- splunk
- servicenow
- pagerduty
- github
- custom
- prometheus
- cloudwatch

**Request Body:**
```json
{
  "event_type": "problem",
  "source_id": "PROB-12345",
  "data": {
    "title": "High CPU usage",
    "severity": "CRITICAL",
    "entity": {
      "id": "HOST-ABCD1234",
      "type": "HOST",
      "name": "prod-app-01"
    },
    "timestamp": "2024-02-07T10:30:00Z"
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/v1/ingest/dynatrace \
  -H "Content-Type: application/json" \
  -d '{"event_type": "problem", "data": {...}}'
```

**Response:** `202 Accepted`
```json
{
  "status": "accepted",
  "message": "Event accepted for processing from dynatrace",
  "event_id": "...",
  "source": "dynatrace",
  "timestamp": "2024-02-07T10:30:00Z"
}
```

#### `POST /api/v1/ingest/{source}/batch`
Ingest multiple events in a batch (max 100).

**Request Body:**
```json
[
  {
    "event_type": "log_error",
    "data": {...}
  },
  {
    "event_type": "metric_threshold",
    "data": {...}
  }
]
```

**Response:** `202 Accepted`
```json
{
  "status": "accepted",
  "message": "Batch of 25 events accepted for processing",
  "source": "splunk",
  "event_count": 25,
  "timestamp": "2024-02-07T10:30:00Z"
}
```

---

## Authentication

API key authentication is optional. To enable:

```bash
# Set environment variable
export API_KEY_HEADER="X-API-Key"

# Include in requests
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/incidents
```

---

## Rate Limiting

Default rate limit: **100 requests per 60 seconds per client IP**

When rate limited, you'll receive:
- Status: `429 Too Many Requests`
- Header: `Retry-After: 60`

---

## Error Handling

All errors include:
```json
{
  "error": "Error message",
  "request_id": "uuid",
  "path": "/api/v1/endpoint"
}
```

**Common Status Codes:**
- `200 OK` - Success
- `201 Created` - Resource created
- `202 Accepted` - Async operation accepted
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service/feature disabled

---

## Pagination

List endpoints support pagination:
- `limit`: Results per page (max varies by endpoint)
- `offset`: Number of results to skip

**Example:**
```bash
# Get first 50 results
curl "http://localhost:8000/api/v1/incidents?limit=50&offset=0"

# Get next 50 results
curl "http://localhost:8000/api/v1/incidents?limit=50&offset=50"
```

---

## Headers

### Request Headers
- `Content-Type: application/json` - For POST/PUT requests
- `X-API-Key: <key>` - Optional API key authentication

### Response Headers
- `X-Request-ID` - Unique request identifier
- `X-Process-Time` - Request processing time in seconds
- `Content-Type: application/json`
- Security headers (HSTS, CSP, etc.)

---

## Configuration

Key environment variables:

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/db

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
API_KEY_HEADER=X-API-Key
CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# Features
ENABLE_ML_PREDICTIONS=true
ENABLE_SEMANTIC_SEARCH=true
ENABLE_AUTO_TICKETING=false

# ML Configuration
ML_CONFIDENCE_THRESHOLD=0.7
ML_ANOMALY_THRESHOLD=3.0
```

---

## Production Deployment

### Using Uvicorn

```bash
uvicorn src.api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level info \
  --access-log
```

### Using Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Health Checks

Configure orchestrator health checks:
- **Liveness**: `GET /health` (interval: 10s)
- **Readiness**: `GET /ready` (interval: 30s, initial delay: 10s)

---

## Monitoring & Observability

### Structured Logging
All logs are in JSON format:
```json
{
  "timestamp": "2024-02-07T10:30:00Z",
  "level": "INFO",
  "logger": "src.api.routes.incidents",
  "message": "Retrieved 15 incidents",
  "request_id": "uuid"
}
```

### Metrics
Request timing available in `X-Process-Time` header.

### Tracing
Request correlation via `X-Request-ID` header.

---

## Best Practices

1. **Always check health before deployment**: `GET /ready`
2. **Use pagination for large result sets**
3. **Include request ID in support requests**
4. **Monitor rate limits in production**
5. **Enable API key authentication in production**
6. **Use semantic search for complex queries**
7. **Check feature flags via `/version` endpoint**
8. **Handle 503 errors when features are disabled**

---

## Support & Resources

- **Interactive Docs**: http://localhost:8000/docs
- **OpenAPI Schema**: http://localhost:8000/openapi.json
- **GitHub**: [Security Data Fabric Repository]
- **Issues**: Report via GitHub Issues
