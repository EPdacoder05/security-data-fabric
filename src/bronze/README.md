# Bronze Layer - Data Source Connectors

The Bronze layer provides connectors for ingesting raw data from multiple security and observability platforms.

## Overview

The Bronze layer implements the **Raw Data Ingestion** stage of the Security Data Fabric, fetching events from various sources and storing them in a consistent format without losing any original data.

## Architecture

```
┌─────────────────┐
│  Data Sources   │
│                 │
│  • Dynatrace    │
│  • Splunk       │
│  • ServiceNow   │
│  • PagerDuty    │
│  • GitHub       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Base Connector  │
│  • HTTP Client  │
│  • Retry Logic  │
│  • Metrics      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Schema Registry │
│  • Validation   │
│  • Versioning   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Bronze Events  │
│  (Raw Storage)  │
└─────────────────┘
```

## Connectors

### 1. DynatraceConnector

Connects to Dynatrace API v2 to fetch monitoring data.

**Features:**
- Fetches problems, events, and entities
- Supports Dynatrace entity selectors
- API token authentication
- Automatic pagination

**Usage:**
```python
from src.bronze import DynatraceConnector

connector = DynatraceConnector(
    base_url="https://abc12345.live.dynatrace.com",
    api_token="dt0c01.ABC..."
)

async with connector:
    events = await connector.fetch(
        start_time=datetime.now() - timedelta(hours=1),
        end_time=datetime.now(),
        fetch_problems=True,
        fetch_events=True,
    )
```

**Data Types:**
- Problems (incidents, performance issues)
- Events (deployments, configuration changes)
- Entities (hosts, services, applications)

### 2. SplunkConnector

Connects to Splunk REST API for log and event data.

**Features:**
- Execute SPL searches
- Session key and bearer token authentication
- Async search job management
- Field extraction

**Usage:**
```python
from src.bronze import SplunkConnector

connector = SplunkConnector(
    base_url="https://splunk.example.com:8089",
    username="admin",
    password="changeme"
)

async with connector:
    events = await connector.fetch(
        search_query='index=security sourcetype="notable"',
        max_results=10000
    )
```

**Data Types:**
- Security events
- Notable events
- Search results

### 3. ServiceNowConnector

Connects to ServiceNow Table API for ITSM data.

**Features:**
- Fetches incidents, changes, and CMDB CIs
- OAuth and basic authentication
- Priority to severity mapping
- State filtering

**Usage:**
```python
from src.bronze import ServiceNowConnector

connector = ServiceNowConnector(
    instance="https://dev12345.service-now.com",
    username="integration_user",
    password="password"
)

async with connector:
    events = await connector.fetch(
        fetch_incidents=True,
        fetch_changes=True,
        incident_state="2"  # In Progress
    )
```

**Data Types:**
- Incidents
- Change requests
- CMDB configuration items

### 4. PagerDutyConnector

Connects to PagerDuty REST API v2 for incident management.

**Features:**
- Fetches incidents and on-call schedules
- Service and team filtering
- Status-based filtering
- User assignments

**Usage:**
```python
from src.bronze import PagerDutyConnector

connector = PagerDutyConnector(
    api_key="u+ABC123...",
    from_email="integration@example.com"
)

async with connector:
    events = await connector.fetch(
        fetch_incidents=True,
        fetch_oncalls=True,
        incident_statuses=["triggered", "acknowledged"]
    )
```

**Data Types:**
- Incidents
- On-call schedules
- Services

### 5. GitHubConnector

Connects to GitHub REST API for deployment and CI/CD data.

**Features:**
- Fetches deployments, releases, and workflow runs
- Security vulnerability alerts (Dependabot)
- Token authentication
- Repository filtering

**Usage:**
```python
from src.bronze import GitHubConnector

connector = GitHubConnector(
    token="ghp_ABC123...",
    owner="example-org",
    repo="example-repo"
)

async with connector:
    events = await connector.fetch(
        fetch_deployments=True,
        fetch_releases=True,
        fetch_workflow_runs=True,
        fetch_security_alerts=True
    )
```

**Data Types:**
- Deployments and deployment statuses
- Releases
- GitHub Actions workflow runs
- Security alerts (Dependabot)

## Schema Registry

The Schema Registry provides validation and versioning for Bronze events.

**Features:**
- Pydantic-based validation
- Schema versioning (1.0, 2.0, etc.)
- Batch validation
- JSON schema export

**Usage:**
```python
from src.bronze import schema_registry, EventSource

# Validate single event
is_valid, validated, error = schema_registry.validate_event(event_dict)

# Validate batch
valid_events, errors = schema_registry.validate_batch(event_list)

# Get schema info
info = schema_registry.get_schema_info(EventSource.DYNATRACE)

# Get JSON schema
json_schema = schema_registry.get_json_schema(EventSource.SPLUNK, version="1.0")
```

## Bronze Event Format

All connectors transform source data into a consistent Bronze format:

```python
{
    "source": "dynatrace",           # Source system
    "source_type": "problem",        # Specific event type
    "event_id": "P-123456",          # Unique identifier
    "timestamp": "2024-01-15T10:30:00Z",  # Event time (ISO 8601)
    "severity": "HIGH",              # CRITICAL, HIGH, MEDIUM, LOW, INFO
    "title": "High CPU usage",       # Event summary
    "description": "CPU > 90%",      # Detailed description
    "raw_data": {...},               # Original event (preserved)
    "ingested_at": "2024-01-15T10:30:05Z",  # Ingestion time
    
    # Source-specific fields...
    "impact_level": "SERVICE",
    "affected_entities": [...],
}
```

## Base Connector

All connectors extend `BaseConnector` which provides:

### Features

1. **HTTP Client Management**
   - Async httpx client
   - Connection pooling
   - Timeout handling

2. **Retry Logic**
   - Exponential backoff
   - Configurable attempts
   - Error-specific retries

3. **Metrics**
   - Fetch count
   - Error count/rate
   - Average latency

4. **Error Handling**
   - `ConnectorError` - Base exception
   - `ConnectorConnectionError` - Network issues
   - `ConnectorAuthError` - Authentication failures
   - `ConnectorRateLimitError` - Rate limiting

### Methods

- `connect()` - Establish connection
- `disconnect()` - Close connection
- `health_check()` - Verify connectivity
- `fetch()` - Retrieve events
- `get_metrics()` - Get performance metrics

## Configuration

All connectors read configuration from environment variables via `settings.py`:

```bash
# Dynatrace
DYNATRACE_BASE_URL=https://abc12345.live.dynatrace.com
DYNATRACE_API_TOKEN=dt0c01.ABC...

# Splunk
SPLUNK_BASE_URL=https://splunk.example.com:8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=changeme
SPLUNK_BEARER_TOKEN=...  # Alternative to username/password

# ServiceNow
SERVICENOW_INSTANCE=https://dev12345.service-now.com
SERVICENOW_USERNAME=integration_user
SERVICENOW_PASSWORD=password
SERVICENOW_CLIENT_ID=...  # For OAuth
SERVICENOW_CLIENT_SECRET=...

# PagerDuty
PAGERDUTY_API_KEY=u+ABC123...
PAGERDUTY_FROM_EMAIL=integration@example.com

# GitHub
GITHUB_TOKEN=ghp_ABC123...
```

## Error Handling

Connectors implement comprehensive error handling:

```python
from src.bronze import DynatraceConnector, ConnectorError

connector = DynatraceConnector(...)

try:
    async with connector:
        events = await connector.fetch()
except ConnectorAuthError as e:
    logger.error(f"Authentication failed: {e}")
except ConnectorRateLimitError as e:
    logger.warning(f"Rate limited: {e}")
except ConnectorError as e:
    logger.error(f"Connector error: {e}")
```

## Testing

Run tests with pytest:

```bash
# Run all Bronze layer tests
pytest tests/test_bronze/

# Run specific connector tests
pytest tests/test_bronze/test_connectors.py::TestDynatraceConnector

# Run with coverage
pytest tests/test_bronze/ --cov=src/bronze --cov-report=html
```

## Best Practices

1. **Always use async context managers**
   ```python
   async with connector:
       events = await connector.fetch()
   ```

2. **Implement proper time ranges**
   ```python
   start_time = datetime.now() - timedelta(hours=1)
   end_time = datetime.now()
   events = await connector.fetch(start_time, end_time)
   ```

3. **Validate events before storage**
   ```python
   valid_events, errors = schema_registry.validate_batch(events)
   for idx, error in errors:
       logger.warning(f"Invalid event at index {idx}: {error}")
   ```

4. **Monitor metrics**
   ```python
   metrics = connector.get_metrics()
   logger.info(f"Fetched {metrics['fetch_count']} events, "
               f"error rate: {metrics['error_rate']:.2%}")
   ```

5. **Handle rate limits gracefully**
   - Use exponential backoff (built-in)
   - Implement batch processing
   - Monitor rate limit headers

## Extension

To add a new connector:

1. Create new file in `src/bronze/`:
   ```python
   from src.bronze.base_connector import BaseConnector
   
   class MyConnector(BaseConnector):
       def _get_headers(self) -> Dict[str, str]:
           # Return API headers
           
       async def health_check(self) -> bool:
           # Verify connectivity
           
       async def fetch(self, start_time, end_time, **kwargs):
           # Fetch and transform events
   ```

2. Register schema in `schema_registry.py`:
   ```python
   class MyEventSchema(BronzeEventBase):
       source: EventSource = Field(default="myservice", frozen=True)
       # Add source-specific fields
   
   schema_registry.register_schema("myservice", MyEventSchema, version="1.0")
   ```

3. Update `__init__.py`:
   ```python
   from src.bronze.my_connector import MyConnector
   __all__.append("MyConnector")
   ```

4. Add tests in `tests/test_bronze/`.

## Security

- **NO hardcoded credentials** - All credentials from environment variables
- **Token rotation** - Support for credential refresh
- **TLS/SSL** - HTTPS for all connections
- **Minimal permissions** - Request only needed API scopes
- **Audit logging** - All API calls logged

## Performance

- **Async/await** - Non-blocking I/O
- **Connection pooling** - Reuse HTTP connections
- **Batch processing** - Fetch multiple events per request
- **Pagination** - Handle large result sets efficiently
- **Retry logic** - Automatic retry with backoff

## Monitoring

Track connector performance:

```python
metrics = connector.get_metrics()
# {
#     "connector": "Dynatrace",
#     "fetch_count": 150,
#     "error_count": 2,
#     "error_rate": 0.013,
#     "avg_latency_ms": 245.67
# }
```

## License

See [LICENSE](../../LICENSE) file for details.
