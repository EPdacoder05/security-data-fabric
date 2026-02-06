"""Bronze layer: Raw data ingestion from multiple sources."""

from src.bronze.base_connector import (
    BaseConnector,
    ConnectorError,
    ConnectorConnectionError,
    ConnectorAuthError,
    ConnectorRateLimitError,
)
from src.bronze.dynatrace_connector import DynatraceConnector
from src.bronze.splunk_connector import SplunkConnector
from src.bronze.servicenow_connector import ServiceNowConnector
from src.bronze.pagerduty_connector import PagerDutyConnector
from src.bronze.github_connector import GitHubConnector
from src.bronze.schema_registry import (
    SchemaRegistry,
    schema_registry,
    validate_event,
    validate_batch,
    EventSeverity,
    EventSource,
    BronzeEventBase,
    DynatraceEventSchema,
    SplunkEventSchema,
    ServiceNowEventSchema,
    PagerDutyEventSchema,
    GitHubEventSchema,
)

__all__ = [
    # Base classes and exceptions
    "BaseConnector",
    "ConnectorError",
    "ConnectorConnectionError",
    "ConnectorAuthError",
    "ConnectorRateLimitError",
    # Connectors
    "DynatraceConnector",
    "SplunkConnector",
    "ServiceNowConnector",
    "PagerDutyConnector",
    "GitHubConnector",
    # Schema registry
    "SchemaRegistry",
    "schema_registry",
    "validate_event",
    "validate_batch",
    # Schema models
    "EventSeverity",
    "EventSource",
    "BronzeEventBase",
    "DynatraceEventSchema",
    "SplunkEventSchema",
    "ServiceNowEventSchema",
    "PagerDutyEventSchema",
    "GitHubEventSchema",
]
