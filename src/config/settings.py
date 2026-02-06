"""Configuration settings for Security Data Fabric."""
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://sdf_user:sdf_password@localhost:5432/sdf_db",
        description="Database connection URL",
    )
    database_pool_size: int = Field(default=20, description="Database connection pool size")
    database_max_overflow: int = Field(default=10, description="Max database connections overflow")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # API
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_workers: int = Field(default=4, description="Number of API workers")
    api_reload: bool = Field(default=False, description="Enable auto-reload")
    log_level: str = Field(default="INFO", description="Logging level")

    # Security
    jwt_secret_key: str = Field(default="change-me-in-production", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_minutes: int = Field(default=60, description="JWT token expiration")

    # Dynatrace
    dynatrace_url: Optional[str] = Field(default=None, description="Dynatrace environment URL")
    dynatrace_api_token: Optional[str] = Field(default=None, description="Dynatrace API token")
    dynatrace_poll_interval: int = Field(default=60, description="Dynatrace polling interval")

    # Splunk
    splunk_url: Optional[str] = Field(default=None, description="Splunk instance URL")
    splunk_token: Optional[str] = Field(default=None, description="Splunk API token")
    splunk_index: str = Field(default="security", description="Splunk index name")

    # ServiceNow
    servicenow_url: Optional[str] = Field(default=None, description="ServiceNow instance URL")
    servicenow_username: Optional[str] = Field(default=None, description="ServiceNow username")
    servicenow_password: Optional[str] = Field(default=None, description="ServiceNow password")

    # PagerDuty
    pagerduty_api_key: Optional[str] = Field(default=None, description="PagerDuty API key")
    pagerduty_integration_key: Optional[str] = Field(
        default=None, description="PagerDuty integration key"
    )

    # GitHub
    github_webhook_secret: Optional[str] = Field(default=None, description="GitHub webhook secret")

    # Slack
    slack_webhook_url: Optional[str] = Field(default=None, description="Slack webhook URL")

    # ML Configuration
    anomaly_warning_threshold: float = Field(
        default=1.5, description="Anomaly warning threshold (Z-score)"
    )
    anomaly_critical_threshold: float = Field(
        default=3.0, description="Anomaly critical threshold (Z-score)"
    )
    anomaly_extreme_threshold: float = Field(
        default=4.5, description="Anomaly extreme threshold (Z-score)"
    )
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2", description="Embedding model name"
    )
    embedding_dimension: int = Field(default=384, description="Embedding vector dimension")

    # Correlation
    correlation_window_minutes: int = Field(
        default=30, description="Correlation time window in minutes"
    )

    # Alerting
    alert_cooldown_minutes: int = Field(
        default=15, description="Alert cooldown period in minutes"
    )


# Global settings instance
settings = Settings()
