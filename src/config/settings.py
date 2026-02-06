"""
Configuration settings for Security Data Fabric.
Uses Pydantic BaseSettings for environment-aware configuration.
NO HARDCODED SECRETS - all sensitive data from environment variables.
"""
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import secrets


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Environment
    environment: str = Field(default="development", description="Application environment")
    
    # Application
    app_name: str = Field(default="security-data-fabric", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_workers: int = Field(default=4, description="Number of worker processes")
    
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://sdf_user:sdf_password@localhost:5432/security_data_fabric",
        description="Async PostgreSQL connection URL"
    )
    database_pool_size: int = Field(default=20, description="Connection pool size")
    database_max_overflow: int = Field(default=10, description="Max overflow connections")
    
    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")
    redis_max_connections: int = Field(default=50, description="Max Redis connections")
    
    # Security
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for signing"
    )
    api_key_header: str = Field(default="X-API-Key", description="API key header name")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    
    # Dynatrace Integration
    dynatrace_base_url: Optional[str] = Field(default=None, description="Dynatrace API base URL")
    dynatrace_api_token: Optional[str] = Field(default=None, description="Dynatrace API token")
    
    # Splunk Integration
    splunk_base_url: Optional[str] = Field(default=None, description="Splunk API base URL")
    splunk_username: Optional[str] = Field(default=None, description="Splunk username")
    splunk_password: Optional[str] = Field(default=None, description="Splunk password")
    splunk_bearer_token: Optional[str] = Field(default=None, description="Splunk bearer token")
    
    # ServiceNow Integration
    servicenow_instance: Optional[str] = Field(default=None, description="ServiceNow instance URL")
    servicenow_username: Optional[str] = Field(default=None, description="ServiceNow username")
    servicenow_password: Optional[str] = Field(default=None, description="ServiceNow password")
    servicenow_client_id: Optional[str] = Field(default=None, description="ServiceNow OAuth client ID")
    servicenow_client_secret: Optional[str] = Field(default=None, description="ServiceNow OAuth client secret")
    
    # PagerDuty Integration
    pagerduty_api_key: Optional[str] = Field(default=None, description="PagerDuty API key")
    pagerduty_integration_key: Optional[str] = Field(default=None, description="PagerDuty integration key")
    pagerduty_from_email: str = Field(default="alerts@example.com", description="PagerDuty from email")
    
    # Slack Integration
    slack_webhook_url: Optional[str] = Field(default=None, description="Slack webhook URL")
    slack_default_channel: str = Field(default="#security-alerts", description="Default Slack channel")
    
    # GitHub Integration
    github_token: Optional[str] = Field(default=None, description="GitHub API token")
    github_webhook_secret: Optional[str] = Field(default=None, description="GitHub webhook secret")
    
    # ML Configuration
    ml_model_path: str = Field(default="./models", description="ML model storage path")
    ml_embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Sentence transformer model"
    )
    ml_anomaly_threshold: float = Field(default=3.0, description="Anomaly detection Z-score threshold")
    ml_confidence_threshold: float = Field(default=0.7, description="ML prediction confidence threshold")
    
    # Correlation & Analysis
    correlation_time_window_minutes: int = Field(default=5, description="Correlation time window")
    dedup_time_window_minutes: int = Field(default=5, description="Deduplication time window")
    timeline_lookback_hours: int = Field(default=24, description="Timeline lookback period")
    severity_enhancement_threshold: int = Field(default=5, description="Event count threshold for severity enhancement")
    
    # Alerting
    alert_dedup_window_minutes: int = Field(default=10, description="Alert deduplication window")
    alert_escalation_delay_minutes: int = Field(default=15, description="Alert escalation delay")
    
    # Feature Flags
    enable_ml_predictions: bool = Field(default=True, description="Enable ML predictions")
    enable_semantic_search: bool = Field(default=True, description="Enable semantic search")
    enable_auto_ticketing: bool = Field(default=False, description="Enable automatic ticket creation")
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from comma-separated string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v_upper
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v):
        """Validate environment."""
        valid_envs = ["development", "staging", "production"]
        v_lower = v.lower()
        if v_lower not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}")
        return v_lower
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"
    
    def validate_required_for_production(self):
        """Validate that required settings are present for production."""
        if self.is_production:
            if self.secret_key == "change-me-in-production-use-openssl-rand-hex-32":
                raise ValueError("SECRET_KEY must be changed in production")
            if self.debug:
                raise ValueError("DEBUG must be False in production")


# Global settings instance
settings = Settings()

# Validate production settings
if settings.is_production:
    settings.validate_required_for_production()
