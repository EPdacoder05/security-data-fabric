"""Application configuration using Pydantic Settings."""

from typing import List, Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Application
    environment: Literal["development", "staging", "production", "test"] = "development"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    cors_origins: str = "*"

    # Azure Key Vault
    azure_keyvault_url: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""  # Only for local dev

    # Database
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "security_data_fabric"
    db_user: str = "postgres"
    db_password: str = ""  # Loaded from Key Vault in production
    db_pool_min: int = 5
    db_pool_max: int = 20
    db_pool_recycle: int = 3600
    db_query_timeout: int = 5
    db_pool_timeout: int = 10

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""  # Loaded from Key Vault in production
    redis_ssl: bool = False
    redis_pool_max: int = 20

    # Encryption & Security
    encryption_key: str = ""  # Loaded from Key Vault
    jwt_signing_key: str = ""  # Loaded from Key Vault
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 15

    # Okta MFA
    okta_domain: str = ""
    okta_client_id: str = ""
    okta_client_secret: str = ""  # Loaded from Key Vault

    @property
    def OKTA_DOMAIN(self) -> str:  # noqa: N802
        """Uppercase alias for okta_domain."""
        return self.okta_domain

    @property
    def OKTA_API_TOKEN(self) -> str:  # noqa: N802
        """Uppercase alias for okta_client_secret."""
        return self.okta_client_secret

    @property
    def AZURE_KEY_VAULT_URL(self) -> str:  # noqa: N802
        """Uppercase alias for azure_keyvault_url."""
        return self.azure_keyvault_url

    # OpenAI / Embeddings
    openai_api_key: str = ""  # Loaded from Key Vault
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_cache_max_size: int = 100000
    embedding_cache_ttl_hours: int = 24

    # Circuit Breaker
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 60

    # Vector DB
    vector_db_type: Literal["pgvector", "weaviate"] = "pgvector"

    # Data Source Connectors
    dynatrace_url: str = ""
    dynatrace_api_token: str = ""  # Loaded from Key Vault

    splunk_url: str = ""
    splunk_token: str = ""  # Loaded from Key Vault

    servicenow_url: str = ""
    servicenow_token: str = ""  # Loaded from Key Vault

    pagerduty_url: str = "https://api.pagerduty.com"
    pagerduty_token: str = ""  # Loaded from Key Vault

    github_url: str = "https://api.github.com"
    github_token: str = ""  # Loaded from Key Vault

    # ML & Analytics
    anomaly_warning_threshold: float = 1.5
    anomaly_critical_threshold: float = 3.0
    correlation_window_minutes: int = 30

    # Prometheus Metrics
    metrics_port: int = 9090
    metrics_path: str = "/metrics"

    # Rate Limiting
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 20

    @property
    def database_url(self) -> str:
        """Construct database URL."""
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        if self.cors_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def redis_url(self) -> str:
        """Construct Redis URL."""
        protocol = "rediss" if self.redis_ssl else "redis"
        if self.redis_password:
            return f"{protocol}://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"{protocol}://{self.redis_host}:{self.redis_port}/{self.redis_db}"


# Global settings instance
settings = Settings()
