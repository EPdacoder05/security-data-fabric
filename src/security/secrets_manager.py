"""Azure Key Vault secrets management with graceful fallback."""

import logging
import os
from functools import lru_cache
from typing import Dict, Optional

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from src.config import settings

logger = logging.getLogger(__name__)


class SecretsManager:
    """Azure Key Vault integration with graceful fallback to environment variables."""

    def __init__(self) -> None:
        """Initialize secrets manager."""
        self._client: Optional[SecretClient] = None
        self._credential: Optional[DefaultAzureCredential] = None
        self._cache: Dict[str, str] = {}
        self._key_vault_available = False

        # Try to initialize Key Vault client
        if settings.azure_keyvault_url:
            try:
                self._credential = DefaultAzureCredential()
                self._client = SecretClient(
                    vault_url=settings.azure_keyvault_url, credential=self._credential
                )
                # Test connection
                self._client.list_properties_of_secrets(max_page_size=1)
                self._key_vault_available = True
                logger.info("Azure Key Vault connected: %s", settings.azure_keyvault_url)
            except Exception as e:
                logger.warning("Azure Key Vault unavailable, falling back to .env: %s", str(e))
                self._key_vault_available = False
        else:
            logger.info("Azure Key Vault not configured, using .env")

    @lru_cache(maxsize=128)
    def get_secret(self, secret_name: str, fallback_env: Optional[str] = None) -> str:
        """Get secret from Key Vault with LRU caching and .env fallback.

        Args:
            secret_name: Name of the secret in Key Vault
            fallback_env: Environment variable name for fallback

        Returns:
            Secret value

        Raises:
            ValueError: If secret not found in Key Vault or environment
        """
        # Check cache first
        if secret_name in self._cache:
            return self._cache[secret_name]

        # Try Key Vault
        if self._key_vault_available and self._client:
            try:
                secret = self._client.get_secret(secret_name)
                value = secret.value
                self._cache[secret_name] = value
                logger.debug("Secret retrieved from Azure Key Vault")
                return value
            except AzureError as e:
                logger.warning("Failed to get secret from Key Vault: %s", str(e))

        # Fallback to environment variable
        env_name = fallback_env or secret_name.upper().replace("-", "_")
        value = os.environ.get(env_name, "")

        if value:
            self._cache[secret_name] = value
            logger.debug("Secret retrieved from environment variable")
            return value

        # Try from settings object
        settings_attr = env_name.lower()
        if hasattr(settings, settings_attr):
            value = getattr(settings, settings_attr)
            if value:
                self._cache[secret_name] = value
                logger.debug("Secret retrieved from application settings")
                return value

        raise ValueError("Secret not found (tried Key Vault and environment)")

    def get_openai_key(self) -> str:
        """Get OpenAI API key."""
        return self.get_secret("openai-api-key", "OPENAI_API_KEY")

    def get_db_password(self) -> str:
        """Get database password."""
        return self.get_secret("db-password", "DB_PASSWORD")

    def get_redis_password(self) -> str:
        """Get Redis password."""
        return self.get_secret("redis-password", "REDIS_PASSWORD")

    def get_oidc_client_secret(self) -> str:
        """Get OIDC/OAuth client secret."""
        return self.get_secret("oidc-client-secret", "OIDC_CLIENT_SECRET")

    def get_jwt_signing_key(self) -> str:
        """Get JWT signing key."""
        return self.get_secret("jwt-signing-key", "JWT_SIGNING_KEY")

    def get_encryption_key(self) -> str:
        """Get encryption key for AES-256."""
        return self.get_secret("encryption-key", "ENCRYPTION_KEY")

    def get_okta_client_secret(self) -> str:
        """Get Okta client secret."""
        return self.get_secret("okta-client-secret", "OKTA_CLIENT_SECRET")

    def get_okta_api_token(self) -> str:
        """Get Okta API token."""
        return self.get_secret("okta-api-token", "OKTA_API_TOKEN")

    def get_connector_token(self, connector_name: str) -> str:
        """Get data source connector token.

        Args:
            connector_name: Name of connector (e.g., "dynatrace", "splunk")

        Returns:
            Connector API token
        """
        secret_name = f"{connector_name}-token"
        env_name = f"{connector_name.upper()}_TOKEN"
        return self.get_secret(secret_name, env_name)

    def refresh_cache(self) -> None:
        """Clear LRU cache to force refresh from Key Vault."""
        self._cache.clear()
        self.get_secret.cache_clear()
        logger.info("Secrets cache refreshed")

    def is_key_vault_available(self) -> bool:
        """Check if Azure Key Vault is available."""
        return self._key_vault_available

    def get_all_secret_names(self) -> list[str]:
        """Get list of all secret names in Key Vault.

        Returns:
            List of secret names or empty list if Key Vault unavailable
        """
        if not self._key_vault_available or not self._client:
            return []

        try:
            properties = self._client.list_properties_of_secrets()
            return [prop.name for prop in properties]
        except AzureError as e:
            logger.error("Failed to list secrets: %s", str(e))
            return []

    def set_secret(self, secret_name: str, secret_value: str) -> bool:
        """Set or update a secret in Key Vault.

        Args:
            secret_name: Name of the secret
            secret_value: Secret value

        Returns:
            True if successful
        """
        if not self._key_vault_available or not self._client:
            logger.warning("Cannot set secret: Key Vault unavailable")
            return False

        try:
            self._client.set_secret(secret_name, secret_value)
            # Clear cache for this secret
            if secret_name in self._cache:
                del self._cache[secret_name]
            logger.info("Secret updated in Key Vault")
            return True
        except AzureError as e:
            logger.error("Failed to set secret in Key Vault: %s", str(e))
            return False

    def close(self) -> None:
        """Close Azure credential."""
        if self._credential:
            self._credential.close()
        logger.info("Secrets manager closed")


# Global secrets manager instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Get or create global secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager
