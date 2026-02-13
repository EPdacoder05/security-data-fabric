"""Azure Key Vault secrets manager with secure logging.

This module provides secure access to secrets stored in Azure Key Vault,
with fallback to environment variables. NO secret identifiers are logged.
"""

import logging
import os
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from src.config.settings import settings

logger = logging.getLogger(__name__)


class SecretsManager:
    """Manages secrets from Azure Key Vault with secure logging."""

    def __init__(self) -> None:
        """Initialize the secrets manager."""
        self.client: Optional[SecretClient] = None
        if settings.AZURE_KEY_VAULT_URL:
            try:
                credential = DefaultAzureCredential()
                self.client = SecretClient(
                    vault_url=settings.AZURE_KEY_VAULT_URL, credential=credential
                )
                logger.info("Secrets manager initialized with Azure Key Vault")
            except Exception as e:
                logger.error("Failed to initialize Azure Key Vault client: %s", str(e))
                self.client = None

    async def get_secret(self, secret_name: str, env_name: Optional[str] = None) -> Optional[str]:
        """Get a secret from Azure Key Vault or environment variable.

        Args:
            secret_name: Name of the secret in Key Vault
            env_name: Optional environment variable name as fallback

        Returns:
            Secret value or None if not found

        Note:
            NO secret identifiers are logged for security compliance.
        """
        if self.client:
            try:
                secret = self.client.get_secret(secret_name)
                logger.debug("Secret retrieved from Azure Key Vault")
                return str(secret.value)
            except Exception as e:
                logger.warning("Failed to get secret from Key Vault: %s", str(e))

        if env_name:
            value = os.getenv(env_name)
            if value:
                logger.debug("Secret retrieved from environment variable")
                return str(value)

        if hasattr(settings, secret_name.upper()):
            value = getattr(settings, secret_name.upper())
            if value:
                logger.debug("Secret retrieved from application settings")
                return str(value)

        raise ValueError("Secret not found (tried Key Vault and environment)")

    async def set_secret(self, secret_name: str, secret_value: str) -> bool:
        """Set a secret in Azure Key Vault.

        Args:
            secret_name: Name of the secret in Key Vault
            secret_value: Value to store

        Returns:
            True if successful, False otherwise

        Note:
            NO secret identifiers are logged for security compliance.
        """
        if not self.client:
            logger.error("Azure Key Vault client not initialized")
            return False

        try:
            self.client.set_secret(secret_name, secret_value)
            logger.info("Secret updated in Key Vault")
            return True
        except Exception as e:
            logger.error("Failed to set secret in Key Vault: %s", str(e))
            return False

    async def delete_secret(self, secret_name: str) -> bool:
        """Delete a secret from Azure Key Vault.

        Args:
            secret_name: Name of the secret to delete

        Returns:
            True if successful, False otherwise

        Note:
            NO secret identifiers are logged for security compliance.
        """
        if not self.client:
            logger.error("Azure Key Vault client not initialized")
            return False

        try:
            self.client.begin_delete_secret(secret_name)
            logger.info("Secret deleted from Key Vault")
            return True
        except Exception as e:
            logger.error("Failed to delete secret from Key Vault: %s", str(e))
            return False

    async def list_secrets(self) -> list[str]:
        """List all secret names in Azure Key Vault.

        Returns:
            List of secret names

        Note:
            This method returns secret names for administrative purposes only.
            Secret names should not be logged in production contexts.
        """
        if not self.client:
            return []

        try:
            properties = self.client.list_properties_of_secrets()
            return [prop.name for prop in properties if prop.name is not None]
        except Exception as e:
            logger.error("Failed to list secrets from Key Vault: %s", str(e))
            return []


secrets_manager = SecretsManager()
