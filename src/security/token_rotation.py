"""Refresh token rotation with Redis storage."""

import hashlib
import secrets
from datetime import datetime
from typing import Any, Dict, Optional

from src.security.redis_cache import RedisCache
from src.security.service_auth import ServiceAuthManager


class TokenRotationManager:
    """Refresh token rotation manager with automatic refresh and invalidation.

    Manages refresh tokens with rotation, automatic invalidation, and Redis storage
    for distributed token tracking.
    """

    def __init__(
        self,
        redis_cache: RedisCache,
        auth_manager: ServiceAuthManager,
        refresh_token_ttl: int = 86400,
    ):
        """Initialize token rotation manager.

        Args:
            redis_cache: Redis cache instance for token storage
            auth_manager: Service authentication manager for JWT operations
            refresh_token_ttl: Refresh token TTL in seconds. Defaults to 24 hours.
        """
        self._cache = redis_cache
        self._auth_manager = auth_manager
        self._refresh_token_ttl = refresh_token_ttl

    def _hash_token(self, token: str) -> str:
        """Generate hash of token for storage key.

        Args:
            token: Token to hash

        Returns:
            SHA-256 hash of token
        """
        return hashlib.sha256(token.encode()).hexdigest()

    async def generate_refresh_token(
        self, service_id: str, service_name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate new refresh token.

        Args:
            service_id: Service identifier
            service_name: Service name
            metadata: Additional metadata to store with token

        Returns:
            Refresh token string
        """
        refresh_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(refresh_token)

        token_data = {
            "service_id": service_id,
            "service_name": service_name,
            "created_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }

        key = f"refresh_token:{token_hash}"
        await self._cache.set(key, token_data, ttl=self._refresh_token_ttl)

        return refresh_token

    async def validate_refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Validate refresh token and retrieve associated data.

        Args:
            refresh_token: Refresh token to validate

        Returns:
            Token data if valid, None otherwise
        """
        token_hash = self._hash_token(refresh_token)
        key = f"refresh_token:{token_hash}"

        token_data = await self._cache.get(key)
        return token_data

    async def rotate_tokens(
        self, refresh_token: str, scopes: Optional[list[str]] = None
    ) -> Optional[Dict[str, str]]:
        """Rotate refresh token and generate new access token.

        Invalidates old refresh token and generates new refresh and access tokens.

        Args:
            refresh_token: Current refresh token
            scopes: Scopes to include in new access token

        Returns:
            Dict with new access_token and refresh_token, or None if invalid
        """
        token_data = await self.validate_refresh_token(refresh_token)
        if not token_data:
            return None

        service_id = token_data["service_id"]
        service_name = token_data["service_name"]
        metadata = token_data.get("metadata", {})

        await self.invalidate_refresh_token(refresh_token)

        new_refresh_token = await self.generate_refresh_token(
            service_id=service_id, service_name=service_name, metadata=metadata
        )

        new_access_token = self._auth_manager.generate_token(
            service_id=service_id, service_name=service_name, scopes=scopes
        )

        return {"access_token": new_access_token, "refresh_token": new_refresh_token}

    async def invalidate_refresh_token(self, refresh_token: str) -> bool:
        """Invalidate refresh token by removing from storage.

        Args:
            refresh_token: Refresh token to invalidate

        Returns:
            True if token was invalidated, False otherwise
        """
        token_hash = self._hash_token(refresh_token)
        key = f"refresh_token:{token_hash}"

        return await self._cache.delete(key)

    async def invalidate_all_service_tokens(self, service_id: str) -> int:
        """Invalidate all refresh tokens for a service.

        Args:
            service_id: Service identifier

        Returns:
            Number of tokens invalidated
        """
        await self._cache.connect()
        count = 0

        try:
            pattern = "refresh_token:*"
            cursor = "0"

            while cursor != 0:
                cursor, keys = await self._cache._client.scan(
                    cursor=int(cursor) if isinstance(cursor, str) else cursor,
                    match=pattern,
                    count=100,
                )

                for key in keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    token_data = await self._cache.get(key_str)

                    if token_data and token_data.get("service_id") == service_id:
                        await self._cache.delete(key_str)
                        count += 1
        except Exception:
            pass

        return count

    async def get_token_ttl(self, refresh_token: str) -> int:
        """Get remaining TTL for refresh token.

        Args:
            refresh_token: Refresh token to check

        Returns:
            Remaining TTL in seconds, -1 if no TTL, -2 if not found
        """
        token_hash = self._hash_token(refresh_token)
        key = f"refresh_token:{token_hash}"

        return await self._cache.ttl(key)

    async def extend_token_ttl(self, refresh_token: str, additional_seconds: int) -> bool:
        """Extend TTL for refresh token.

        Args:
            refresh_token: Refresh token to extend
            additional_seconds: Seconds to add to current TTL

        Returns:
            True if TTL was extended, False otherwise
        """
        current_ttl = await self.get_token_ttl(refresh_token)
        if current_ttl <= 0:
            return False

        new_ttl = current_ttl + additional_seconds
        token_hash = self._hash_token(refresh_token)
        key = f"refresh_token:{token_hash}"

        return await self._cache.expire(key, new_ttl)
