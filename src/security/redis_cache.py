"""Redis cache with AES-256-GCM encryption for secure data storage."""

import base64
import json
import os
from typing import Any, Optional

import redis.asyncio as redis
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from redis.asyncio.connection import ConnectionPool

from src.config.settings import settings


class RedisCache:
    """Redis cache with AES-256-GCM encryption for secure data storage.

    Provides encrypted caching with connection pooling, TTL support, and
    automatic encryption/decryption of cached values.
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """Initialize Redis cache with encryption.

        Args:
            encryption_key: Base64-encoded encryption key. If not provided,
                          uses key from settings.
        """
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None

        key = encryption_key or settings.encryption_key
        if not key:
            raise ValueError("Encryption key must be provided")

        key_bytes = base64.b64decode(key) if len(key) > 32 else key.encode()

        if len(key_bytes) != 32:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"security-data-fabric",
                iterations=100000,
                backend=default_backend(),
            )
            key_bytes = kdf.derive(key_bytes)

        self._cipher = AESGCM(key_bytes)

    async def connect(self) -> None:
        """Establish connection pool to Redis."""
        if self._pool is None:
            self._pool = ConnectionPool.from_url(
                settings.redis_url, max_connections=settings.redis_pool_max, decode_responses=False
            )
            self._client = redis.Redis(connection_pool=self._pool)

    async def disconnect(self) -> None:
        """Close Redis connection pool."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        self._pool = None
        self._client = None

    def _encrypt(self, data: str) -> bytes:
        """Encrypt data using AES-256-GCM.

        Args:
            data: Plain text data to encrypt

        Returns:
            Encrypted data with nonce prepended
        """
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    def _decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt data using AES-256-GCM.

        Args:
            encrypted_data: Encrypted data with nonce prepended

        Returns:
            Decrypted plain text data
        """
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = self._cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set encrypted value in cache with optional TTL.

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds

        Returns:
            True if successful, False otherwise
        """
        if not self._client:
            await self.connect()

        try:
            serialized = json.dumps(value)
            encrypted = self._encrypt(serialized)

            if ttl:
                await self._client.setex(key, ttl, encrypted)
            else:
                await self._client.set(key, encrypted)

            return True
        except Exception:
            return False

    async def get(self, key: str) -> Optional[Any]:
        """Get and decrypt value from cache.

        Args:
            key: Cache key

        Returns:
            Decrypted and deserialized value, or None if not found
        """
        if not self._client:
            await self.connect()

        try:
            encrypted = await self._client.get(key)
            if not encrypted:
                return None

            decrypted = self._decrypt(encrypted)
            return json.loads(decrypted)
        except Exception:
            return None

    async def delete(self, key: str) -> bool:
        """Delete key from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if key was deleted, False otherwise
        """
        if not self._client:
            await self.connect()

        try:
            result = await self._client.delete(key)
            return result > 0
        except Exception:
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists, False otherwise
        """
        if not self._client:
            await self.connect()

        try:
            result = await self._client.exists(key)
            return result > 0
        except Exception:
            return False

    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key.

        Args:
            key: Cache key
            ttl: Time to live in seconds

        Returns:
            True if TTL was set, False otherwise
        """
        if not self._client:
            await self.connect()

        try:
            result = await self._client.expire(key, ttl)
            return result
        except Exception:
            return False

    async def ttl(self, key: str) -> int:
        """Get remaining TTL for key.

        Args:
            key: Cache key

        Returns:
            Remaining TTL in seconds, -1 if no TTL, -2 if key doesn't exist
        """
        if not self._client:
            await self.connect()

        try:
            return await self._client.ttl(key)
        except Exception:
            return -2
