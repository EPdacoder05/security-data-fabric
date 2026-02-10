"""Redis distributed cache with AES-256 encryption and audit logging."""
import json
import time
import logging
import hashlib
from typing import Any, Optional, Callable
from functools import wraps
from contextlib import asynccontextmanager

import redis.asyncio as redis
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

from src.config import settings

logger = logging.getLogger(__name__)


class RedisCache:
    """Redis cache with AES-256 encryption for sensitive data."""
    
    def __init__(self) -> None:
        """Initialize Redis connection pool."""
        self._pool: Optional[redis.ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._encryption_key: Optional[bytes] = None
        
    async def _get_client(self) -> redis.Redis:
        """Get or create Redis client with connection pooling."""
        if self._client is None:
            self._pool = redis.ConnectionPool.from_url(
                settings.redis_url,
                max_connections=settings.redis_pool_max,
                decode_responses=False,  # Handle bytes for encryption
                socket_keepalive=True,
                socket_connect_timeout=5,
                retry_on_timeout=True,
            )
            self._client = redis.Redis(connection_pool=self._pool)
            logger.info("Redis connection pool created with max %d connections", 
                       settings.redis_pool_max)
        return self._client
    
    def _get_encryption_key(self) -> bytes:
        """Get or derive encryption key for AES-256."""
        if self._encryption_key is None:
            key = settings.encryption_key or "development-key-32-bytes-long!!"
            # Ensure key is 32 bytes for AES-256
            self._encryption_key = hashlib.sha256(key.encode()).digest()
        return self._encryption_key
    
    def _encrypt(self, data: str) -> bytes:
        """Encrypt data using AES-256-CBC."""
        key = self._get_encryption_key()
        iv = os.urandom(16)  # Random IV for each encryption
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend IV to encrypted data
        return iv + encrypted
    
    def _decrypt(self, data: bytes) -> str:
        """Decrypt data using AES-256-CBC."""
        key = self._get_encryption_key()
        
        # Extract IV and encrypted data
        iv = data[:16]
        encrypted = data[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(padded_data) + unpadder.finalize()
        
        return unpadded.decode()
    
    async def get(self, key: str, decrypt: bool = False) -> Optional[Any]:
        """Get value from cache with optional decryption.
        
        Args:
            key: Cache key
            decrypt: Whether to decrypt the value
            
        Returns:
            Cached value or None if not found
        """
        start_time = time.perf_counter()
        client = await self._get_client()
        
        try:
            value = await client.get(key)
            duration = (time.perf_counter() - start_time) * 1000
            
            if value is None:
                logger.debug("Cache MISS for key: %s (%.2fms)", key, duration)
                return None
            
            logger.debug("Cache HIT for key: %s (%.2fms)", key, duration)
            
            if decrypt:
                decrypted = self._decrypt(value)
                return json.loads(decrypted)
            
            return json.loads(value.decode())
            
        except Exception as e:
            logger.error("Cache GET error for key %s: %s", key, str(e))
            return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        encrypt: bool = False
    ) -> bool:
        """Set value in cache with optional encryption and TTL.
        
        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds
            encrypt: Whether to encrypt the value
            
        Returns:
            True if successful
        """
        start_time = time.perf_counter()
        client = await self._get_client()
        
        try:
            serialized = json.dumps(value)
            
            if encrypt:
                data = self._encrypt(serialized)
            else:
                data = serialized.encode()
            
            if ttl:
                await client.setex(key, ttl, data)
            else:
                await client.set(key, data)
            
            duration = (time.perf_counter() - start_time) * 1000
            logger.debug("Cache SET for key: %s (%.2fms, ttl=%s)", key, duration, ttl)
            
            # Audit log for sensitive data
            if encrypt:
                logger.info("Encrypted cache write: key=%s, ttl=%s", key, ttl)
            
            return True
            
        except Exception as e:
            logger.error("Cache SET error for key %s: %s", key, str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if key was deleted
        """
        client = await self._get_client()
        
        try:
            result = await client.delete(key)
            logger.info("Cache DELETE: key=%s, deleted=%s", key, bool(result))
            return bool(result)
        except Exception as e:
            logger.error("Cache DELETE error for key %s: %s", key, str(e))
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        client = await self._get_client()
        try:
            return bool(await client.exists(key))
        except Exception as e:
            logger.error("Cache EXISTS error for key %s: %s", key, str(e))
            return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter (for rate limiting).
        
        Args:
            key: Counter key
            amount: Amount to increment by
            
        Returns:
            New counter value or None on error
        """
        client = await self._get_client()
        try:
            return await client.incrby(key, amount)
        except Exception as e:
            logger.error("Cache INCREMENT error for key %s: %s", key, str(e))
            return None
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL on existing key."""
        client = await self._get_client()
        try:
            return bool(await client.expire(key, ttl))
        except Exception as e:
            logger.error("Cache EXPIRE error for key %s: %s", key, str(e))
            return False
    
    async def close(self) -> None:
        """Close Redis connection pool."""
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis connection pool closed")


# Global cache instance
_cache: Optional[RedisCache] = None


def get_cache() -> RedisCache:
    """Get or create global cache instance."""
    global _cache
    if _cache is None:
        _cache = RedisCache()
    return _cache


def cached(
    ttl: int = 300,
    namespace: str = "default",
    encrypt: bool = False,
    key_func: Optional[Callable] = None
):
    """Decorator for automatic caching with TTL and namespace.
    
    Args:
        ttl: Time to live in seconds (default: 5 minutes)
        namespace: Cache namespace for organization
        encrypt: Whether to encrypt cached values
        key_func: Optional function to generate cache key from args
        
    Example:
        @cached(ttl=3600, namespace="user", encrypt=True)
        async def get_user(user_id: str):
            return await db.fetch_user(user_id)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Generate cache key
            if key_func:
                cache_key = f"{namespace}:{key_func(*args, **kwargs)}"
            else:
                # Default: use function name and stringified args
                args_str = "_".join(str(arg) for arg in args)
                kwargs_str = "_".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
                key_parts = [func.__name__, args_str, kwargs_str]
                key_str = "_".join(filter(None, key_parts))
                cache_key = f"{namespace}:{key_str}"
            
            # Try to get from cache
            cached_value = await cache.get(cache_key, decrypt=encrypt)
            if cached_value is not None:
                return cached_value
            
            # Cache miss - call function
            result = await func(*args, **kwargs)
            
            # Store in cache
            await cache.set(cache_key, result, ttl=ttl, encrypt=encrypt)
            
            return result
        
        return wrapper
    return decorator


async def rate_limit(key: str, limit: int, window: int) -> bool:
    """Rate limiting using Redis counters.
    
    Args:
        key: Rate limit key (e.g., f"ratelimit:user:{user_id}")
        limit: Maximum requests allowed
        window: Time window in seconds
        
    Returns:
        True if within rate limit, False if exceeded
    """
    cache = get_cache()
    
    # Get current count
    count = await cache.increment(key)
    if count is None:
        return True  # Error - allow request
    
    # Set expiry on first request
    if count == 1:
        await cache.expire(key, window)
    
    # Check if limit exceeded
    if count > limit:
        logger.warning("Rate limit exceeded: key=%s, count=%d, limit=%d", key, count, limit)
        return False
    
    return True
