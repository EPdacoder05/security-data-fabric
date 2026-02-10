"""Tests for Redis cache with AES-256 encryption."""

import pytest

from src.security.redis_cache import RedisCache, cached, get_cache, rate_limit


@pytest.fixture
def mock_redis_cache():
    """Create mock Redis cache for testing."""
    cache = RedisCache()
    # In-memory cache for testing
    cache._cache_data = {}

    # Mock client methods
    async def mock_get(key):
        return cache._cache_data.get(key)

    async def mock_set(key, value):
        cache._cache_data[key] = value
        return True

    async def mock_setex(key, ttl, value):
        cache._cache_data[key] = value
        return True

    async def mock_delete(key):
        if key in cache._cache_data:
            del cache._cache_data[key]
            return 1
        return 0

    async def mock_exists(key):
        return 1 if key in cache._cache_data else 0

    async def mock_incrby(key, amount):
        if key not in cache._cache_data:
            cache._cache_data[key] = 0
        cache._cache_data[key] += amount
        return cache._cache_data[key]

    async def mock_expire(key, ttl):
        return True

    # Create mock client
    class MockRedis:
        async def get(self, key):
            return await mock_get(key)

        async def set(self, key, value):
            return await mock_set(key, value)

        async def setex(self, key, ttl, value):
            return await mock_setex(key, ttl, value)

        async def delete(self, key):
            return await mock_delete(key)

        async def exists(self, key):
            return await mock_exists(key)

        async def incrby(self, key, amount):
            return await mock_incrby(key, amount)

        async def expire(self, key, ttl):
            return await mock_expire(key, ttl)

    cache._client = MockRedis()
    return cache


class TestCacheBasicOperations:
    """Test basic cache operations."""

    @pytest.mark.asyncio
    async def test_set_and_get(self, mock_redis_cache):
        """Test setting and getting a value."""
        cache = mock_redis_cache

        # Set value
        success = await cache.set("test_key", {"data": "test_value"})
        assert success

        # Get value
        value = await cache.get("test_key")
        assert value is not None
        assert value["data"] == "test_value"

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, mock_redis_cache):
        """Test getting a non-existent key."""
        cache = mock_redis_cache
        value = await cache.get("nonexistent_key")
        assert value is None

    @pytest.mark.asyncio
    async def test_delete(self, mock_redis_cache):
        """Test deleting a key."""
        cache = mock_redis_cache

        # Set value
        await cache.set("test_key", {"data": "test_value"})

        # Delete
        deleted = await cache.delete("test_key")
        assert deleted

        # Verify deleted
        value = await cache.get("test_key")
        assert value is None

    @pytest.mark.asyncio
    async def test_exists(self, mock_redis_cache):
        """Test checking if key exists."""
        cache = mock_redis_cache

        # Key doesn't exist
        exists = await cache.exists("test_key")
        assert not exists

        # Set value
        await cache.set("test_key", {"data": "test_value"})

        # Key exists
        exists = await cache.exists("test_key")
        assert exists


class TestEncryption:
    """Test cache encryption."""

    @pytest.mark.asyncio
    async def test_encrypted_set_and_get(self, mock_redis_cache):
        """Test setting and getting encrypted values."""
        cache = mock_redis_cache

        # Set encrypted value
        success = await cache.set("secret_key", {"secret": "sensitive_data"}, encrypt=True)
        assert success

        # Get encrypted value
        value = await cache.get("secret_key", decrypt=True)
        assert value is not None
        assert value["secret"] == "sensitive_data"

    def test_encrypt_decrypt(self, mock_redis_cache):
        """Test encryption and decryption."""
        cache = mock_redis_cache

        original = "sensitive data"
        encrypted = cache._encrypt(original)
        decrypted = cache._decrypt(encrypted)

        assert original == decrypted
        assert encrypted != original.encode()


class TestTTL:
    """Test TTL (Time To Live) functionality."""

    @pytest.mark.asyncio
    async def test_set_with_ttl(self, mock_redis_cache):
        """Test setting value with TTL."""
        cache = mock_redis_cache

        # Set value with TTL
        success = await cache.set("temp_key", {"data": "temp_value"}, ttl=60)
        assert success

        # Value should be retrievable
        value = await cache.get("temp_key")
        assert value is not None

    @pytest.mark.asyncio
    async def test_expire(self, mock_redis_cache):
        """Test setting expiration on existing key."""
        cache = mock_redis_cache

        # Set value
        await cache.set("test_key", {"data": "test_value"})

        # Set expiration
        result = await cache.expire("test_key", 60)
        assert result


class TestIncrement:
    """Test counter increment for rate limiting."""

    @pytest.mark.asyncio
    async def test_increment(self, mock_redis_cache):
        """Test incrementing a counter."""
        cache = mock_redis_cache

        # First increment
        count = await cache.increment("counter")
        assert count == 1

        # Second increment
        count = await cache.increment("counter")
        assert count == 2

        # Increment by 5
        count = await cache.increment("counter", 5)
        assert count == 7


class TestCachedDecorator:
    """Test @cached decorator."""

    @pytest.mark.asyncio
    async def test_cached_function(self, mock_redis_cache, monkeypatch):
        """Test caching a function result."""
        # Mock the global cache
        monkeypatch.setattr("src.security.redis_cache._cache", mock_redis_cache)

        call_count = 0

        @cached(ttl=300, namespace="test")
        async def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call - should execute function
        result1 = await expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Second call - should use cache
        result2 = await expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Function not called again


class TestRateLimiting:
    """Test rate limiting functionality."""

    @pytest.mark.asyncio
    async def test_rate_limit_within_limit(self, mock_redis_cache, monkeypatch):
        """Test rate limiting within allowed limit."""
        monkeypatch.setattr("src.security.redis_cache._cache", mock_redis_cache)

        # Should allow first 5 requests
        for i in range(5):
            allowed = await rate_limit("test_user", limit=10, window=60)
            assert allowed

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, mock_redis_cache, monkeypatch):
        """Test rate limiting when limit exceeded."""
        monkeypatch.setattr("src.security.redis_cache._cache", mock_redis_cache)

        # Make 11 requests (limit is 10)
        for i in range(11):
            allowed = await rate_limit("test_user", limit=10, window=60)
            if i < 10:
                assert allowed
            else:
                assert not allowed  # 11th request should be blocked


class TestGlobalCache:
    """Test global cache instance."""

    def test_get_cache_singleton(self):
        """Test global cache is singleton."""
        cache1 = get_cache()
        cache2 = get_cache()
        assert cache1 is cache2


class TestPerformance:
    """Test cache performance metrics."""

    @pytest.mark.asyncio
    async def test_cache_hit_latency(self, mock_redis_cache):
        """Test cache hit latency is under 1ms target."""
        import time

        cache = mock_redis_cache

        # Set value
        await cache.set("perf_test", {"data": "test"})

        # Measure get latency
        start = time.perf_counter()
        await cache.get("perf_test")
        duration = (time.perf_counter() - start) * 1000

        # Should be fast (in-memory mock)
        assert duration < 1.0  # Less than 1ms
