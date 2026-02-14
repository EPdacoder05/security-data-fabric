"""Pytest configuration and fixtures for Security Data Fabric tests."""

import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.main import app
from src.config.settings import Settings


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests.

    Yields:
        Event loop instance
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings for testing.

    Returns:
        Test settings instance
    """
    test_settings = Settings(
        environment="test",
        log_level="DEBUG",
        db_host="localhost",
        db_port=5432,
        db_name="test_security_data_fabric",
        db_user="test_user",
        db_password="test_password",
        redis_host="localhost",
        redis_port=6379,
        redis_db=1,
        redis_password="",
        encryption_key="dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcw==",
        jwt_signing_key="test-jwt-signing-key-for-testing-purposes",
        jwt_algorithm="HS256",
        jwt_expiration_minutes=15,
        OKTA_DOMAIN="test.okta.com",
        OKTA_API_TOKEN="test-okta-token",
        openai_api_key="test-openai-key",
        rate_limit_per_minute=1000,
        AZURE_KEY_VAULT_URL="",
        azure_tenant_id="",
        azure_client_id="",
        azure_client_secret="",
    )
    return test_settings


@pytest_asyncio.fixture
async def async_db_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Create async database engine for testing.

    Args:
        test_settings: Test settings

    Yields:
        Async database engine
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture
async def async_db_session(async_db_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Create async database session for testing.

    Args:
        async_db_engine: Async database engine

    Yields:
        Async database session
    """
    async_session_maker = sessionmaker(async_db_engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session_maker() as session:
        yield session


@pytest_asyncio.fixture
async def mock_redis_client() -> AsyncMock:
    """Create mock Redis client.

    Returns:
        Mock Redis client
    """
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=None)
    mock_client.set = AsyncMock(return_value=True)
    mock_client.setex = AsyncMock(return_value=True)
    mock_client.delete = AsyncMock(return_value=1)
    mock_client.exists = AsyncMock(return_value=1)
    mock_client.expire = AsyncMock(return_value=True)
    mock_client.ttl = AsyncMock(return_value=3600)
    mock_client.close = AsyncMock()

    return mock_client


@pytest_asyncio.fixture
async def mock_redis_pool() -> AsyncMock:
    """Create mock Redis connection pool.

    Returns:
        Mock Redis connection pool
    """
    mock_pool = AsyncMock()
    mock_pool.disconnect = AsyncMock()
    return mock_pool


@pytest.fixture
def mock_azure_keyvault() -> Mock:
    """Create mock Azure Key Vault client.

    Returns:
        Mock Azure Key Vault client
    """
    mock_client = Mock()
    mock_secret = Mock()
    mock_secret.value = "test-secret-value"
    mock_client.get_secret.return_value = mock_secret
    mock_client.set_secret.return_value = None
    mock_client.begin_delete_secret.return_value = None
    mock_client.list_properties_of_secrets.return_value = []

    return mock_client


@pytest.fixture
def mock_okta_client() -> Mock:
    """Create mock Okta API client.

    Returns:
        Mock Okta client
    """
    mock_client = Mock()
    mock_client.send_sms = Mock(return_value=True)
    mock_client.send_email = Mock(return_value=True)
    mock_client.verify_factor = Mock(return_value=True)

    return mock_client


@pytest_asyncio.fixture
async def async_http_client() -> AsyncGenerator[AsyncClient, None]:
    """Create async HTTP client for API testing.

    Yields:
        Async HTTP client
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def sync_http_client() -> Generator[TestClient, None, None]:
    """Create synchronous HTTP client for API testing.

    Yields:
        Synchronous HTTP test client
    """
    with TestClient(app) as client:
        yield client


@pytest.fixture
def mock_isolation_forest() -> Mock:
    """Create mock Isolation Forest model.

    Returns:
        Mock Isolation Forest model
    """
    mock_model = Mock()
    mock_model.fit.return_value = None
    mock_model.predict.return_value = [1, 1, -1, 1]
    mock_model.decision_function.return_value = [0.1, 0.2, -0.5, 0.15]
    mock_model.score_samples.return_value = [0.1, 0.2, -0.5, 0.15]

    return mock_model


@pytest.fixture
def sample_security_events() -> list[dict]:
    """Create sample security events for testing.

    Returns:
        List of sample security event dictionaries
    """
    return [
        {
            "event_id": "evt-001",
            "timestamp": "2024-01-15T10:00:00Z",
            "event_type": "login_attempt",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "user_id": "user123",
            "status": "failed",
        },
        {
            "event_id": "evt-002",
            "timestamp": "2024-01-15T10:05:00Z",
            "event_type": "data_access",
            "severity": "medium",
            "source_ip": "192.168.1.101",
            "user_id": "user456",
            "status": "success",
        },
        {
            "event_id": "evt-003",
            "timestamp": "2024-01-15T10:10:00Z",
            "event_type": "config_change",
            "severity": "critical",
            "source_ip": "192.168.1.102",
            "user_id": "admin789",
            "status": "success",
        },
    ]


@pytest.fixture
def sample_jwt_payload() -> dict:
    """Create sample JWT payload for testing.

    Returns:
        Sample JWT payload dictionary
    """
    return {
        "sub": "service-123",
        "service_name": "test-service",
        "scopes": ["read", "write"],
        "type": "service",
    }


@pytest.fixture
def mock_service_auth_manager(test_settings: Settings) -> Mock:
    """Create mock service auth manager.

    Args:
        test_settings: Test settings

    Returns:
        Mock service auth manager
    """
    from src.security.service_auth import ServiceAuthManager

    mock_manager = Mock(spec=ServiceAuthManager)
    mock_manager.generate_token.return_value = "test-jwt-token"
    mock_manager.validate_token.return_value = {
        "sub": "service-123",
        "service_name": "test-service",
        "scopes": ["read", "write"],
        "type": "service",
    }
    mock_manager.is_token_expired.return_value = False
    mock_manager.get_service_id.return_value = "service-123"
    mock_manager.get_scopes.return_value = ["read", "write"]
    mock_manager.has_scope.return_value = True

    return mock_manager


@pytest.fixture
def encryption_key() -> bytes:
    """Create encryption key for testing.

    Returns:
        32-byte encryption key
    """
    return b"test-encryption-key-32-bytes!"


@pytest.fixture
def mock_aesgcm_cipher(encryption_key: bytes) -> AESGCM:
    """Create AESGCM cipher for testing.

    Args:
        encryption_key: Encryption key

    Returns:
        AESGCM cipher instance
    """
    return AESGCM(encryption_key)
