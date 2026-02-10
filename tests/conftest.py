"""Shared test fixtures for pytest."""

import asyncio
from datetime import datetime
from typing import AsyncGenerator, Generator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.config import Settings
from src.database.connection import Base
from src.database.models import *  # noqa: F401, F403

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    # Create engine
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False)

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session factory
    async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Create session
    async with async_session_factory() as session:
        yield session

    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings."""
    return Settings(
        environment="testing",
        db_host="localhost",
        db_port=5432,
        db_name="test_db",
        db_user="test_user",
        db_password="test_password",
        redis_host="localhost",
        redis_port=6379,
        redis_password="test_redis_password",
        encryption_key="test-encryption-key-32-bytes-long",
        jwt_signing_key="test-jwt-signing-key-64-bytes-long",
    )


@pytest.fixture
def sample_incident():
    """Create sample incident data."""
    return {
        "id": "incident-001",
        "severity_score": 4,
        "affected_users_count": 500,
        "detected_at": datetime.utcnow().isoformat(),
        "cve_score": 7.5,
        "title": "Test Security Incident",
        "description": "This is a test incident",
    }


@pytest.fixture
def sample_incidents():
    """Create multiple sample incidents."""
    return [
        {
            "id": f"incident-{i:03d}",
            "severity_score": (i % 5) + 1,
            "affected_users_count": i * 100,
            "detected_at": datetime.utcnow().isoformat(),
            "cve_score": (i % 10) * 1.0,
            "title": f"Incident {i}",
            "description": f"Test incident {i}",
        }
        for i in range(1, 11)
    ]


@pytest.fixture
def sample_historical_data():
    """Create sample historical data for forecasting."""
    from datetime import timedelta

    base_date = datetime.utcnow()

    return [
        {
            "timestamp": (base_date - timedelta(days=i)).isoformat(),
            "incident_count": 40 + (i % 10) - 5,
        }
        for i in range(60, 0, -1)
    ]
