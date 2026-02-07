"""Pytest configuration and shared fixtures."""
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from datetime import datetime
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from fastapi.testclient import TestClient

from src.database.connection import Base
from src.database.models import RawEvent, NormalizedEvent, EnrichedEvent
from src.main import app
from src.config import settings


# Override database URL for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest.fixture
async def test_db(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session


@pytest.fixture
def test_client() -> TestClient:
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_raw_event():
    """Create sample raw event."""
    return {
        "source": "dynatrace",
        "source_id": "test-123",
        "raw_data": {
            "metric_id": "builtin:host.cpu.usage",
            "value": 75.5,
            "unit": "percent",
            "timestamp": datetime.utcnow().isoformat(),
        },
    }


@pytest.fixture
def sample_normalized_event():
    """Create sample normalized event."""
    from src.processing.schema import NormalizedEventSchema
    
    return NormalizedEventSchema(
        event_type="metric",
        timestamp=datetime.utcnow(),
        source="dynatrace",
        severity=3,
        title="CPU Usage Metric",
        description="CPU usage at 75.5%",
        metadata={"metric_id": "builtin:host.cpu.usage", "value": 75.5},
    )


@pytest.fixture
def sample_enriched_event():
    """Create sample enriched event."""
    from src.processing.schema import EnrichedEventSchema
    
    return EnrichedEventSchema(
        normalized_event_id=uuid4(),
        risk_score=45.5,
        tags=["source:dynatrace", "type:metric", "severity:medium"],
        correlations=[],
        root_cause_analysis=None,
        incident_id=None,
    )


@pytest.fixture
def sample_github_webhook_payload():
    """Create sample GitHub webhook payload."""
    return {
        "action": "created",
        "deployment": {
            "id": 123456,
            "sha": "abc123",
            "ref": "main",
            "environment": "production",
            "creator": {"login": "test-user"},
            "created_at": datetime.utcnow().isoformat(),
        },
        "repository": {
            "full_name": "test-org/test-repo",
        },
    }


@pytest.fixture
def mock_metric_data():
    """Create mock time-series metric data."""
    import numpy as np
    
    # Generate 24 hours of data points (1 per minute = 1440 points)
    timestamps = [datetime.utcnow().timestamp() - (i * 60) for i in range(1440, 0, -1)]
    # Normal baseline around 50% with some noise
    values = np.random.normal(50, 5, 1440).tolist()
    
    return list(zip(timestamps, values))
