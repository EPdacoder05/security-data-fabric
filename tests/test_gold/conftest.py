"""
Shared test fixtures for Gold layer tests.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from uuid import uuid4


@pytest.fixture
def db_session():
    """Mock database session for testing."""
    session = AsyncMock()
    
    # Mock execute to return results
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    
    return session


@pytest.fixture
def mock_event_result():
    """Mock SQLAlchemy result for event queries."""
    result = AsyncMock()
    result.scalar_one_or_none = AsyncMock(return_value=None)
    result.scalars = MagicMock()
    result.scalars.return_value.all = MagicMock(return_value=[])
    return result
