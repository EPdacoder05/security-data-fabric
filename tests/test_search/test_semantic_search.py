"""
Unit tests for SemanticSearch.
Tests natural language query interface and result formatting.
"""
import pytest
from datetime import datetime
from uuid import uuid4
import numpy as np
from unittest.mock import AsyncMock, patch

from src.search.semantic_search import (
    SemanticSearch, SearchError, SearchResult, SearchResultType
)
from src.database.models import EventSeverity


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    return AsyncMock()


@pytest.fixture
def mock_embedding_engine():
    """Create a mock embedding engine."""
    engine = AsyncMock()
    engine.initialize = AsyncMock()
    engine.generate_embedding = AsyncMock()
    engine.generate_embedding.return_value = np.random.rand(384)
    return engine


@pytest.fixture
def semantic_search(mock_session, mock_embedding_engine):
    """Create a SemanticSearch instance with mocks."""
    return SemanticSearch(mock_session, mock_embedding_engine)


class TestSearchResult:
    """Test suite for SearchResult."""
    
    def test_search_result_creation(self):
        """Test creating a SearchResult."""
        entity_id = uuid4()
        embedding_id = uuid4()
        
        result = SearchResult(
            result_type=SearchResultType.EVENT,
            entity_id=entity_id,
            similarity_score=0.95,
            embedding_id=embedding_id,
            entity_data={'title': 'Test event'}
        )
        
        assert result.result_type == SearchResultType.EVENT
        assert result.entity_id == entity_id
        assert result.similarity_score == 0.95
        assert result.entity_data['title'] == 'Test event'
    
    def test_search_result_to_dict(self):
        """Test SearchResult to_dict method."""
        entity_id = uuid4()
        embedding_id = uuid4()
        
        result = SearchResult(
            result_type=SearchResultType.INCIDENT,
            entity_id=entity_id,
            similarity_score=0.88,
            embedding_id=embedding_id,
            entity_data={'title': 'Test incident', 'severity': 'high'}
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['result_type'] == 'incident'
        assert result_dict['similarity_score'] == 0.88
        assert result_dict['title'] == 'Test incident'
        assert result_dict['severity'] == 'high'


class TestSemanticSearch:
    """Test suite for SemanticSearch."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, semantic_search):
        """Test SemanticSearch initialization."""
        assert semantic_search is not None
        assert semantic_search.session is not None
        assert semantic_search.vector_store is not None
        assert semantic_search.embedding_engine is not None
        assert not semantic_search._initialized
    
    @pytest.mark.asyncio
    async def test_initialize(self, semantic_search, mock_embedding_engine):
        """Test initialization method."""
        await semantic_search.initialize()
        
        assert semantic_search._initialized
        assert mock_embedding_engine.initialize.called
    
    @pytest.mark.asyncio
    async def test_search_empty_query(self, semantic_search):
        """Test search with empty query."""
        with pytest.raises(SearchError, match="Query cannot be empty"):
            await semantic_search.search("")
        
        with pytest.raises(SearchError, match="Query cannot be empty"):
            await semantic_search.search("   ")
    
    @pytest.mark.asyncio
    async def test_search_no_results(self, semantic_search, mock_embedding_engine):
        """Test search with no matching results."""
        with patch.object(semantic_search.vector_store, 'search', return_value=[]):
            results = await semantic_search.search("test query")
        
        assert results == []
        assert mock_embedding_engine.generate_embedding.called
    
    @pytest.mark.asyncio
    async def test_search_with_filters(self, semantic_search, mock_embedding_engine):
        """Test search with various filters."""
        with patch.object(semantic_search.vector_store, 'search', return_value=[]):
            results = await semantic_search.search(
                query="test",
                severity=EventSeverity.CRITICAL,
                source="dynatrace",
                entity_filter="HOST-123",
                limit=5
            )
        
        assert results == []
        assert mock_embedding_engine.generate_embedding.called
    
    @pytest.mark.asyncio
    async def test_search_paginated(self, semantic_search):
        """Test paginated search."""
        mock_results = [
            SearchResult(
                result_type=SearchResultType.EVENT,
                entity_id=uuid4(),
                similarity_score=0.9 - i * 0.05,
                embedding_id=uuid4(),
                entity_data={'title': f'Event {i}'}
            )
            for i in range(25)
        ]
        
        with patch.object(semantic_search, 'search', return_value=mock_results):
            result = await semantic_search.search_paginated(
                query="test",
                page=2,
                page_size=10
            )
        
        assert result['pagination']['page'] == 2
        assert result['pagination']['page_size'] == 10
        assert result['pagination']['total_results'] == 25
        assert result['pagination']['total_pages'] == 3
        assert result['pagination']['has_next']
        assert result['pagination']['has_prev']
        assert len(result['results']) == 10
    
    @pytest.mark.asyncio
    async def test_search_paginated_invalid_page(self, semantic_search):
        """Test paginated search with invalid page number."""
        with pytest.raises(SearchError, match="Page must be >= 1"):
            await semantic_search.search_paginated("test", page=0)
    
    @pytest.mark.asyncio
    async def test_search_paginated_invalid_page_size(self, semantic_search):
        """Test paginated search with invalid page size."""
        with pytest.raises(SearchError, match="Page size must be between 1 and 100"):
            await semantic_search.search_paginated("test", page_size=0)
        
        with pytest.raises(SearchError, match="Page size must be between 1 and 100"):
            await semantic_search.search_paginated("test", page_size=101)
