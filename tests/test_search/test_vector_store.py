"""
Unit tests for VectorStore.
Tests pgvector storage, indexing, and similarity search.
"""
import pytest
from datetime import datetime
from uuid import uuid4
import numpy as np
from unittest.mock import Mock, AsyncMock, patch

from src.search.vector_store import VectorStore, VectorStoreError
from src.database.models import Embedding


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    session = AsyncMock()
    return session


@pytest.fixture
def vector_store(mock_session):
    """Create a VectorStore instance with mock session."""
    return VectorStore(mock_session)


@pytest.fixture
def sample_embedding():
    """Create a sample embedding vector."""
    return np.random.rand(384)


@pytest.fixture
def sample_embedding_obj():
    """Create a sample Embedding model object."""
    embedding_id = uuid4()
    source_id = uuid4()
    return Embedding(
        id=embedding_id,
        source_type='event',
        source_id=source_id,
        text_content='Sample security event',
        text_hash='abc123',
        embedding=np.random.rand(384).tolist(),
        model_version='all-MiniLM-L6-v2',
        metadata_json={'severity': 'high'},
        created_at=datetime.utcnow()
    )


class TestVectorStore:
    """Test suite for VectorStore."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, vector_store):
        """Test VectorStore initialization."""
        assert vector_store is not None
        assert vector_store.session is not None
    
    @pytest.mark.asyncio
    async def test_create_index(self, vector_store, mock_session):
        """Test IVFFlat index creation."""
        await vector_store.create_index(lists=100, recreate=False)
        
        assert mock_session.execute.called
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_create_index_failure(self, vector_store, mock_session):
        """Test index creation failure handling."""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(VectorStoreError):
            await vector_store.create_index()
        
        assert mock_session.rollback.called
    
    @pytest.mark.asyncio
    async def test_store_embeddings_batch_empty(self, vector_store):
        """Test batch storage with empty list."""
        result = await vector_store.store_embeddings_batch([])
        assert result == []
    
    @pytest.mark.asyncio
    async def test_search_failure(self, vector_store, mock_session, sample_embedding):
        """Test search failure handling."""
        mock_session.execute.side_effect = Exception("Search error")
        
        with pytest.raises(VectorStoreError):
            await vector_store.search(
                query_embedding=sample_embedding,
                limit=10
            )
    
    @pytest.mark.asyncio
    async def test_delete_by_source_failure(self, vector_store, mock_session):
        """Test delete failure handling."""
        mock_session.execute.side_effect = Exception("Delete error")
        
        with pytest.raises(VectorStoreError):
            await vector_store.delete_by_source(
                source_type='event',
                source_id=uuid4()
            )
        
        assert mock_session.rollback.called
    
    @pytest.mark.asyncio
    async def test_get_statistics_error(self, vector_store, mock_session):
        """Test statistics retrieval with error."""
        mock_session.execute.side_effect = Exception("Stats error")
        
        stats = await vector_store.get_statistics()
        
        # Should return default stats with error
        assert stats['total_embeddings'] == 0
        assert 'error' in stats
    
    @pytest.mark.asyncio
    async def test_compute_text_hash(self, vector_store):
        """Test text hash computation."""
        text1 = "Test text"
        text2 = "Test text"
        text3 = "Different text"
        
        hash1 = vector_store._compute_text_hash(text1)
        hash2 = vector_store._compute_text_hash(text2)
        hash3 = vector_store._compute_text_hash(text3)
        
        # Same text should produce same hash
        assert hash1 == hash2
        # Different text should produce different hash
        assert hash1 != hash3
        # Hash should be 64-character hex string
        assert len(hash1) == 64
