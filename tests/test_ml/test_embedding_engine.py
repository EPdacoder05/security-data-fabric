"""
Tests for embedding engine.
"""
import pytest
import numpy as np
import asyncio

from src.ml.embedding_engine import EmbeddingEngine


class TestEmbeddingEngine:
    """Test suite for EmbeddingEngine."""
    
    @pytest.fixture
    def engine(self):
        """Create embedding engine for tests."""
        return EmbeddingEngine(cache_size=100)
    
    def test_initialization(self, engine):
        """Test engine initialization."""
        assert engine.model_name == "sentence-transformers/all-MiniLM-L6-v2"
        assert engine.cache_size == 100
        assert len(engine.cache) == 0
        assert not engine._model_loaded
    
    @pytest.mark.asyncio
    async def test_initialize_model(self, engine):
        """Test model initialization."""
        await engine.initialize()
        assert engine._model_loaded
        assert engine.model is not None
    
    @pytest.mark.asyncio
    async def test_generate_embedding(self, engine):
        """Test single embedding generation."""
        text = "This is a test security alert"
        embedding = await engine.generate_embedding(text)
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384  # Dimension for all-MiniLM-L6-v2
        assert embedding.dtype == np.float32 or embedding.dtype == np.float64
    
    @pytest.mark.asyncio
    async def test_embedding_caching(self, engine):
        """Test embedding cache functionality."""
        text = "This is a test security alert"
        
        # First call should compute
        embedding1 = await engine.generate_embedding(text, use_cache=True)
        assert len(engine.cache) == 1
        
        # Second call should use cache
        embedding2 = await engine.generate_embedding(text, use_cache=True)
        np.testing.assert_array_equal(embedding1, embedding2)
        assert len(engine.cache) == 1
    
    @pytest.mark.asyncio
    async def test_no_caching(self, engine):
        """Test embedding without caching."""
        text = "Test alert message"
        
        embedding = await engine.generate_embedding(text, use_cache=False)
        assert len(engine.cache) == 0
        assert isinstance(embedding, np.ndarray)
    
    @pytest.mark.asyncio
    async def test_batch_embedding(self, engine):
        """Test batch embedding generation."""
        texts = [
            "Security alert 1",
            "Security alert 2",
            "Security alert 3"
        ]
        
        embeddings = await engine.generate_embeddings_batch(texts)
        
        assert len(embeddings) == 3
        assert all(isinstance(emb, np.ndarray) for emb in embeddings)
        assert all(len(emb) == 384 for emb in embeddings)
    
    @pytest.mark.asyncio
    async def test_batch_with_cache(self, engine):
        """Test batch embedding with partial cache hits."""
        texts = ["Alert 1", "Alert 2", "Alert 3"]
        
        # First batch
        embeddings1 = await engine.generate_embeddings_batch(texts, use_cache=True)
        assert len(engine.cache) == 3
        
        # Second batch with some repeated texts
        texts2 = ["Alert 1", "Alert 4", "Alert 2"]
        embeddings2 = await engine.generate_embeddings_batch(texts2, use_cache=True)
        
        # Should have 4 unique texts cached
        assert len(engine.cache) == 4
        
        # First and third embeddings in second batch should match first batch
        np.testing.assert_array_equal(embeddings2[0], embeddings1[0])
        np.testing.assert_array_equal(embeddings2[2], embeddings1[1])
    
    @pytest.mark.asyncio
    async def test_empty_batch(self, engine):
        """Test batch embedding with empty list."""
        embeddings = await engine.generate_embeddings_batch([])
        assert embeddings == []
    
    @pytest.mark.asyncio
    async def test_embed_security_event(self, engine):
        """Test embedding generation for security event."""
        event_data = {
            "title": "High CPU Usage",
            "description": "CPU usage exceeded threshold",
            "severity": "critical",
            "source": "monitoring-system"
        }
        
        embedding = await engine.embed_security_event(event_data)
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384
    
    @pytest.mark.asyncio
    async def test_embed_security_event_minimal(self, engine):
        """Test embedding with minimal event data."""
        event_data = {"message": "Alert"}
        
        embedding = await engine.embed_security_event(event_data)
        assert isinstance(embedding, np.ndarray)
    
    @pytest.mark.asyncio
    async def test_embed_security_event_empty(self, engine):
        """Test embedding with empty event data."""
        event_data = {}
        
        # Should use default text
        embedding = await engine.embed_security_event(event_data)
        assert isinstance(embedding, np.ndarray)
    
    @pytest.mark.asyncio
    async def test_embed_incident_description(self, engine):
        """Test embedding for incident description."""
        embedding = await engine.embed_incident_description(
            title="Security Breach",
            description="Unauthorized access detected",
            additional_context="Multiple failed login attempts"
        )
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384
    
    @pytest.mark.asyncio
    async def test_embed_alert_message(self, engine):
        """Test embedding for alert message."""
        embedding = await engine.embed_alert_message(
            alert_message="Disk space critical",
            alert_type="capacity"
        )
        
        assert isinstance(embedding, np.ndarray)
    
    def test_sync_embedding(self, engine):
        """Test synchronous embedding generation."""
        text = "Test synchronous embedding"
        
        embedding = engine.generate_embedding_sync(text)
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384
        assert engine._model_loaded
    
    def test_cache_eviction(self, engine):
        """Test cache eviction when full."""
        engine.cache_size = 3
        
        # Add 4 embeddings (should evict oldest)
        for i in range(4):
            engine.generate_embedding_sync(f"Text {i}")
        
        # Cache should have only 3 entries
        assert len(engine.cache) == 3
    
    def test_clear_cache(self, engine):
        """Test cache clearing."""
        engine.generate_embedding_sync("Text 1")
        engine.generate_embedding_sync("Text 2")
        assert len(engine.cache) > 0
        
        engine.clear_cache()
        assert len(engine.cache) == 0
    
    def test_get_cache_stats(self, engine):
        """Test cache statistics."""
        engine.generate_embedding_sync("Test")
        
        stats = engine.get_cache_stats()
        
        assert "cache_size" in stats
        assert "cache_limit" in stats
        assert "model_loaded" in stats
        assert "model_name" in stats
        assert stats["cache_size"] == 1
        assert stats["model_loaded"] == True
    
    def test_embedding_dimension(self, engine):
        """Test embedding dimension property."""
        assert engine.embedding_dimension == 384
    
    def test_compute_similarity_identical(self, engine):
        """Test similarity computation for identical embeddings."""
        text = "Test alert"
        emb1 = engine.generate_embedding_sync(text)
        emb2 = engine.generate_embedding_sync(text)
        
        similarity = engine.compute_similarity(emb1, emb2)
        
        # Should be very close to 1.0 (might not be exactly 1.0 due to normalization)
        assert 0.99 < similarity <= 1.0
    
    def test_compute_similarity_different(self, engine):
        """Test similarity computation for different embeddings."""
        emb1 = engine.generate_embedding_sync("Security breach detected")
        emb2 = engine.generate_embedding_sync("System performance degraded")
        
        similarity = engine.compute_similarity(emb1, emb2)
        
        # Should be less than 1.0 but greater than 0
        assert 0.0 < similarity < 1.0
    
    def test_compute_similarity_zero_vector(self, engine):
        """Test similarity with zero vector."""
        emb1 = np.zeros(384)
        emb2 = np.ones(384)
        
        similarity = engine.compute_similarity(emb1, emb2)
        
        # Should handle zero vector gracefully
        assert similarity == 0.0
    
    @pytest.mark.asyncio
    async def test_concurrent_initialization(self, engine):
        """Test concurrent model initialization."""
        # Multiple concurrent calls should not cause issues
        await asyncio.gather(
            engine.initialize(),
            engine.initialize(),
            engine.initialize()
        )
        
        assert engine._model_loaded
        assert engine.model is not None
    
    def test_model_not_loaded_error(self):
        """Test error when using model before initialization."""
        engine = EmbeddingEngine()
        
        with pytest.raises(RuntimeError, match="Model not loaded"):
            engine._ensure_model_loaded()
