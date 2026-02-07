"""
Text embedding generation engine for Security Data Fabric.
Uses sentence-transformers for semantic embeddings of security events.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Union
import hashlib
import numpy as np
from sentence_transformers import SentenceTransformer

from src.config.settings import settings

logger = logging.getLogger(__name__)


class EmbeddingEngine:
    """
    Text embedding generation engine using sentence-transformers.
    
    Generates semantic embeddings for security events, alerts, and incidents
    to enable similarity search and semantic analysis.
    """
    
    def __init__(
        self,
        model_name: Optional[str] = None,
        cache_size: int = 10000
    ):
        """
        Initialize embedding engine.
        
        Args:
            model_name: Sentence transformer model name (uses ml_embedding_model from settings if None)
            cache_size: Maximum number of embeddings to cache
        """
        self.model_name = model_name or settings.ml_embedding_model
        self.model: Optional[SentenceTransformer] = None
        self.cache: Dict[str, np.ndarray] = {}
        self.cache_size = cache_size
        self._model_loaded = False
        self._load_lock = asyncio.Lock()
        
        logger.info(f"EmbeddingEngine initialized with model: {self.model_name}")
    
    async def initialize(self) -> None:
        """Initialize and load the model asynchronously."""
        if self._model_loaded:
            return
        
        async with self._load_lock:
            if self._model_loaded:  # Double-check after acquiring lock
                return
            
            await self._load_model()
    
    async def _load_model(self) -> None:
        """Load the sentence transformer model."""
        try:
            logger.info(f"Loading sentence transformer model: {self.model_name}")
            
            # Load model in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            self.model = await loop.run_in_executor(
                None,
                lambda: SentenceTransformer(self.model_name)
            )
            
            self._model_loaded = True
            logger.info(f"Model loaded successfully: {self.model_name}")
            
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            raise RuntimeError(f"Could not load embedding model: {e}")
    
    def _ensure_model_loaded(self) -> None:
        """Ensure model is loaded (synchronous check)."""
        if not self._model_loaded or self.model is None:
            raise RuntimeError(
                "Model not loaded. Call initialize() first or use async methods."
            )
    
    async def generate_embedding(
        self,
        text: str,
        use_cache: bool = True
    ) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Text to embed
            use_cache: Whether to use cache for repeated texts
        
        Returns:
            Embedding vector as numpy array
        """
        await self.initialize()
        
        # Check cache
        if use_cache:
            cache_key = self._get_cache_key(text)
            if cache_key in self.cache:
                logger.debug(f"Cache hit for text: {text[:50]}...")
                return self.cache[cache_key]
        
        # Generate embedding
        try:
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None,
                lambda: self.model.encode(text, convert_to_numpy=True)
            )
            
            # Cache result
            if use_cache:
                self._cache_embedding(cache_key, embedding)
            
            logger.debug(f"Generated embedding for text: {text[:50]}... (dim={len(embedding)})")
            return embedding
            
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            raise
    
    async def generate_embeddings_batch(
        self,
        texts: List[str],
        use_cache: bool = True,
        batch_size: int = 32
    ) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts in batches.
        
        Args:
            texts: List of texts to embed
            use_cache: Whether to use cache
            batch_size: Batch size for processing
        
        Returns:
            List of embedding vectors
        """
        await self.initialize()
        
        if not texts:
            return []
        
        # Check cache for all texts
        embeddings = []
        texts_to_compute = []
        text_indices = []
        
        for i, text in enumerate(texts):
            if use_cache:
                cache_key = self._get_cache_key(text)
                if cache_key in self.cache:
                    embeddings.append(self.cache[cache_key])
                    continue
            
            texts_to_compute.append(text)
            text_indices.append(i)
            embeddings.append(None)  # Placeholder
        
        # Compute embeddings for uncached texts
        if texts_to_compute:
            logger.info(f"Computing embeddings for {len(texts_to_compute)} texts")
            
            try:
                loop = asyncio.get_event_loop()
                computed_embeddings = await loop.run_in_executor(
                    None,
                    lambda: self.model.encode(
                        texts_to_compute,
                        batch_size=batch_size,
                        convert_to_numpy=True,
                        show_progress_bar=False
                    )
                )
                
                # Fill in computed embeddings and cache
                for idx, text_idx in enumerate(text_indices):
                    embedding = computed_embeddings[idx]
                    embeddings[text_idx] = embedding
                    
                    if use_cache:
                        cache_key = self._get_cache_key(texts[text_idx])
                        self._cache_embedding(cache_key, embedding)
                
            except Exception as e:
                logger.error(f"Error in batch embedding generation: {e}")
                raise
        
        logger.info(f"Generated {len(embeddings)} embeddings ({len(texts_to_compute)} computed, {len(texts) - len(texts_to_compute)} cached)")
        return embeddings
    
    def generate_embedding_sync(
        self,
        text: str,
        use_cache: bool = True
    ) -> np.ndarray:
        """
        Generate embedding synchronously (loads model if needed).
        
        Args:
            text: Text to embed
            use_cache: Whether to use cache
        
        Returns:
            Embedding vector
        """
        # Load model if not loaded
        if not self._model_loaded:
            self.model = SentenceTransformer(self.model_name)
            self._model_loaded = True
        
        # Check cache
        if use_cache:
            cache_key = self._get_cache_key(text)
            if cache_key in self.cache:
                return self.cache[cache_key]
        
        # Generate embedding
        embedding = self.model.encode(text, convert_to_numpy=True)
        
        # Cache result
        if use_cache:
            self._cache_embedding(cache_key, embedding)
        
        return embedding
    
    async def embed_security_event(
        self,
        event_data: Dict
    ) -> np.ndarray:
        """
        Generate embedding for a security event.
        
        Args:
            event_data: Dictionary containing event information
        
        Returns:
            Embedding vector
        """
        # Extract relevant text fields
        text_parts = []
        
        if "title" in event_data:
            text_parts.append(f"Title: {event_data['title']}")
        
        if "description" in event_data:
            text_parts.append(f"Description: {event_data['description']}")
        
        if "message" in event_data:
            text_parts.append(f"Message: {event_data['message']}")
        
        if "severity" in event_data:
            text_parts.append(f"Severity: {event_data['severity']}")
        
        if "source" in event_data:
            text_parts.append(f"Source: {event_data['source']}")
        
        # Combine text parts
        combined_text = " | ".join(text_parts)
        
        if not combined_text.strip():
            logger.warning("Empty text for event embedding, using default")
            combined_text = "security event"
        
        return await self.generate_embedding(combined_text)
    
    async def embed_incident_description(
        self,
        title: str,
        description: str,
        additional_context: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate embedding for an incident.
        
        Args:
            title: Incident title
            description: Incident description
            additional_context: Additional context (optional)
        
        Returns:
            Embedding vector
        """
        text_parts = [f"Incident: {title}", description]
        
        if additional_context:
            text_parts.append(additional_context)
        
        combined_text = " | ".join(text_parts)
        return await self.generate_embedding(combined_text)
    
    async def embed_alert_message(
        self,
        alert_message: str,
        alert_type: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate embedding for an alert message.
        
        Args:
            alert_message: Alert message text
            alert_type: Type of alert (optional)
        
        Returns:
            Embedding vector
        """
        if alert_type:
            text = f"Alert Type: {alert_type} | Message: {alert_message}"
        else:
            text = alert_message
        
        return await self.generate_embedding(text)
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        # Use hash to handle long texts
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def _cache_embedding(self, cache_key: str, embedding: np.ndarray) -> None:
        """Add embedding to cache with LRU eviction."""
        # Simple FIFO eviction if cache is full
        if len(self.cache) >= self.cache_size:
            # Remove oldest entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            logger.debug(f"Cache full, evicted entry: {oldest_key}")
        
        self.cache[cache_key] = embedding
    
    def clear_cache(self) -> None:
        """Clear embedding cache."""
        self.cache.clear()
        logger.info("Embedding cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        return {
            "cache_size": len(self.cache),
            "cache_limit": self.cache_size,
            "model_loaded": self._model_loaded,
            "model_name": self.model_name
        }
    
    @property
    def embedding_dimension(self) -> int:
        """Get embedding dimension."""
        if self.model_name == "sentence-transformers/all-MiniLM-L6-v2":
            return 384
        elif self.model_name == "sentence-transformers/all-mpnet-base-v2":
            return 768
        else:
            # Default assumption
            return 384
    
    def compute_similarity(
        self,
        embedding1: np.ndarray,
        embedding2: np.ndarray
    ) -> float:
        """
        Compute cosine similarity between two embeddings.
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
        
        Returns:
            Cosine similarity score (0-1)
        """
        # Normalize vectors
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        # Compute cosine similarity
        similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
        
        # Ensure result is in [0, 1] range
        similarity = (similarity + 1) / 2
        
        return float(similarity)
