"""Text embedding engine for semantic search using sentence transformers."""
import hashlib
from typing import List, Dict, Optional, Tuple
import numpy as np

from src.config import settings
from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class EmbeddingEngine:
    """Generates text embeddings for semantic search capabilities."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        cache_size: int = 10000,
    ) -> None:
        """Initialize embedding engine.

        Args:
            model_name: Sentence transformer model name (default from settings)
            cache_size: Maximum number of embeddings to cache
        """
        self.model_name = model_name or settings.embedding_model
        self.cache_size = cache_size
        self.embedding_cache: Dict[str, np.ndarray] = {}
        self._model = None
        
        logger.info(
            "Initialized EmbeddingEngine",
            extra={"model": self.model_name, "cache_size": cache_size},
        )

    def _load_model(self):
        """Lazy load the sentence transformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                
                logger.info("Loading sentence transformer model", extra={"model": self.model_name})
                self._model = SentenceTransformer(self.model_name)
                metrics.increment("embedding_engine.model_loads")
                logger.info("Model loaded successfully")
                
            except Exception as e:
                logger.error(
                    "Failed to load sentence transformer model",
                    extra={"model": self.model_name, "error": str(e)},
                    exc_info=True,
                )
                metrics.increment("embedding_engine.model_load_errors")
                raise RuntimeError(f"Failed to load embedding model: {str(e)}")
        
        return self._model

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text.

        Args:
            text: Input text

        Returns:
            MD5 hash of the text
        """
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    def _manage_cache_size(self) -> None:
        """Evict oldest entries if cache exceeds size limit."""
        if len(self.embedding_cache) > self.cache_size:
            # Remove 10% of oldest entries (simple FIFO)
            num_to_remove = self.cache_size // 10
            keys_to_remove = list(self.embedding_cache.keys())[:num_to_remove]
            for key in keys_to_remove:
                del self.embedding_cache[key]
            
            logger.debug(
                "Evicted cache entries",
                extra={"removed": num_to_remove, "remaining": len(self.embedding_cache)},
            )

    def embed_text(self, text: str, use_cache: bool = True) -> np.ndarray:
        """Generate embedding for a single text.

        Args:
            text: Input text to embed
            use_cache: Whether to use/update cache

        Returns:
            Embedding vector as numpy array
        """
        metrics.increment("embedding_engine.embed_requests")
        
        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return np.zeros(settings.embedding_dimension)

        # Check cache
        cache_key = self._get_cache_key(text)
        if use_cache and cache_key in self.embedding_cache:
            metrics.increment("embedding_engine.cache_hits")
            return self.embedding_cache[cache_key]

        try:
            # Load model and generate embedding
            model = self._load_model()
            embedding = model.encode(text, convert_to_numpy=True)
            
            # Ensure correct dimension
            if embedding.shape[0] != settings.embedding_dimension:
                logger.warning(
                    "Embedding dimension mismatch",
                    extra={
                        "expected": settings.embedding_dimension,
                        "actual": embedding.shape[0],
                    },
                )

            # Cache the result
            if use_cache:
                self.embedding_cache[cache_key] = embedding
                self._manage_cache_size()
                metrics.increment("embedding_engine.cache_misses")

            metrics.increment("embedding_engine.embeddings_generated")
            return embedding

        except Exception as e:
            logger.error(
                "Error generating embedding",
                extra={"text_length": len(text), "error": str(e)},
                exc_info=True,
            )
            metrics.increment("embedding_engine.errors")
            # Return zero vector on error
            return np.zeros(settings.embedding_dimension)

    def embed_batch(
        self,
        texts: List[str],
        use_cache: bool = True,
        batch_size: int = 32,
    ) -> List[np.ndarray]:
        """Generate embeddings for multiple texts efficiently.

        Args:
            texts: List of input texts
            use_cache: Whether to use/update cache
            batch_size: Batch size for model inference

        Returns:
            List of embedding vectors
        """
        metrics.increment("embedding_engine.batch_requests")
        
        if not texts:
            return []

        embeddings = []
        texts_to_embed = []
        text_indices = []

        # Check cache for each text
        for i, text in enumerate(texts):
            if not text or not text.strip():
                embeddings.append(np.zeros(settings.embedding_dimension))
                continue

            cache_key = self._get_cache_key(text)
            if use_cache and cache_key in self.embedding_cache:
                embeddings.append(self.embedding_cache[cache_key])
                metrics.increment("embedding_engine.cache_hits")
            else:
                embeddings.append(None)  # Placeholder
                texts_to_embed.append(text)
                text_indices.append(i)

        # Generate embeddings for cache misses
        if texts_to_embed:
            try:
                model = self._load_model()
                
                logger.info(
                    "Generating batch embeddings",
                    extra={"batch_size": len(texts_to_embed)},
                )
                
                # Generate embeddings in batches
                new_embeddings = model.encode(
                    texts_to_embed,
                    batch_size=batch_size,
                    convert_to_numpy=True,
                    show_progress_bar=False,
                )

                # Update results and cache
                for idx, embedding in zip(text_indices, new_embeddings):
                    embeddings[idx] = embedding
                    
                    if use_cache:
                        cache_key = self._get_cache_key(texts[idx])
                        self.embedding_cache[cache_key] = embedding

                metrics.increment("embedding_engine.embeddings_generated", len(texts_to_embed))
                metrics.increment("embedding_engine.cache_misses", len(texts_to_embed))
                
                # Manage cache size after batch update
                if use_cache:
                    self._manage_cache_size()

            except Exception as e:
                logger.error(
                    "Error generating batch embeddings",
                    extra={"batch_size": len(texts_to_embed), "error": str(e)},
                    exc_info=True,
                )
                metrics.increment("embedding_engine.errors")
                
                # Fill remaining with zero vectors
                for idx in text_indices:
                    if embeddings[idx] is None:
                        embeddings[idx] = np.zeros(settings.embedding_dimension)

        return embeddings

    def compute_similarity(
        self,
        embedding1: np.ndarray,
        embedding2: np.ndarray,
    ) -> float:
        """Compute cosine similarity between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Cosine similarity score between -1 and 1
        """
        try:
            # Normalize vectors
            norm1 = np.linalg.norm(embedding1)
            norm2 = np.linalg.norm(embedding2)

            if norm1 == 0 or norm2 == 0:
                return 0.0

            # Cosine similarity
            similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
            
            # Clamp to [-1, 1] to handle numerical errors
            similarity = max(-1.0, min(1.0, float(similarity)))
            
            return similarity

        except Exception as e:
            logger.error(
                "Error computing similarity",
                extra={"error": str(e)},
                exc_info=True,
            )
            return 0.0

    def find_similar(
        self,
        query_embedding: np.ndarray,
        candidate_embeddings: List[np.ndarray],
        top_k: int = 10,
        min_similarity: float = 0.5,
    ) -> List[Tuple[int, float]]:
        """Find most similar embeddings to a query.

        Args:
            query_embedding: Query embedding vector
            candidate_embeddings: List of candidate embedding vectors
            top_k: Number of top results to return
            min_similarity: Minimum similarity threshold

        Returns:
            List of (index, similarity_score) tuples, sorted by similarity
        """
        metrics.increment("embedding_engine.similarity_searches")
        
        if not candidate_embeddings:
            return []

        try:
            # Compute similarities
            similarities = []
            for i, candidate in enumerate(candidate_embeddings):
                similarity = self.compute_similarity(query_embedding, candidate)
                if similarity >= min_similarity:
                    similarities.append((i, similarity))

            # Sort by similarity (descending) and return top_k
            similarities.sort(key=lambda x: x[1], reverse=True)
            
            return similarities[:top_k]

        except Exception as e:
            logger.error(
                "Error finding similar embeddings",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("embedding_engine.errors")
            return []

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cache_size": len(self.embedding_cache),
            "cache_limit": self.cache_size,
            "cache_utilization_percent": int(
                (len(self.embedding_cache) / self.cache_size) * 100
            ),
        }

    def clear_cache(self) -> None:
        """Clear the embedding cache."""
        self.embedding_cache.clear()
        logger.info("Embedding cache cleared")
        metrics.increment("embedding_engine.cache_clears")
