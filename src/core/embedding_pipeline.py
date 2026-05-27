"""Vector embedding pipeline for the Security Data Fabric.

Generates OpenAI text embeddings for incidents, vulnerabilities, and breaches,
with in-memory caching and semantic search capability.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Embedding dimension for OpenAI text-embedding-3-small
EMBEDDING_DIM = 1536


@dataclass
class EmbeddingRecord:
    """An embedding for a single Silver fact record."""

    record_id: str
    record_type: str  # incident | vulnerability | breach
    text: str
    embedding: List[float]
    model_name: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EmbeddingMetrics:
    """Metrics for an embedding generation run."""

    records_processed: int = 0
    cache_hits: int = 0
    api_calls: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


@dataclass
class SearchResult:
    """A single semantic search result."""

    record_id: str
    record_type: str
    text: str
    similarity_score: float


class EmbeddingPipeline:
    """Generates and stores vector embeddings for Security Data Fabric records.

    Uses OpenAI text-embedding-3-small (1536-dim) for embedding generation,
    with a TTL-based in-memory cache to reduce API call costs.

    When no OpenAI client is provided (test mode), uses deterministic mock
    embeddings so tests run without external API dependencies.
    """

    MODEL_NAME = "text-embedding-3-small"
    CACHE_TTL_SECONDS = 3600  # 1-hour TTL

    def __init__(
        self,
        db_session: Any = None,
        openai_client: Any = None,
    ) -> None:
        """Initialize the embedding pipeline.

        Args:
            db_session: Database session (optional, for future persistence)
            openai_client: OpenAI client instance. If None, uses mock embeddings.
        """
        self.db = db_session
        self._openai = openai_client
        self._embeddings: Dict[str, EmbeddingRecord] = {}
        # Cache: text_hash → (embedding, expiry_timestamp)
        self._cache: Dict[str, Tuple[List[float], float]] = {}

    # ------------------------------------------------------------------
    # Embedding generation
    # ------------------------------------------------------------------

    def _text_hash(self, text: str) -> str:
        """Compute a hash key for cache lookups.

        Args:
            text: Input text

        Returns:
            SHA-256 hex digest of the text
        """
        return hashlib.sha256(text.encode()).hexdigest()

    def _mock_embedding(self, text: str) -> List[float]:
        """Generate a deterministic mock embedding for testing.

        Uses character code sums seeded by the text hash to produce a stable,
        normalized 1536-dimension vector.

        Args:
            text: Input text

        Returns:
            1536-dimensional list of floats
        """
        import math

        seed = sum(ord(c) for c in text[:100])
        vec = []
        for i in range(EMBEDDING_DIM):
            val = math.sin(seed + i) * 0.5 + math.cos(seed * 2 + i * 3) * 0.5
            vec.append(val)
        # Normalize to unit length
        magnitude = math.sqrt(sum(v * v for v in vec))
        if magnitude > 0:
            vec = [v / magnitude for v in vec]
        return vec

    def _get_embedding(self, text: str) -> Tuple[List[float], bool]:
        """Retrieve embedding from cache or generate via API/mock.

        Args:
            text: Input text to embed

        Returns:
            Tuple of (embedding vector, was_cache_hit)
        """
        key = self._text_hash(text)
        now = time.time()

        # Check cache
        if key in self._cache:
            embedding, expiry = self._cache[key]
            if now < expiry:
                return embedding, True

        # Generate embedding
        if self._openai is not None:
            try:
                response = self._openai.embeddings.create(
                    input=text,
                    model=self.MODEL_NAME,
                )
                embedding = response.data[0].embedding
            except Exception as exc:
                logger.warning("OpenAI embedding failed, using mock: %s", exc)
                embedding = self._mock_embedding(text)
        else:
            embedding = self._mock_embedding(text)

        # Store in cache
        self._cache[key] = (embedding, now + self.CACHE_TTL_SECONDS)
        return embedding, False

    def _record_to_text(self, record: Any, record_type: str) -> str:
        """Convert a fact record into a text string for embedding.

        Args:
            record: FactIncident, FactVulnerability, or FactBreach
            record_type: Type string for field mapping

        Returns:
            Concatenated text string
        """
        if record_type == "incident":
            parts = [
                f"Incident: {getattr(record, 'title', '')}",
                f"Severity: {getattr(record, 'severity', '')}",
                f"Source: {getattr(record, 'source', '')}",
                f"Description: {getattr(record, 'description', '')}",
            ]
        elif record_type == "vulnerability":
            parts = [
                f"Vulnerability: {getattr(record, 'title', '')}",
                f"Severity: {getattr(record, 'severity', '')}",
                f"Asset: {getattr(record, 'affected_asset', '')}",
                f"CVE: {getattr(record, 'cve_id', '') or 'N/A'}",
                f"Description: {getattr(record, 'description', '')}",
            ]
        elif record_type == "breach":
            parts = [
                f"Breach: {getattr(record, 'title', '')}",
                f"Organization: {getattr(record, 'organization', '')}",
                f"Type: {getattr(record, 'breach_type', '')}",
                f"Industry: {getattr(record, 'industry', '')}",
                f"Records: {getattr(record, 'records_affected', 0)}",
            ]
        else:
            parts = [str(record)]

        return " | ".join(p for p in parts if p)

    # ------------------------------------------------------------------
    # Batch embedding
    # ------------------------------------------------------------------

    def embed_incidents(self, incidents: list) -> EmbeddingMetrics:
        """Generate embeddings for a list of FactIncident records.

        Args:
            incidents: List of FactIncident objects

        Returns:
            EmbeddingMetrics with processing counts
        """
        return self._embed_batch(incidents, "incident")

    def embed_vulnerabilities(self, vulnerabilities: list) -> EmbeddingMetrics:
        """Generate embeddings for a list of FactVulnerability records.

        Args:
            vulnerabilities: List of FactVulnerability objects

        Returns:
            EmbeddingMetrics with processing counts
        """
        return self._embed_batch(vulnerabilities, "vulnerability")

    def embed_breaches(self, breaches: list) -> EmbeddingMetrics:
        """Generate embeddings for a list of FactBreach records.

        Args:
            breaches: List of FactBreach objects

        Returns:
            EmbeddingMetrics with processing counts
        """
        return self._embed_batch(breaches, "breach")

    def _embed_batch(self, records: list, record_type: str) -> EmbeddingMetrics:
        """Generate embeddings for a batch of records.

        Args:
            records: List of fact records
            record_type: Type string (incident | vulnerability | breach)

        Returns:
            EmbeddingMetrics with processing counts
        """
        start = time.time()
        metrics = EmbeddingMetrics(records_processed=len(records))

        id_field = {
            "incident": "incident_id",
            "vulnerability": "vuln_id",
            "breach": "breach_id",
        }.get(record_type, "id")

        for record in records:
            try:
                record_id = getattr(record, id_field, str(id(record)))
                text = self._record_to_text(record, record_type)
                embedding, cache_hit = self._get_embedding(text)

                if cache_hit:
                    metrics.cache_hits += 1
                else:
                    metrics.api_calls += 1

                emb_record = EmbeddingRecord(
                    record_id=record_id,
                    record_type=record_type,
                    text=text,
                    embedding=embedding,
                    model_name=self.MODEL_NAME,
                )
                self._embeddings[record_id] = emb_record

            except Exception as exc:
                metrics.errors += 1
                logger.warning("Embedding error for %s: %s", record_type, exc)

        metrics.duration_seconds = time.time() - start
        return metrics

    # ------------------------------------------------------------------
    # Semantic search
    # ------------------------------------------------------------------

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors.

        Args:
            a: First vector
            b: Second vector

        Returns:
            Cosine similarity (0.0-1.0)
        """
        if len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        mag_a = sum(x * x for x in a) ** 0.5
        mag_b = sum(x * x for x in b) ** 0.5
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return float(dot / (mag_a * mag_b))

    def semantic_search(
        self,
        query: str,
        top_k: int = 5,
        record_type: Optional[str] = None,
    ) -> List[SearchResult]:
        """Find records semantically similar to the query text.

        Args:
            query: Search query text
            top_k: Maximum number of results to return
            record_type: Optional filter by record type

        Returns:
            List of SearchResult sorted by similarity (descending)
        """
        if not self._embeddings:
            return []

        query_embedding, _ = self._get_embedding(query)
        results: List[SearchResult] = []

        for record_id, emb_record in self._embeddings.items():
            if record_type and emb_record.record_type != record_type:
                continue
            score = self._cosine_similarity(query_embedding, emb_record.embedding)
            results.append(
                SearchResult(
                    record_id=record_id,
                    record_type=emb_record.record_type,
                    text=emb_record.text[:200],
                    similarity_score=round(score, 4),
                )
            )

        results.sort(key=lambda r: r.similarity_score, reverse=True)
        return results[:top_k]

    def build_index(self) -> Dict[str, Any]:
        """Build a summary of the embedding index.

        Returns:
            Dictionary with index statistics
        """
        by_type: Dict[str, int] = {}
        for emb in self._embeddings.values():
            by_type[emb.record_type] = by_type.get(emb.record_type, 0) + 1

        return {
            "total_embeddings": len(self._embeddings),
            "by_type": by_type,
            "embedding_dim": EMBEDDING_DIM,
            "model": self.MODEL_NAME,
            "cache_entries": len(self._cache),
        }

    def get_embedding_count(self) -> int:
        """Return total number of stored embeddings."""
        return len(self._embeddings)
