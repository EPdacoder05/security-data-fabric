"""P5 Vector embedding pipeline tests - 14 tests."""

import pytest

from src.core.embedding_pipeline import EMBEDDING_DIM, EmbeddingPipeline
from src.core.transformer import SilverTransformer
from src.data.fixtures.mock_grafana_incidents import (
    MOCK_DEFENDER_INCIDENTS,
    MOCK_GRAFANA_ALERTS,
    MOCK_SERVICENOW_INCIDENTS,
    MOCK_USATODAY_BREACHES,
)


async def _load_silver():
    """Return Silver-layer records from all 4 mock sources."""
    t = SilverTransformer()
    await t.transform_batch("servicenow", MOCK_SERVICENOW_INCIDENTS)
    await t.transform_batch("grafana", MOCK_GRAFANA_ALERTS)
    await t.transform_batch("defender", MOCK_DEFENDER_INCIDENTS)
    await t.transform_batch("usatoday", MOCK_USATODAY_BREACHES)
    return t.get_incidents(), t.get_vulnerabilities(), t.get_breaches()


class TestEmbeddingPipelineInit:
    """Pipeline initialization tests."""

    def test_pipeline_initializes(self):
        pipeline = EmbeddingPipeline()
        assert pipeline is not None

    def test_pipeline_starts_empty(self):
        pipeline = EmbeddingPipeline()
        assert pipeline.get_embedding_count() == 0

    def test_embedding_dim_constant(self):
        assert EMBEDDING_DIM == 1536


class TestEmbeddingGeneration:
    """Embedding generation for each record type."""

    @pytest.mark.asyncio
    async def test_embed_incidents(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()
        metrics = pipeline.embed_incidents(incidents)
        assert metrics.records_processed == len(incidents)
        assert metrics.errors == 0
        assert pipeline.get_embedding_count() == len(incidents)

    @pytest.mark.asyncio
    async def test_embed_vulnerabilities(self):
        _, vulns, _ = await _load_silver()
        pipeline = EmbeddingPipeline()
        metrics = pipeline.embed_vulnerabilities(vulns)
        assert metrics.records_processed == len(vulns)
        assert metrics.errors == 0

    @pytest.mark.asyncio
    async def test_embed_breaches(self):
        _, _, breaches = await _load_silver()
        pipeline = EmbeddingPipeline()
        metrics = pipeline.embed_breaches(breaches)
        assert metrics.records_processed == len(breaches)
        assert metrics.errors == 0

    @pytest.mark.asyncio
    async def test_embedding_vector_dimension(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()
        pipeline.embed_incidents(incidents[:1])
        emb = next(iter(pipeline._embeddings.values()))
        assert len(emb.embedding) == EMBEDDING_DIM

    @pytest.mark.asyncio
    async def test_embedding_is_normalized(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()
        pipeline.embed_incidents(incidents[:1])
        emb = next(iter(pipeline._embeddings.values()))
        magnitude = sum(v * v for v in emb.embedding) ** 0.5
        assert abs(magnitude - 1.0) < 0.01  # Unit vector


class TestEmbeddingCache:
    """Caching behavior tests."""

    @pytest.mark.asyncio
    async def test_duplicate_text_hits_cache(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()

        # Embed once (no cache hit)
        pipeline.embed_incidents(incidents[:1])
        # Embed same record again - should be cache hit
        metrics = pipeline.embed_incidents(incidents[:1])
        assert metrics.cache_hits >= 1

    @pytest.mark.asyncio
    async def test_cache_reduces_api_calls(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()

        # First pass: no cache
        m1 = pipeline.embed_incidents(incidents)
        first_api_calls = m1.api_calls

        # Second pass: all cache hits
        m2 = pipeline.embed_incidents(incidents)
        assert m2.cache_hits == len(incidents)
        assert m2.api_calls == 0


class TestSemanticSearch:
    """Semantic search tests."""

    @pytest.mark.asyncio
    async def test_search_empty_index_returns_empty(self):
        pipeline = EmbeddingPipeline()
        results = pipeline.semantic_search("DNS failure")
        assert results == []

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        incidents, _, _ = await _load_silver()
        pipeline = EmbeddingPipeline()
        pipeline.embed_incidents(incidents)
        results = pipeline.semantic_search("DNS resolution failure", top_k=3)
        assert len(results) <= 3
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_search_results_sorted_by_score(self):
        incidents, vulns, breaches = await _load_silver()
        pipeline = EmbeddingPipeline()
        pipeline.embed_incidents(incidents)
        pipeline.embed_vulnerabilities(vulns)
        results = pipeline.semantic_search("critical vulnerability", top_k=5)
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].similarity_score >= results[i + 1].similarity_score


class TestIndexBuilding:
    """Embedding index building tests."""

    @pytest.mark.asyncio
    async def test_build_index_empty(self):
        pipeline = EmbeddingPipeline()
        index = pipeline.build_index()
        assert index["total_embeddings"] == 0
        assert index["embedding_dim"] == EMBEDDING_DIM
        assert index["model"] == "text-embedding-3-small"

    @pytest.mark.asyncio
    async def test_build_index_with_data(self):
        incidents, vulns, breaches = await _load_silver()
        pipeline = EmbeddingPipeline()
        pipeline.embed_incidents(incidents)
        pipeline.embed_vulnerabilities(vulns)
        pipeline.embed_breaches(breaches)

        index = pipeline.build_index()
        assert index["total_embeddings"] == len(incidents) + len(vulns) + len(breaches)
        assert "incident" in index["by_type"]
        assert "vulnerability" in index["by_type"]
        assert "breach" in index["by_type"]
