# Search Layer - pgvector Semantic Search

The Search layer provides semantic search capabilities over security events, incidents, and predictions using pgvector and embeddings.

## Components

### 1. VectorStore (`vector_store.py`)

Low-level vector storage and retrieval using pgvector.

**Key Features:**
- Store embeddings with automatic deduplication
- IVFFlat indexing for performance
- Cosine similarity search
- Batch operations
- Embedding versioning

**Usage:**
```python
from src.search.vector_store import VectorStore

# Initialize with async session
store = VectorStore(session)

# Create IVFFlat index for performance
await store.create_index(lists=100)

# Store embedding
embedding_id = await store.store_embedding(
    source_type='event',
    source_id=event_id,
    text_content='CPU spike detected',
    embedding=embedding_vector,
    model_version='all-MiniLM-L6-v2'
)

# Search for similar embeddings
results = await store.search(
    query_embedding=query_vector,
    limit=10,
    min_similarity=0.5
)

# Batch storage
await store.store_embeddings_batch(embeddings_data)
```

### 2. SemanticSearch (`semantic_search.py`)

High-level natural language query interface.

**Key Features:**
- Natural language queries
- Flexible filtering (time, severity, source, entity)
- Pagination
- Find similar entities
- Result formatting with metadata

**Usage:**
```python
from src.search.semantic_search import SemanticSearch

# Initialize
search = SemanticSearch(session, embedding_engine)
await search.initialize()

# Natural language search
results = await search.search(
    query="What caused the authentication outage last Tuesday?",
    limit=10,
    severity=EventSeverity.CRITICAL,
    time_range=(start_time, end_time)
)

# Access results
for result in results:
    print(f"Type: {result.result_type}")
    print(f"Score: {result.similarity_score}")
    print(f"Data: {result.entity_data}")

# Paginated search
page_results = await search.search_paginated(
    query="database errors",
    page=1,
    page_size=20
)

# Find similar entities
similar = await search.find_similar(
    entity_type='incident',
    entity_id=incident_id,
    limit=5
)
```

## Integration with Database Models

The search layer integrates with existing models:

- **Embedding**: Stores vectors and metadata in PostgreSQL with pgvector
- **NormalizedEvent**: Silver layer events searchable by content
- **Incident**: Gold layer incidents searchable by description
- **Prediction**: ML predictions searchable by explanation

## Performance Considerations

1. **Indexing**: Create IVFFlat index after loading initial data
   ```python
   await vector_store.create_index(lists=rows/1000)
   ```

2. **Batch Operations**: Use batch methods for bulk operations
   ```python
   await vector_store.store_embeddings_batch(batch_data)
   ```

3. **Filtering**: Use database filters before vector search when possible

4. **Caching**: EmbeddingEngine caches embeddings automatically

## Example Queries

```python
# Find authentication issues
await search.search("authentication failures and login errors")

# Find similar incidents
await search.find_similar('incident', incident_id)

# Search with time filter
await search.search(
    "CPU exhaustion",
    time_range=(yesterday, today)
)

# Search by severity
await search.search(
    "critical alerts",
    severity=EventSeverity.CRITICAL
)

# Paginated results
page1 = await search.search_paginated("errors", page=1, page_size=10)
page2 = await search.search_paginated("errors", page=2, page_size=10)
```

## Error Handling

Both components raise specific exceptions:
- `VectorStoreError`: Vector storage/retrieval issues
- `SearchError`: Search operation failures

```python
from src.search.vector_store import VectorStoreError
from src.search.semantic_search import SearchError

try:
    results = await search.search("test query")
except SearchError as e:
    logger.error(f"Search failed: {e}")
```

## Testing

Run tests with:
```bash
pytest tests/test_search/ -v
```

Tests cover:
- Vector storage and retrieval
- Semantic search functionality
- Pagination and filters
- Error handling
- Edge cases
