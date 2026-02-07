# Architecture Documentation

## System Architecture

Security Data Fabric (SDF) implements a **medallion architecture** with four distinct layers for progressive data refinement and intelligence extraction.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     External Data Sources                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │Dynatrace │  │  Splunk  │  │ServiceNow│  │PagerDuty │           │
│  │  Metrics │  │   Logs   │  │ Incidents│  │  Alerts  │           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
└───────┼─────────────┼─────────────┼─────────────┼──────────────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────┐
│                  BRONZE LAYER (Raw Ingestion)                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ • Base Connector (rate limiting, retry, health checks)       │  │
│  │ • Source-specific connectors                                 │  │
│  │ • Raw event storage (raw_events table)                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────┬──────────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────┐
│            SILVER LAYER (Normalization & Cleaning)                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ • Event Normalizer (unified schema)                          │  │
│  │ • Deduplicator (content hash + time window)                  │  │
│  │ • Enricher (tags, classification, risk scoring)              │  │
│  │ • Normalized storage (normalized_events table)               │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────┬──────────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────┐
│              GOLD LAYER (Security Intelligence)                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ • Correlator (cross-source event correlation)                │  │
│  │ • Timeline Builder (incident reconstruction)                 │  │
│  │ • Root Cause Analyzer (probabilistic RCA)                    │  │
│  │ • Risk Scorer (asset/service risk assessment)                │  │
│  │ • Enriched storage (enriched_events table)                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────┬──────────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────┐
│                   ML & ANALYTICS LAYER                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ • Anomaly Detector (Z-score + Isolation Forest)              │  │
│  │ • Trajectory Predictor (time-to-breach)                      │  │
│  │ • Embedding Engine (sentence-transformers)                   │  │
│  │ • Forecaster (capacity planning)                             │  │
│  │ • Predictions storage (predictions table)                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────┬──────────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────────┐
│                  SEARCH & API LAYER                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ • Vector Store (pgvector)                                    │  │
│  │ • Semantic Search                                            │  │
│  │ • REST API (17+ endpoints)                                   │  │
│  │ • Alert Manager (multi-channel)                              │  │
│  │ • Embeddings storage (embeddings table)                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Interactions

### Data Flow

1. **Ingestion** → Connectors poll/receive data from sources
2. **Normalization** → Events mapped to unified schema
3. **Deduplication** → Duplicate events filtered
4. **Enrichment** → Tags, risk scores added
5. **Correlation** → Cross-source relationships identified
6. **ML Analysis** → Anomalies detected, predictions made
7. **Embedding** → Text vectorized for semantic search
8. **API** → Data served via REST endpoints
9. **Alerting** → Critical events routed to destinations

## Database Schema

### Core Tables

**raw_events** (Bronze)
- Raw ingested data
- Source identification
- Processing flag

**normalized_events** (Silver)
- Unified schema
- Severity normalization
- Content hash for dedup

**enriched_events** (Gold)
- Risk scores
- Tags & classifications
- Correlations
- Root cause analysis

**predictions** (ML)
- Anomaly predictions
- Time-to-breach forecasts
- Confidence scores

**embeddings** (Search)
- Vector embeddings (384-dim)
- Text content
- pgvector index

**alerts** (Alerting)
- Alert history
- Delivery status
- Deduplication tracking

**incident_timelines** (Intelligence)
- Reconstructed timelines
- Root cause
- Impact analysis

## Scalability Considerations

### Current Capacity

- **Ingestion**: 1000+ events/sec per connector
- **Search**: <100ms p95 latency
- **Correlation**: Real-time (<5s for 30-min window)
- **Storage**: ~2.5x overhead (Bronze→Silver→Gold)

### Scaling Strategies

**Horizontal Scaling**
- Add more API instances behind load balancer
- Connector instances can run independently
- Database read replicas for queries

**Vertical Scaling**
- Increase database resources
- More CPU for ML processing
- More memory for caching

**Data Retention**
- Bronze: 7 days
- Silver: 30 days
- Gold: 90 days
- Aggregates: 1 year

## Security Architecture

### Authentication & Authorization
- JWT tokens (HS256)
- Role-based access control
- API key for service-to-service

### Data Protection
- TLS/SSL for all connections
- Environment variable secrets
- No PII collection
- Audit logging

### Network Security
- Rate limiting (60 req/min)
- CORS configuration
- Security headers
- Input validation

## Technology Choices

### Why PostgreSQL + pgvector?
- Single database for relational + vector data
- ACID guarantees
- Mature tooling
- Lower operational complexity than separate vector DB

### Why sentence-transformers?
- Local execution (no API costs)
- Privacy (data doesn't leave system)
- Fast inference (<50ms)
- Good quality (768-dim embeddings)

### Why FastAPI?
- Async/await support
- Auto-generated OpenAPI docs
- Type checking with Pydantic
- High performance

### Why scikit-learn?
- Production-ready ML
- No GPU required
- Explainable models
- Standard library

## Monitoring & Observability

### Metrics Collected
- Ingestion rate per source
- Processing latency
- Correlation matches
- Prediction accuracy
- API response times
- Error rates

### Logs
- Structured JSON logging
- Request ID tracking
- Correlation IDs
- Error stack traces

### Health Checks
- `/health` - Basic liveness
- `/ready` - Database connectivity
- Connector health status

## Future Enhancements

1. **Streaming**: Apache Kafka for real-time ingestion
2. **Time-series**: TimescaleDB for metric storage
3. **Distributed Tracing**: OpenTelemetry
4. **Advanced ML**: AutoML, deep learning
5. **Multi-tenancy**: Tenant isolation for SaaS
6. **Graph Database**: Neo4j for complex relationships
7. **Real-time Dashboards**: WebSocket updates
8. **Mobile App**: iOS/Android clients

## Deployment Patterns

### Single Server
- Docker Compose
- All services on one host
- Good for: Dev, testing, small deployments

### Multi-Server
- Separate database server
- Multiple API instances
- Load balancer
- Good for: Production, high availability

### Kubernetes
- Helm charts
- Auto-scaling
- Service mesh
- Good for: Enterprise, cloud-native

## Performance Tuning

### Database
- Connection pooling (20 connections)
- Prepared statements
- Index optimization
- Query caching

### API
- Response caching (Redis)
- Async I/O
- Request batching
- Connection reuse

### ML
- Model caching
- Batch predictions
- Feature pre-computation
- Embedding cache

## Disaster Recovery

### Backup Strategy
- Database: Daily full + hourly incremental
- Configuration: Version controlled
- Models: Stored in object storage

### Recovery Time
- RTO: 1 hour
- RPO: 1 hour

### High Availability
- Database replication
- API load balancing
- Health check monitoring
- Automatic failover
