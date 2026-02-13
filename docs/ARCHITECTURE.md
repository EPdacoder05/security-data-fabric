# Security Data Fabric - System Architecture

## Table of Contents
1. [Overview](#overview)
2. [Medallion Architecture](#medallion-architecture)
3. [System Components](#system-components)
4. [Data Flow](#data-flow)
5. [Security Layers](#security-layers)
6. [Integration Points](#integration-points)
7. [Technology Stack](#technology-stack)
8. [Deployment Architecture](#deployment-architecture)

---

## Overview

The Security Data Fabric is a unified security data platform that implements a **Medallion Architecture** (Bronze → Silver → Gold) for progressive data refinement, combined with ML-based anomaly detection and predictive analytics.

### Key Features
- Multi-source security data ingestion
- Progressive data quality improvement (Bronze/Silver/Gold)
- Real-time threat detection with ML
- Vector-based similarity search for threat intelligence
- Comprehensive audit logging and compliance
- Multi-tenancy with RBAC
- Enterprise SSO integration (Azure AD, Okta)

---

## Medallion Architecture

The Medallion Architecture organizes data into three progressive layers of quality and refinement:

```
┌─────────────────────────────────────────────────────────────┐
│                     DATA SOURCES                             │
│  SIEM │ EDR │ Firewall │ Cloud Logs │ Vulnerability Scans  │
└──────────────────┬──────────────────────────────────────────┘
                   │
         ┌─────────▼─────────┐
         │   BRONZE LAYER    │  Raw ingested data
         │  ┌──────────────┐ │  - Original format
         │  │ Raw Events   │ │  - Minimal validation
         │  │ Unstructured │ │  - Complete history
         │  └──────────────┘ │  - Append-only
         └─────────┬─────────┘
                   │ Cleansing, Validation
         ┌─────────▼─────────┐
         │   SILVER LAYER    │  Cleaned & validated
         │  ┌──────────────┐ │  - Standardized schema
         │  │ Normalized   │ │  - Data quality rules
         │  │ Enriched     │ │  - Deduplication
         │  └──────────────┘ │  - Type enforcement
         └─────────┬─────────┘
                   │ Aggregation, ML Processing
         ┌─────────▼─────────┐
         │    GOLD LAYER     │  Business-ready data
         │  ┌──────────────┐ │  - Aggregated metrics
         │  │ Analytics    │ │  - ML predictions
         │  │ Reports      │ │  - Threat intelligence
         │  └──────────────┘ │  - Optimized queries
         └───────────────────┘
                   │
         ┌─────────▼─────────┐
         │   PRESENTATION    │
         │  API │ Dashboard  │
         └───────────────────┘
```

### Bronze Layer (Raw Data)
**Purpose**: Capture all raw data exactly as received from sources.

**Characteristics**:
- **Format**: Original structure preserved (JSON, XML, CEF, etc.)
- **Validation**: Minimal (source identity, timestamp)
- **Storage**: Append-only, immutable
- **Use Cases**: Forensics, reprocessing, audit trails

**Tables**:
- `bronze_events` - Raw security events
- `bronze_logs` - Raw log data
- `bronze_alerts` - Raw alerts from sources

**Example**:
```json
{
  "source": "azure_sentinel",
  "raw_data": "{\"TimeGenerated\":\"2024-01-01T10:00:00Z\",\"AlertName\":\"Suspicious Login\"...}",
  "ingestion_timestamp": "2024-01-01T10:00:01Z",
  "source_id": "azure-prod-001"
}
```

### Silver Layer (Cleansed Data)
**Purpose**: Standardized, validated, enriched data ready for analysis.

**Characteristics**:
- **Format**: Normalized schema (relational)
- **Validation**: Data quality rules enforced
- **Enrichment**: GeoIP, threat intel, user context
- **Deduplication**: Events merged and deduplicated
- **Use Cases**: Dashboards, basic analytics, searches

**Tables**:
- `silver_security_events` - Normalized security events
- `silver_alerts` - Processed and enriched alerts
- `silver_user_activities` - User behavior data

**Transformations**:
1. Parse raw data into structured format
2. Validate data types and required fields
3. Enrich with external data (GeoIP, threat feeds)
4. Normalize timestamps to UTC
5. Deduplicate events
6. Apply data quality scoring

**Example**:
```json
{
  "event_id": "uuid",
  "event_type": "authentication",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "source_country": "US",
  "user_id": "user@example.com",
  "timestamp": "2024-01-01T10:00:00Z",
  "is_threat": false,
  "threat_score": 0.15,
  "enrichment": {
    "ip_reputation": "clean",
    "user_risk_score": 0.2
  }
}
```

### Gold Layer (Analytics-Ready)
**Purpose**: Aggregated, ML-enhanced data optimized for business intelligence.

**Characteristics**:
- **Format**: Aggregated metrics, ML predictions
- **Processing**: Statistical analysis, ML models
- **Optimization**: Pre-computed for fast queries
- **Use Cases**: Executive dashboards, predictions, compliance reports

**Tables**:
- `gold_threat_metrics` - Aggregated threat statistics
- `gold_user_risk_profiles` - User risk assessments
- `gold_compliance_reports` - Compliance status
- `gold_predictions` - ML-based predictions

**Features**:
- Time-series aggregations (hourly, daily, monthly)
- Anomaly detection results
- Threat predictions
- User behavior analytics (UEBA)
- Compliance score calculations

**Example**:
```json
{
  "metric_id": "uuid",
  "metric_type": "threat_summary",
  "period": "2024-01-01",
  "granularity": "daily",
  "data": {
    "total_events": 1500000,
    "threats_detected": 45,
    "critical_alerts": 5,
    "anomalies_found": 12,
    "top_threat_types": ["malware", "phishing", "ransomware"],
    "risk_score": 0.35,
    "trend": "increasing"
  },
  "ml_insights": {
    "predicted_threats_24h": 8,
    "confidence": 0.87
  }
}
```

---

## System Components

```
┌────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                             │
│  Web Dashboard │ CLI Tools │ External Systems (SIEM, SOAR)     │
└────────────────┬───────────────────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────────────────┐
│                        API GATEWAY                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ Rate Limit   │  │ Auth/AuthZ   │  │  Validation  │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
└────────────────┬───────────────────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────────────────┐
│                    APPLICATION SERVICES                         │
│  ┌───────────────────────────────────────────────────────┐    │
│  │  Ingestion      Analytics       Compliance   ML/AI    │    │
│  │  Service        Service          Service     Service  │    │
│  └───────────────────────────────────────────────────────┘    │
└────────────────┬───────────────────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────────────────┐
│                      DATA LAYER                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ PostgreSQL   │  │    Redis     │  │   pgvector   │        │
│  │  (Primary)   │  │   (Cache)    │  │  (Vectors)   │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
└────────────────────────────────────────────────────────────────┘
                 │
┌────────────────▼───────────────────────────────────────────────┐
│                   MONITORING & SECURITY                         │
│  Prometheus │ Audit Logs │ Encryption │ Secret Management     │
└────────────────────────────────────────────────────────────────┘
```

### 1. API Gateway
- **FastAPI**: High-performance async web framework
- **Authentication**: JWT tokens, API keys, OAuth2
- **Rate Limiting**: Per-user/per-endpoint limits
- **Request Validation**: Pydantic models
- **OpenAPI Documentation**: Auto-generated API docs

### 2. Ingestion Service
- **Connectors**: Azure Sentinel, Splunk, AWS Security Hub
- **Protocols**: REST API, Syslog, S3, Event Hubs
- **Processing**: Async batch and streaming ingestion
- **Validation**: Schema validation, data quality checks

### 3. Analytics Service
- **Query Engine**: Complex analytical queries
- **Aggregations**: Time-series rollups
- **Reporting**: Scheduled report generation
- **Export**: CSV, JSON, PDF formats

### 4. ML/AI Service
- **Anomaly Detection**: Isolation Forest, DBSCAN
- **Similarity Search**: Vector embeddings with pgvector
- **Predictions**: Threat forecasting
- **UEBA**: User behavior profiling

### 5. Compliance Service
- **Standards**: SOC 2, ISO 27001, GDPR, HIPAA, PCI-DSS
- **Checks**: Automated compliance validation
- **Reports**: Audit-ready documentation
- **Remediation**: Guidance and tracking

---

## Data Flow

### Ingestion Flow
```
1. Data Source → 2. API Gateway → 3. Validation → 4. Bronze Layer
                                         ↓
5. Enrichment Pipeline → 6. Silver Layer → 7. ML Processing → 8. Gold Layer
                                                                      ↓
                                                            9. Cache (Redis)
                                                                      ↓
                                                         10. API Response
```

**Detailed Steps**:

1. **Data Source**: External system sends data via API/webhook
2. **API Gateway**: Authentication, rate limiting, routing
3. **Validation**: Basic schema validation, source verification
4. **Bronze Layer**: Raw data stored as-is in PostgreSQL
5. **Enrichment Pipeline**: 
   - Parse and normalize data
   - Enrich with GeoIP, threat intel
   - Apply data quality rules
6. **Silver Layer**: Cleansed data stored
7. **ML Processing**: 
   - Anomaly detection
   - Vector embeddings
   - Predictions
8. **Gold Layer**: Analytics-ready data stored
9. **Cache**: Hot data cached in Redis
10. **API Response**: Return processed data to client

### Query Flow
```
1. Client Request → 2. API Gateway → 3. Authorization → 4. Cache Check
                                                              ↓ (miss)
                                                    5. Database Query
                                                              ↓
                                                    6. Result Processing
                                                              ↓
                                                    7. Cache Update
                                                              ↓
                                                    8. Response to Client
```

---

## Security Layers

### Layer 1: Network Security
- **Isolation**: Network segmentation (frontend/backend/monitoring)
- **Firewall**: Restricted port access
- **TLS**: Encrypted communication (TLS 1.3)
- **DDoS Protection**: Rate limiting, WAF integration

### Layer 2: Authentication
- **Multi-Factor**: TOTP, SMS, email verification
- **SSO Integration**: Azure AD, Okta SAML/OAuth2
- **Password Policy**: Complexity, rotation, history
- **Session Management**: JWT with short expiration, refresh tokens

### Layer 3: Authorization
- **RBAC**: Role-based access control
- **Attribute-Based**: Fine-grained permissions
- **Resource-Level**: Per-entity access control
- **Audit**: All access logged

### Layer 4: Data Security
- **Encryption at Rest**: AES-256 for sensitive fields
- **Encryption in Transit**: TLS 1.3
- **Key Management**: Azure Key Vault integration
- **PII Protection**: Automatic detection and masking

### Layer 5: Application Security
- **Input Validation**: Parameterized queries, input sanitization
- **Output Encoding**: XSS prevention
- **CSRF Protection**: Token-based
- **Security Headers**: HSTS, CSP, X-Frame-Options

### Layer 6: Monitoring & Audit
- **Audit Logging**: All actions logged immutably
- **Threat Detection**: Real-time anomaly detection
- **Metrics**: Prometheus monitoring
- **Alerting**: Critical security events

---

## Integration Points

### Data Sources
1. **SIEM Systems**
   - Azure Sentinel (REST API)
   - Splunk (REST API, HEC)
   - IBM QRadar (REST API)

2. **Cloud Providers**
   - AWS Security Hub
   - Azure Security Center
   - GCP Security Command Center

3. **EDR/XDR**
   - CrowdStrike
   - Carbon Black
   - Microsoft Defender

4. **Log Sources**
   - Syslog (RFC 5424)
   - Windows Event Logs
   - Application logs (JSON, CEF)

### Data Consumers
1. **Dashboards**: Grafana, Kibana, PowerBI
2. **SOAR**: Palo Alto Cortex, Splunk SOAR
3. **Ticketing**: ServiceNow, Jira
4. **BI Tools**: Tableau, Looker

### Authentication Providers
- Azure Active Directory
- Okta
- Auth0
- Custom LDAP/AD

---

## Technology Stack

### Backend
- **Language**: Python 3.11
- **Framework**: FastAPI 0.109
- **Async Runtime**: Uvicorn with uvloop
- **ORM**: SQLAlchemy 2.0 (async)

### Database
- **Primary Database**: PostgreSQL 15
- **Vector Search**: pgvector extension
- **Caching**: Redis 7.2
- **Connection Pool**: asyncpg

### Machine Learning
- **Framework**: scikit-learn 1.4
- **NLP**: sentence-transformers 2.3
- **Embeddings**: OpenAI GPT-4 (optional)
- **Anomaly Detection**: Isolation Forest, DBSCAN

### Security
- **Encryption**: cryptography 42.0 (AES-256-GCM)
- **JWT**: python-jose with cryptography
- **Password Hashing**: bcrypt
- **MFA**: pyotp (TOTP)
- **Secrets**: Azure Key Vault

### Monitoring
- **Metrics**: Prometheus client
- **Logging**: Python JSON Logger
- **Tracing**: OpenTelemetry (optional)
- **Health Checks**: Built-in endpoints

### DevOps
- **Containerization**: Docker 24+
- **Orchestration**: Docker Compose / Kubernetes
- **CI/CD**: GitHub Actions
- **Code Quality**: Ruff, Black, Mypy, Bandit

---

## Deployment Architecture

### Development Environment
```
Developer Laptop
├── Docker Compose (all services)
├── Hot reload enabled
└── Debug logging
```

### Staging Environment
```
Cloud VM (4 CPU, 16GB RAM)
├── Docker Compose
├── Separate DB instance
├── SSL/TLS enabled
└── Monitoring active
```

### Production Environment
```
Kubernetes Cluster
├── API Pods (3+ replicas)
│   ├── HPA (auto-scaling)
│   └── Rolling updates
├── PostgreSQL (managed service)
│   ├── Read replicas
│   └── Automated backups
├── Redis Cluster (3 nodes)
├── Load Balancer (HTTPS)
├── WAF (DDoS protection)
└── Monitoring Stack
    ├── Prometheus
    ├── Grafana
    └── Alertmanager
```

### High Availability Setup
```
┌─────────────────────────────────────────────────┐
│              Load Balancer (HA Proxy)           │
└──────────┬────────────────────┬─────────────────┘
           │                    │
    ┌──────▼──────┐      ┌──────▼──────┐
    │  API Node 1 │      │  API Node 2 │
    └──────┬──────┘      └──────┬──────┘
           │                    │
    ┌──────▼────────────────────▼──────┐
    │   PostgreSQL Primary + Replicas  │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────┐
    │ Redis Cluster│
    └─────────────┘
```

---

## Performance Considerations

### Database Optimization
- **Indexing**: Strategic indexes on query patterns
- **Partitioning**: Time-based partitioning for large tables
- **Connection Pooling**: Async pool with 20-50 connections
- **Query Optimization**: EXPLAIN ANALYZE for slow queries

### Caching Strategy
- **L1 Cache**: In-memory (application)
- **L2 Cache**: Redis (distributed)
- **TTL**: 5-60 minutes depending on data type
- **Invalidation**: Event-based cache invalidation

### Scaling Strategy
- **Horizontal**: Multiple API instances behind load balancer
- **Vertical**: Database read replicas
- **Sharding**: Future consideration for multi-tenancy
- **CDN**: Static assets via CDN

---

## Future Roadmap

1. **Phase 1** (Current): Core platform with medallion architecture
2. **Phase 2**: Advanced ML models, automated response
3. **Phase 3**: Multi-region deployment, global scale
4. **Phase 4**: AI-driven security orchestration

---

## References

- [Medallion Architecture](https://www.databricks.com/glossary/medallion-architecture)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [PostgreSQL Best Practices](https://wiki.postgresql.org/wiki/Don%27t_Do_This)
- [Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl/)
