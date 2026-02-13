# Security Data Fabric - Production Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Secret Management](#secret-management)
4. [Database Initialization](#database-initialization)
5. [Container Deployment](#container-deployment)
6. [Health Checks](#health-checks)
7. [Monitoring Setup](#monitoring-setup)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)
10. [Scaling Considerations](#scaling-considerations)

---

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended) or equivalent
- **CPU**: Minimum 4 cores (8+ recommended for production)
- **RAM**: Minimum 8GB (16GB+ recommended)
- **Storage**: Minimum 50GB SSD
- **Network**: Static IP with firewall configured

### Software Dependencies
```bash
# Docker Engine 24.0+
docker --version

# Docker Compose 2.20+
docker compose version

# OpenSSL (for secret generation)
openssl version

# PostgreSQL Client (for database operations)
psql --version
```

### Install Docker (if needed)
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Start Docker service
sudo systemctl enable docker
sudo systemctl start docker
```

---

## Environment Setup

### 1. Clone Repository
```bash
git clone https://github.com/your-org/security-data-fabric.git
cd security-data-fabric
```

### 2. Create Environment File
```bash
# Copy example environment file
cp .env.example .env

# Edit with your configuration
nano .env  # or vim, vi, etc.
```

### 3. Generate Secure Secrets
```bash
# Generate SECRET_KEY (256-bit)
SECRET_KEY=$(openssl rand -hex 32)

# Generate JWT_SECRET_KEY (256-bit)
JWT_SECRET_KEY=$(openssl rand -hex 32)

# Generate ENCRYPTION_KEY (256-bit, base64 encoded)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Generate strong database password
POSTGRES_PASSWORD=$(openssl rand -base64 24)

# Generate Redis password
REDIS_PASSWORD=$(openssl rand -base64 24)

# Save to .env file
echo "SECRET_KEY=$SECRET_KEY" >> .env
echo "JWT_SECRET_KEY=$JWT_SECRET_KEY" >> .env
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env
echo "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" >> .env
echo "REDIS_PASSWORD=$REDIS_PASSWORD" >> .env
```

### 4. Set Proper Permissions
```bash
# Secure environment file
chmod 600 .env

# Create log directory
mkdir -p logs
chmod 755 logs
```

---

## Secret Management

### Using Azure Key Vault (Recommended)

```bash
# 1. Create Azure Key Vault
az keyvault create \
  --name security-fabric-kv \
  --resource-group your-resource-group \
  --location eastus

# 2. Store secrets
az keyvault secret set --vault-name security-fabric-kv --name SECRET-KEY --value "$SECRET_KEY"
az keyvault secret set --vault-name security-fabric-kv --name JWT-SECRET-KEY --value "$JWT_SECRET_KEY"
az keyvault secret set --vault-name security-fabric-kv --name ENCRYPTION-KEY --value "$ENCRYPTION_KEY"
az keyvault secret set --vault-name security-fabric-kv --name POSTGRES-PASSWORD --value "$POSTGRES_PASSWORD"
az keyvault secret set --vault-name security-fabric-kv --name REDIS-PASSWORD --value "$REDIS_PASSWORD"

# 3. Grant access to service principal
az keyvault set-policy \
  --name security-fabric-kv \
  --spn YOUR_CLIENT_ID \
  --secret-permissions get list
```

### Using Docker Secrets (Alternative)
```bash
# Initialize Docker Swarm
docker swarm init

# Create secrets
echo "$SECRET_KEY" | docker secret create secret_key -
echo "$JWT_SECRET_KEY" | docker secret create jwt_secret_key -
echo "$POSTGRES_PASSWORD" | docker secret create postgres_password -
echo "$REDIS_PASSWORD" | docker secret create redis_password -
```

---

## Database Initialization

### 1. Create Database Initialization Script
```bash
mkdir -p init-scripts
cat > init-scripts/01-init.sql << 'EOF'
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- Create application schema
CREATE SCHEMA IF NOT EXISTS security_fabric;

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA security_fabric 
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO securityfabric;

ALTER DEFAULT PRIVILEGES IN SCHEMA security_fabric 
GRANT USAGE, SELECT ON SEQUENCES TO securityfabric;

-- Create audit table
CREATE TABLE IF NOT EXISTS security_fabric.audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    status VARCHAR(50),
    details JSONB,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX idx_audit_timestamp ON security_fabric.audit_log(timestamp);
CREATE INDEX idx_audit_user ON security_fabric.audit_log(user_id);
EOF
```

### 2. Run Database Migrations
```bash
# Wait for PostgreSQL to be ready
docker compose up -d postgres
sleep 10

# Run migrations using Alembic
docker compose exec app alembic upgrade head

# Verify migrations
docker compose exec postgres psql -U securityfabric -d security_fabric -c "\dt security_fabric.*"
```

---

## Container Deployment

### 1. Build Images
```bash
# Set build arguments
export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
export VERSION=$(cat pyproject.toml | grep version | head -1 | cut -d'"' -f2)

# Build application image
docker compose build --no-cache
```

### 2. Start Services
```bash
# Start all services
docker compose up -d

# Check service status
docker compose ps

# View logs
docker compose logs -f app
```

### 3. Verify Deployment
```bash
# Check API health
curl http://localhost:8000/health

# Check metrics endpoint
curl http://localhost:8000/metrics

# Check Prometheus
curl http://localhost:9090/-/healthy
```

---

## Health Checks

### Application Health Endpoint
```bash
# Basic health check
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","version":"1.0.0","timestamp":"2024-01-01T00:00:00Z"}
```

### Database Health
```bash
# Check PostgreSQL
docker compose exec postgres pg_isready -U securityfabric

# Check connections
docker compose exec postgres psql -U securityfabric -d security_fabric -c "SELECT count(*) FROM pg_stat_activity;"
```

### Redis Health
```bash
# Check Redis
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" PING

# Check memory usage
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" INFO memory
```

### Container Health
```bash
# Check all container health status
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# Check resource usage
docker stats --no-stream
```

---

## Monitoring Setup

### 1. Access Prometheus UI
```bash
# Open in browser
http://localhost:9090

# Query examples:
# - up{job="security-fabric-api"}
# - rate(http_requests_total[5m])
# - container_memory_usage_bytes
```

### 2. Configure Alerts (Optional)
```bash
# Create alerts directory
mkdir -p alerts

# Create alert rules
cat > alerts/api-alerts.yml << 'EOF'
groups:
  - name: api_alerts
    interval: 30s
    rules:
      - alert: APIHighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High API error rate detected"
          
      - alert: APIDown
        expr: up{job="security-fabric-api"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "API is down"
EOF
```

### 3. Set Up Grafana (Optional)
```bash
# Add Grafana to docker-compose.yml
cat >> docker-compose.yml << 'EOF'
  grafana:
    image: grafana/grafana:10.2.0
    container_name: sdf-grafana
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - monitoring
    restart: unless-stopped
EOF

# Restart services
docker compose up -d grafana
```

---

## Backup and Recovery

### Database Backup
```bash
# Create backup directory
mkdir -p backups

# Full database backup
docker compose exec -T postgres pg_dump \
  -U securityfabric \
  -d security_fabric \
  -F c \
  -b \
  -v \
  -f /tmp/backup.dump

# Copy backup from container
docker compose cp postgres:/tmp/backup.dump backups/security_fabric_$(date +%Y%m%d_%H%M%S).dump

# Automated backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="./backups"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Database backup
docker compose exec -T postgres pg_dump \
  -U securityfabric -d security_fabric -F c \
  > "$BACKUP_DIR/db_backup_$DATE.dump"

# Volume backup
docker run --rm \
  -v security-data-fabric_postgres_data:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/volumes_$DATE.tar.gz -C /data .

# Cleanup old backups
find $BACKUP_DIR -name "*.dump" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
EOF

chmod +x backup.sh

# Schedule with cron
echo "0 2 * * * /path/to/security-data-fabric/backup.sh" | crontab -
```

### Database Restore
```bash
# Stop application
docker compose stop app

# Restore database
docker compose exec -T postgres pg_restore \
  -U securityfabric \
  -d security_fabric \
  -c \
  --if-exists \
  < backups/security_fabric_YYYYMMDD_HHMMSS.dump

# Restart application
docker compose start app
```

---

## Troubleshooting

### Common Issues

#### 1. Container Won't Start
```bash
# Check logs
docker compose logs app

# Check system resources
df -h  # Disk space
free -h  # Memory
docker system df  # Docker disk usage

# Clean up Docker resources
docker system prune -a --volumes
```

#### 2. Database Connection Issues
```bash
# Test database connectivity
docker compose exec app python -c "
from sqlalchemy import create_engine
import os
engine = create_engine(os.getenv('DATABASE_URL'))
with engine.connect() as conn:
    print('Database connected successfully')
"

# Check PostgreSQL logs
docker compose logs postgres

# Verify credentials
docker compose exec postgres psql -U securityfabric -d security_fabric -c "SELECT 1;"
```

#### 3. Redis Connection Issues
```bash
# Test Redis connectivity
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" PING

# Check Redis logs
docker compose logs redis
```

#### 4. High Memory Usage
```bash
# Check container memory
docker stats --no-stream

# Restart containers with memory limits
docker compose restart

# Check for memory leaks in logs
docker compose logs app | grep -i "memory\|oom"
```

#### 5. Port Conflicts
```bash
# Check what's using ports
sudo lsof -i :8000
sudo lsof -i :5432
sudo lsof -i :6379

# Change ports in docker-compose.yml or .env
```

### Debug Mode
```bash
# Enable debug logging
echo "LOG_LEVEL=debug" >> .env

# Restart with verbose logging
docker compose up -d

# Follow logs
docker compose logs -f --tail=100 app
```

---

## Scaling Considerations

### Horizontal Scaling

#### 1. Multiple API Instances
```bash
# Scale API service
docker compose up -d --scale app=3

# Add load balancer (nginx)
cat > nginx.conf << 'EOF'
upstream api_backend {
    least_conn;
    server app:8000 max_fails=3 fail_timeout=30s;
    server app:8001 max_fails=3 fail_timeout=30s;
    server app:8002 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
```

#### 2. Database Read Replicas
```yaml
# Add to docker-compose.yml
postgres-replica:
  image: ankane/pgvector:v0.5.1
  environment:
    POSTGRES_PRIMARY_HOST: postgres
    POSTGRES_PRIMARY_PORT: 5432
  command: >
    postgres
    -c 'hot_standby=on'
    -c 'primary_conninfo=host=postgres port=5432 user=replicator'
```

#### 3. Redis Cluster
```bash
# Redis Sentinel for HA
# See Redis Sentinel documentation for cluster setup
```

### Vertical Scaling
```yaml
# Increase resources in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 8G
    reservations:
      cpus: '2.0'
      memory: 4G
```

### Kubernetes Deployment
```yaml
# Example Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-fabric-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-fabric-api
  template:
    metadata:
      labels:
        app: security-fabric-api
    spec:
      containers:
      - name: api
        image: security-fabric:1.0.0
        ports:
        - containerPort: 8000
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
```

---

## Production Checklist

- [ ] All secrets generated and stored securely
- [ ] Environment variables configured
- [ ] SSL/TLS certificates installed
- [ ] Firewall rules configured
- [ ] Database initialized and migrations applied
- [ ] Backup strategy implemented and tested
- [ ] Monitoring and alerting configured
- [ ] Log aggregation set up
- [ ] Health checks passing
- [ ] Performance testing completed
- [ ] Security audit completed
- [ ] Documentation updated
- [ ] Disaster recovery plan documented
- [ ] Team trained on operations

---

## Support and Maintenance

### Regular Maintenance Tasks
- **Daily**: Check logs, monitor metrics, verify backups
- **Weekly**: Review security alerts, update dependencies
- **Monthly**: Security patching, performance optimization
- **Quarterly**: Disaster recovery testing, capacity planning

### Getting Help
- Documentation: `/docs`
- Issue Tracker: GitHub Issues
- Security Issues: security@example.com
- Team Chat: Slack #security-fabric

---

## License
See [LICENSE](LICENSE) file for details.
