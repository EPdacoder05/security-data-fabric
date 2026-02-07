# Operational Runbook

## Quick Reference

**Service Status**: `docker-compose ps`
**View Logs**: `docker-compose logs -f app`
**Restart Service**: `docker-compose restart app`
**Health Check**: `curl http://localhost:8000/health`

## Starting the Platform

### Initial Setup

```bash
# Clone repository
git clone https://github.com/EPdacoder05/security-data-fabric.git
cd security-data-fabric

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Start services
docker-compose up -d

# Verify all services are running
docker-compose ps

# Check logs
docker-compose logs -f
```

### Verify Installation

```bash
# Health check
curl http://localhost:8000/health

# API docs
open http://localhost:8000/docs

# Check database
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "SELECT COUNT(*) FROM raw_events;"
```

## Common Operations

### Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f postgres

# Last 100 lines
docker-compose logs --tail=100 app

# Filter by level
docker-compose logs app | grep ERROR
```

### Restarting Services

```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart app

# Full rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Database Operations

```bash
# Connect to database
docker-compose exec postgres psql -U sdf_user -d sdf_db

# Backup database
docker-compose exec postgres pg_dump -U sdf_user sdf_db > backup.sql

# Restore database
docker-compose exec -T postgres psql -U sdf_user -d sdf_db < backup.sql

# Check table sizes
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
  FROM pg_tables
  WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

### Monitoring

```bash
# Check resource usage
docker stats

# Check disk space
df -h

# Active connections
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  SELECT count(*) FROM pg_stat_activity;
"

# Query performance
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  SELECT query, mean_exec_time, calls
  FROM pg_stat_statements
  ORDER BY mean_exec_time DESC
  LIMIT 10;
"
```

## Troubleshooting

### Service Won't Start

**Symptom**: `docker-compose up` fails

**Solution**:
```bash
# Check logs
docker-compose logs app

# Common issues:
# 1. Port already in use
lsof -i :8000
# Kill process or change port in docker-compose.yml

# 2. Database connection failed
docker-compose logs postgres
# Check DATABASE_URL in .env

# 3. Missing dependencies
docker-compose build --no-cache
```

### High Memory Usage

**Symptom**: System running out of memory

**Solution**:
```bash
# Check memory usage
docker stats

# Restart services to free memory
docker-compose restart

# Reduce pool size in .env
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=5

# Clear caches
docker-compose exec redis redis-cli FLUSHALL
```

### Slow Queries

**Symptom**: API responses taking >1 second

**Solution**:
```bash
# Enable query logging
# In .env: LOG_LEVEL=DEBUG

# Check slow queries
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  SELECT query, mean_exec_time, calls
  FROM pg_stat_statements
  WHERE mean_exec_time > 1000
  ORDER BY mean_exec_time DESC;
"

# Add missing indexes
# Review src/database/models.py for index definitions
```

### Connector Errors

**Symptom**: No data from specific source

**Solution**:
```bash
# Check connector health
curl http://localhost:8000/connectors/{source}/health

# Check credentials
# Verify in .env: DYNATRACE_API_TOKEN, etc.

# Test connector manually
curl -X POST http://localhost:8000/ingest/dynatrace \
  -H "Content-Type: application/json" \
  -d '{"source_id": "test", "raw_data": {}}'

# Check logs for errors
docker-compose logs app | grep "dynatrace"
```

### Database Connection Pool Exhausted

**Symptom**: "QueuePool limit exceeded"

**Solution**:
```bash
# Increase pool size in .env
DATABASE_POOL_SIZE=30
DATABASE_MAX_OVERFLOW=20

# Restart service
docker-compose restart app

# Check active connections
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  SELECT count(*), state
  FROM pg_stat_activity
  GROUP BY state;
"
```

### Disk Space Running Out

**Symptom**: Database errors, slow performance

**Solution**:
```bash
# Check disk usage
df -h

# Clean up Docker
docker system prune -a

# Archive old data
docker-compose exec postgres psql -U sdf_user -d sdf_db -c "
  DELETE FROM raw_events WHERE ingested_at < NOW() - INTERVAL '7 days';
  DELETE FROM normalized_events WHERE created_at < NOW() - INTERVAL '30 days';
  VACUUM FULL;
"

# Implement data retention policy
# Add to cron: 0 2 * * * /path/to/cleanup.sh
```

## Alert Response Procedures

### Critical Prediction Alert

**Alert**: "CPU exhaustion predicted in 5 minutes"

**Response**:
1. Verify current metrics: `GET /dashboard/overview`
2. Check incident timeline: `GET /incidents/{id}/timeline`
3. Review correlated events for root cause
4. Take action: Scale resources or restart services
5. Document in incident timeline

### Anomaly Detection Alert

**Alert**: "Anomaly detected: Z-score 4.5"

**Response**:
1. Check anomaly details: `GET /predictions/{id}`
2. Review historical baseline
3. Correlate with recent deployments/changes
4. Investigate affected services
5. Create incident if needed

### Integration Failure

**Alert**: "Dynatrace connector health check failed"

**Response**:
1. Check connector logs
2. Verify credentials: `DYNATRACE_API_TOKEN`
3. Test API access manually
4. Check network connectivity
5. Restart connector if needed

## Maintenance Tasks

### Daily
- [ ] Check service health
- [ ] Review error logs
- [ ] Monitor disk space
- [ ] Verify data ingestion

### Weekly
- [ ] Review performance metrics
- [ ] Check database growth
- [ ] Test backup restoration
- [ ] Update dependencies (Dependabot PRs)

### Monthly
- [ ] Review and optimize queries
- [ ] Audit user access
- [ ] Check security scan results
- [ ] Update documentation

### Quarterly
- [ ] Disaster recovery drill
- [ ] Capacity planning review
- [ ] Security audit
- [ ] Performance testing

## Backup & Recovery

### Creating Backups

```bash
# Full backup
./scripts/backup.sh

# Database only
docker-compose exec postgres pg_dump -U sdf_user -Fc sdf_db > backup.dump

# Configuration backup
tar -czf config-backup.tar.gz .env docker-compose.yml
```

### Restoring from Backup

```bash
# Stop services
docker-compose down

# Restore database
docker-compose up -d postgres
docker-compose exec -T postgres pg_restore -U sdf_user -d sdf_db < backup.dump

# Start all services
docker-compose up -d

# Verify
curl http://localhost:8000/health
```

## Performance Tuning

### Database Optimization

```sql
-- Analyze tables
ANALYZE raw_events;
ANALYZE normalized_events;
ANALYZE enriched_events;

-- Reindex
REINDEX DATABASE sdf_db;

-- Update statistics
VACUUM ANALYZE;
```

### API Optimization

```bash
# Increase workers
# In .env: API_WORKERS=8

# Enable caching
# Configure Redis caching layer

# Connection pooling
# In .env: DATABASE_POOL_SIZE=30
```

## Security Incidents

### Suspicious API Activity

1. Check API logs for unusual patterns
2. Review rate limiting logs
3. Identify source IP
4. Block if necessary: Update firewall rules
5. Rotate JWT secret if compromised

### Data Breach

1. Immediately isolate affected systems
2. Preserve logs and evidence
3. Notify security team
4. Initiate incident response plan
5. Review access logs
6. Rotate all credentials

## Scaling Operations

### Horizontal Scaling

```bash
# Add more API instances
docker-compose up -d --scale app=3

# Add load balancer
# Use nginx or HAProxy

# Configure health checks
# Monitor instance health
```

### Vertical Scaling

```bash
# Increase container resources
# In docker-compose.yml:
#   resources:
#     limits:
#       cpus: '2'
#       memory: 4G
```

## Contacts

- **On-Call Engineer**: [Your paging system]
- **Database Admin**: [DBA contact]
- **Security Team**: [Security contact]
- **Vendor Support**: See integration documentation

## Additional Resources

- Architecture: `docs/architecture.md`
- API Reference: `docs/api_reference.md`
- Integration Guide: `docs/integration_guide.md`
- GitHub Issues: https://github.com/EPdacoder05/security-data-fabric/issues
