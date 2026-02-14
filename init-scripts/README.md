# PostgreSQL Initialization Scripts

This directory contains SQL scripts that are automatically executed when the PostgreSQL container is first initialized. Scripts are executed in alphabetical order.

## Purpose

These scripts set up:
- Database extensions (pgvector)
- Initial schema
- Default users and permissions
- Database-level security settings

## Usage

1. Place `.sql` or `.sh` files in this directory
2. Scripts are executed once during initial database creation
3. Files are mounted read-only for security

## Security Considerations

- Scripts run as the `postgres` superuser during initialization only
- After initialization, the application uses a limited database user
- All scripts should follow principle of least privilege
- Never include secrets in scripts (use environment variables)

## Example Scripts

### 01-extensions.sql
```sql
-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

### 02-schema.sql
```sql
-- Create application schema
CREATE SCHEMA IF NOT EXISTS security_fabric;

-- Set search path
ALTER DATABASE security_fabric SET search_path TO security_fabric, public;
```

### 03-users.sql
```sql
-- Create application user with limited permissions
CREATE USER app_user WITH PASSWORD 'changeme';
GRANT CONNECT ON DATABASE security_fabric TO app_user;
GRANT USAGE ON SCHEMA security_fabric TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA security_fabric TO app_user;
```

## Notes

- Scripts in this directory are mounted as read-only volumes
- The directory is specified in `docker-compose.yml`:
  ```yaml
  volumes:
    - ./init-scripts:/docker-entrypoint-initdb.d:ro
  ```
- For sensitive operations, use environment variables from `.env`
