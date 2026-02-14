-- PostgreSQL Extensions for Security Data Fabric
-- This script runs during initial database setup

-- Enable pgvector for semantic search and embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable pg_stat_statements for query performance monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Enable pgcrypto for cryptographic functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable uuid-ossp for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Log extension installation
DO $$
BEGIN
  RAISE NOTICE 'Security Data Fabric: Database extensions initialized successfully';
  RAISE NOTICE 'Enabled extensions: vector, pg_stat_statements, pgcrypto, uuid-ossp';
END $$;
