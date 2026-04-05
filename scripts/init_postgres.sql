-- Initial PostgreSQL setup for Email Threat Analysis System
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Ensure database exists
SELECT 'Database initialized' as status;
