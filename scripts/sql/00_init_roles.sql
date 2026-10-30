-- =============================================================================
-- Zylar Phase 7: PostgreSQL Least-Privilege Role Setup & Object Ownership
-- =============================================================================
-- Roles:
--   1. zylar_migration: Administrative DDL owner role (owns schema and all objects).
--   2. zylar_app:       Runtime DML role (table-specific permissions, no DDL/DROP/TRUNCATE).
--   3. zylar_read:      Read-only audit role (SELECT only; excludes password hashes).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Idempotent Role Creation
-- (Passes are updated outside DO blocks to allow both psql variable substitution
-- and Python string replacement without syntax errors inside PL/pgSQL)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_migration') THEN
    CREATE ROLE zylar_migration WITH LOGIN;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_app') THEN
    CREATE ROLE zylar_app WITH LOGIN;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_read') THEN
    CREATE ROLE zylar_read WITH LOGIN;
  END IF;
END $$;

ALTER ROLE zylar_migration WITH PASSWORD :'migration_password';
ALTER ROLE zylar_app WITH PASSWORD :'app_password';
ALTER ROLE zylar_read WITH PASSWORD :'read_password';

-- -----------------------------------------------------------------------------
-- 2. Schema and Object Ownership Transfer to zylar_migration
-- -----------------------------------------------------------------------------
-- Grant CONNECT dynamically using current_database() to avoid hardcoding database name
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_migration', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_app', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_read', current_database());
END $$;

ALTER SCHEMA public OWNER TO zylar_migration;

-- Transfer ownership of all existing schema objects to zylar_migration
DO $$
DECLARE
  r RECORD;
BEGIN
  -- Tables
  FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
    EXECUTE 'ALTER TABLE public.' || quote_ident(r.tablename) || ' OWNER TO zylar_migration';
  END LOOP;

  -- Sequences
  FOR r IN (SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public') LOOP
    EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequence_name) || ' OWNER TO zylar_migration';
  END LOOP;

  -- Views
  FOR r IN (SELECT table_name FROM information_schema.views WHERE table_schema = 'public') LOOP
    EXECUTE 'ALTER VIEW public.' || quote_ident(r.table_name) || ' OWNER TO zylar_migration';
  END LOOP;

  -- Materialized Views
  FOR r IN (SELECT matviewname FROM pg_matviews WHERE schemaname = 'public') LOOP
    EXECUTE 'ALTER MATERIALIZED VIEW public.' || quote_ident(r.matviewname) || ' OWNER TO zylar_migration';
  END LOOP;

  -- Routines / Functions / Procedures (with identity arguments to handle function overloads unambiguously)
  FOR r IN (
    SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'public'
  ) LOOP
    EXECUTE format('ALTER ROUTINE public.%I(%s) OWNER TO zylar_migration', r.proname, r.args);
  END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- 3. Comprehensive Privilege Revocation (Remove broad/inherited grants first)
-- -----------------------------------------------------------------------------
REVOKE ALL ON SCHEMA public FROM PUBLIC, zylar_app, zylar_read;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, zylar_app, zylar_read;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, zylar_app, zylar_read;
REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM PUBLIC, zylar_app, zylar_read;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, zylar_app, zylar_read;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM PUBLIC, zylar_app, zylar_read;

-- Ensure default privileges do not leak broad access on future objects created by zylar_migration
ALTER DEFAULT PRIVILEGES FOR ROLE zylar_migration IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, zylar_app, zylar_read;
ALTER DEFAULT PRIVILEGES FOR ROLE zylar_migration IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, zylar_app, zylar_read;
ALTER DEFAULT PRIVILEGES FOR ROLE zylar_migration IN SCHEMA public
  REVOKE ALL ON ROUTINES FROM PUBLIC, zylar_app, zylar_read;

-- -----------------------------------------------------------------------------
-- 4. Table-Specific Least-Privilege Grants to zylar_app (Runtime DML only)
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO zylar_app;

-- Append-only audit logs: Strictly NO UPDATE, NO DELETE
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'audit_logs') THEN
    EXECUTE 'GRANT SELECT, INSERT ON TABLE public.audit_logs TO zylar_app';
  END IF;
END $$;

-- Operational tables: SELECT, INSERT, UPDATE; Strictly NO DELETE
DO $$
DECLARE
  t TEXT;
  tbls TEXT[] := ARRAY[
    'incidents',
    'ip_history',
    'user_history',
    'risk_history',
    'ingestion_checkpoints',
    'dead_letter_events',
    'worker_instances'
  ];
BEGIN
  FOREACH t IN ARRAY tbls LOOP
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = t) THEN
      EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.' || quote_ident(t) || ' TO zylar_app';
    END IF;
  END LOOP;
END $$;

-- Incident event references (Association records): SELECT, INSERT only; NO UPDATE, NO DELETE
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'incident_event_refs') THEN
    EXECUTE 'GRANT SELECT, INSERT ON TABLE public.incident_event_refs TO zylar_app';
  END IF;
END $$;

-- User identities: SELECT, Column-restricted INSERT & UPDATE (prevents runtime role escalation)
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users') THEN
    EXECUTE 'GRANT SELECT ON TABLE public.users TO zylar_app';
    -- Column-level INSERT explicitly excludes 'role' so zylar_app cannot provision admin users
    EXECUTE 'GRANT INSERT (id, username, hashed_password, disabled, created_at, updated_at) ON TABLE public.users TO zylar_app';
    -- Column-level UPDATE restricted to non-privileged state fields
    EXECUTE 'GRANT UPDATE (disabled, updated_at) ON TABLE public.users TO zylar_app';
  END IF;
END $$;

-- Sequence usage for nextval(); Strictly NO UPDATE (setval) to runtime roles
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO zylar_app;

-- Future sequence objects created by zylar_migration
ALTER DEFAULT PRIVILEGES FOR ROLE zylar_migration IN SCHEMA public
  GRANT USAGE ON SEQUENCES TO zylar_app;

-- -----------------------------------------------------------------------------
-- 5. Read-Only Audit Grants to zylar_read (SELECT only, excluding password hashes)
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO zylar_read;

DO $$
DECLARE
  t TEXT;
  tbls TEXT[] := ARRAY[
    'incidents',
    'incident_event_refs',
    'ip_history',
    'user_history',
    'risk_history',
    'audit_logs',
    'ingestion_checkpoints',
    'dead_letter_events',
    'worker_instances'
  ];
BEGIN
  FOREACH t IN ARRAY tbls LOOP
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = t) THEN
      EXECUTE 'GRANT SELECT ON TABLE public.' || quote_ident(t) || ' TO zylar_read';
    END IF;
  END LOOP;
END $$;

-- Sensitive user data protection: Provide users_public_view without hashed_password
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users') THEN
    EXECUTE 'CREATE OR REPLACE VIEW public.users_public_view AS ' ||
            'SELECT id, username, role, disabled, created_at, updated_at FROM public.users';
    EXECUTE 'ALTER VIEW public.users_public_view OWNER TO zylar_migration';
    EXECUTE 'GRANT SELECT ON TABLE public.users_public_view TO zylar_read';
    EXECUTE 'REVOKE ALL ON TABLE public.users FROM zylar_read';
  END IF;
END $$;
