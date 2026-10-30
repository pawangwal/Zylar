#!/bin/bash
set -e

echo "Initializing Zylar PostgreSQL database roles and object ownership..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v migration_password="${ZYLAR_MIGRATION_DB_PASSWORD:-dev_migration_pass_123}" \
  -v app_password="${ZYLAR_APP_DB_PASSWORD:-dev_app_pass_123}" \
  -v read_password="${ZYLAR_READ_DB_PASSWORD:-dev_read_pass_123}" \
  -f /scripts/sql/00_init_roles.sql

echo "Zylar PostgreSQL roles and permissions initialized successfully."

