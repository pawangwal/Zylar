# ADR-005: Least-Privilege PostgreSQL Roles, Durable Identity, and Secret Hygiene

## Context and Problem Statement

A security platform must uphold the highest standards of defense-in-depth and operational security. Prior to Phase 7, the application connected to PostgreSQL using a shared administrative account, user authentication fell back to an in-memory dictionary, and database credentials lacked column-level restrictions.

This introduced severe attack vectors:
1. **Application Compromise**: A SQL injection or code execution vulnerability in the API or worker runtime could allow an attacker to `DROP` tables, alter schemas, or extract password hashes.
2. **Privilege Elevation**: If the runtime application role could `INSERT` arbitrary rows into `users`, it could grant itself administrative roles (`role='ADMIN'`).
3. **Secret Leakage**: Hardcoded passwords, default credentials, or logging of database connection strings risked credential exfiltration.

## Decision Drivers

- Enforce strict database least-privilege role boundaries separating administrative DDL from runtime DML.
- Column-level insert restrictions to prevent unauthorized privilege elevation.
- Durable user identity in PostgreSQL protected with bcrypt hashing, avoiding in-memory state.
- Fail-closed secret hygiene across production and container deployments.

## Considered Options

1. **Single Application Database User**: Retain single user with table-level grants.
2. **Least-Privilege Three-Role Architecture with Column-Level Grants (Chosen)**:
   - `zylar_migration`: DDL owner role.
   - `zylar_app`: Runtime DML role with column restrictions.
   - `zylar_read`: Read-only audit role.

## Decision Outcome

Chosen option: **Three-Role Least-Privilege Architecture (Option 2)**.

### Architectural Rules:
1. **Role Separation**:
   - `zylar_migration` owns the `public` schema and all tables/sequences. Only the one-shot `migration` container connects as `zylar_migration`.
   - `zylar_app` receives table-specific DML: `SELECT`, `INSERT`, `UPDATE`, `DELETE`. It has zero `CREATE`, `ALTER`, `DROP`, or `TRUNCATE` privileges.
2. **Column-Level Restrictions**:
   - On the `users` table, `zylar_app` is granted `INSERT` only on `(username, password_hash, full_name, email, disabled, created_at, updated_at)`.
   - `role` is excluded from runtime insert permissions and defaults to `'ANALYST'`. Administrative promotion requires an explicit administrative operation.
   - `zylar_app` can only `UPDATE` `(disabled, updated_at)`.
3. **Transaction-Safe Identity Bootstrap**:
   - Initial administrative user bootstrap occurs under an explicit advisory transaction lock (`SELECT pg_advisory_xact_lock(742109)`).
   - In production (`ZYLAR_ENVIRONMENT=production`), fallback to default or in-memory credentials is strictly prohibited and fails closed.
4. **Secret Masking & Sanitization**:
   - All connection strings mask passwords in logs (`mask_db_url`).
   - Pydantic models store passwords as `SecretStr`.

### Consequences

#### Positive:
- Strong defense-in-depth: Even full compromise of the API container cannot drop database tables or modify schema.
- Immutable privilege boundary: An attacker cannot escalate a standard user to administrator via the application runtime role.
- Audit compliance: Meets SOC 2 and ISO 27001 requirements for database role segregation and credential hygiene.

#### Negative:
- Role provisioning step: Setting up a fresh PostgreSQL database requires running `scripts/setup_postgres_roles.py` or entrypoint initialization.

