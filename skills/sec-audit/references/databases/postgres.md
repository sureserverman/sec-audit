# PostgreSQL

## Source

- https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
- https://www.postgresql.org/docs/current/sql-grant.html
- https://www.postgresql.org/docs/current/runtime-config-connection.html
- https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- https://cisecurity.org/benchmark/postgresql

## Scope

Covers PostgreSQL 13 through 16 server configuration, role management,
`pg_hba.conf`, SSL/TLS, and PL/pgSQL security patterns. Does not cover
client-library parameterization (see application-layer references) or
managed-service specifics (AWS RDS, Azure Flexible Server) beyond
configuration options that map to the same settings.

## Dangerous patterns (regex/AST hints)

### pg_hba.conf trust authentication — CWE-287

- Why: `trust` auth method allows any OS user to connect as any PostgreSQL role without a password, enabling privilege escalation from any local code execution.
- Grep: `\btrust\b`
- File globs: `**/pg_hba.conf`
- Source: https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

### SSL disabled or not required — CWE-319

- Why: `ssl = off` or `sslmode=disable` in client connections transmits credentials and data in plaintext over the network.
- Grep: `ssl\s*=\s*off|sslmode\s*=\s*disable|sslmode\s*=\s*allow`
- File globs: `**/postgresql.conf`, `**/*.conf`, `**/.env`, `**/database.yml`
- Source: https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-SSL

### Public schema default privileges — CWE-732

- Why: In PostgreSQL < 15, the `public` schema grants CREATE to all roles by default, allowing unprivileged users to create objects and trojan-horse trusted functions.
- Grep: `GRANT.*public|public.*schema` — check for absence of `REVOKE CREATE ON SCHEMA public FROM PUBLIC`
- File globs: `**/init.sql`, `**/*.sql`, `**/migrations/**`
- Source: https://www.postgresql.org/docs/current/sql-revoke.html

### SECURITY DEFINER function without search_path lock — CWE-264

- Why: A `SECURITY DEFINER` function that does not set `search_path = pg_catalog, public` is vulnerable to search_path injection — an attacker with CREATE in any schema can shadow functions it calls.
- Grep: `SECURITY DEFINER`
- File globs: `**/*.sql`
- Source: https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY

### COPY FROM PROGRAM — CWE-78

- Why: `COPY ... FROM PROGRAM 'cmd'` executes an OS command as the postgres OS user; if reachable by a low-privilege role, it enables local privilege escalation.
- Grep: `COPY\s+.*FROM\s+PROGRAM|copy\s+.*from\s+program`
- File globs: `**/*.sql`, `**/migrations/**`
- Source: https://www.postgresql.org/docs/current/sql-copy.html

## Secure patterns

```
# pg_hba.conf — require scram-sha-256 for all connections
# TYPE  DATABASE  USER    ADDRESS       METHOD
local   all       all                   scram-sha-256
host    all       all     127.0.0.1/32  scram-sha-256
host    all       all     ::1/128       scram-sha-256
hostssl all       all     0.0.0.0/0     scram-sha-256
```

Source: https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

```sql
-- Revoke public schema CREATE in PostgreSQL < 15
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Restrict role to only necessary privileges
GRANT CONNECT ON DATABASE mydb TO app_role;
GRANT USAGE ON SCHEMA public TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_role;
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

```sql
-- SECURITY DEFINER with locked search_path
CREATE OR REPLACE FUNCTION safe_definer_func()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- function body
END;
$$;
```

Source: https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY

## Fix recipes

### Recipe: Replace trust with scram-sha-256 in pg_hba.conf — addresses CWE-287

**Before (dangerous):**

```
local   all   all   trust
```

**After (safe):**

```
local   all   all   scram-sha-256
```

Source: https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

### Recipe: Require SSL for all connections — addresses CWE-319

**Before (dangerous):**

```
# postgresql.conf
ssl = off
```

**After (safe):**

```
# postgresql.conf
ssl = on
# pg_hba.conf: use hostssl lines only for remote connections
```

Source: https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-SSL

### Recipe: Lock SECURITY DEFINER search_path — addresses CWE-264

**Before (dangerous):**

```sql
CREATE FUNCTION risky() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS
$$ BEGIN PERFORM some_func(); END; $$;
```

**After (safe):**

```sql
CREATE FUNCTION risky() RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS
$$ BEGIN PERFORM some_func(); END; $$;
```

Source: https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY

## Version notes

- PostgreSQL 15+: Public schema no longer grants CREATE to PUBLIC by default; the `REVOKE` step is still recommended for older clusters and for explicit documentation of intent.
- PostgreSQL 14+: `scram-sha-256` is now the default `password_encryption`; clusters created on older versions may still store `md5` hashes — run `SELECT rolname, rolpassword FROM pg_authid WHERE rolpassword LIKE 'md5%'` to audit.
- `md5` auth method in `pg_hba.conf` is deprecated as of PostgreSQL 14 and should be migrated to `scram-sha-256`.

## Common false positives

- `trust` method scoped to `local` socket connections only on a server where OS-level access is already restricted to the postgres service account — lower risk, but still worth noting for defense-in-depth.
- `COPY FROM PROGRAM` in superuser-only migration scripts run by DBAs, never exposed to application roles — risk is lower; verify role grants.
- `ssl = off` in `docker-compose.yml` for a local dev-only database with no external port binding — not a production concern; verify no prod config inherits it.
