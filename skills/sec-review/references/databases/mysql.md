# MySQL / MariaDB

## Source

- https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html
- https://dev.mysql.com/doc/refman/8.0/en/privilege-system.html
- https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- https://cisecurity.org/benchmark/mysql

## Scope

Covers MySQL 5.7, 8.0, and MariaDB 10.x server configuration, user/privilege
management, and connection security. Does not cover application-layer
parameterization (covered in framework references) or MySQL replication
topology security beyond the noted patterns.

## Dangerous patterns (regex/AST hints)

### User granted from wildcard host @'%' — CWE-250

- Why: `CREATE USER 'app'@'%'` allows connections from any network host; combined with a public-facing MySQL port, this dramatically expands the attack surface.
- Grep: `@\s*['"]%['"]|GRANT.*@\s*'%'|CREATE USER.*@\s*'%'`
- File globs: `**/*.sql`, `**/init.sql`, `**/create_user*.sql`
- Source: https://dev.mysql.com/doc/refman/8.0/en/privilege-system.html

### LOCAL INFILE enabled — CWE-200

- Why: `LOAD DATA LOCAL INFILE` lets a malicious server instruct a client to send arbitrary local files; `local_infile=ON` on the server side enables this attack vector.
- Grep: `local_infile\s*=\s*[Oo][Nn]|local-infile\s*=\s*1|LOAD DATA LOCAL INFILE`
- File globs: `**/my.cnf`, `**/my.ini`, `**/*.cnf`, `**/*.sql`
- Source: https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html

### require_secure_transport disabled — CWE-319

- Why: Without `require_secure_transport=ON`, clients can connect and transmit credentials in plaintext even if TLS is configured server-side.
- Grep: `require_secure_transport\s*=\s*OFF|require.secure.transport\s*=\s*0`
- File globs: `**/my.cnf`, `**/my.ini`, `**/*.cnf`
- Source: https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html

### bind-address set to 0.0.0.0 — CWE-668

- Why: Binding MySQL to all interfaces exposes it to the public network; it should bind only to `127.0.0.1` or a private interface unless a firewall enforces access control.
- Grep: `bind.address\s*=\s*0\.0\.0\.0`
- File globs: `**/my.cnf`, `**/my.ini`, `**/mysqld.cnf`
- Source: https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_bind_address

### skip-grant-tables in configuration — CWE-287

- Why: `skip-grant-tables` disables all privilege enforcement; any user can connect and perform any operation without authentication.
- Grep: `skip.grant.tables|skip-grant-tables`
- File globs: `**/my.cnf`, `**/my.ini`, `**/mysqld.cnf`
- Source: https://dev.mysql.com/doc/refman/8.0/en/server-options.html#option_mysqld_skip-grant-tables

## Secure patterns

```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf
[mysqld]
bind-address            = 127.0.0.1
require_secure_transport = ON
local_infile             = OFF
sql_mode                 = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION
# Passwords
default_authentication_plugin = caching_sha2_password
secure_file_priv        = /var/lib/mysql-files
```

Source: https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html

```sql
-- Least-privilege application user on a specific host
CREATE USER 'app'@'10.0.1.5' IDENTIFIED BY 'strong-random-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'app'@'10.0.1.5';
-- Require TLS for this user
ALTER USER 'app'@'10.0.1.5' REQUIRE SSL;
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

## Fix recipes

### Recipe: Restrict user host from % to specific address — addresses CWE-250

**Before (dangerous):**

```sql
CREATE USER 'app'@'%' IDENTIFIED BY 'password';
```

**After (safe):**

```sql
CREATE USER 'app'@'10.0.1.5' IDENTIFIED BY 'password';
-- Or for Docker networks use the subnet CIDR and firewall externally
```

Source: https://dev.mysql.com/doc/refman/8.0/en/privilege-system.html

### Recipe: Disable LOCAL INFILE — addresses CWE-200

**Before (dangerous):**

```ini
[mysqld]
local_infile = ON
```

**After (safe):**

```ini
[mysqld]
local_infile = OFF
```

Source: https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html

### Recipe: Enforce TLS for all connections — addresses CWE-319

**Before (dangerous):**

```ini
[mysqld]
# require_secure_transport not set (defaults to OFF)
```

**After (safe):**

```ini
[mysqld]
require_secure_transport = ON
ssl_ca   = /etc/mysql/ca-cert.pem
ssl_cert = /etc/mysql/server-cert.pem
ssl_key  = /etc/mysql/server-key.pem
```

Source: https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html

## Version notes

- MySQL 8.0+: `caching_sha2_password` is the default authentication plugin, replacing `mysql_native_password`; older clients lacking SHA2 support may require `--authentication-policy=mysql_native_password` as a fallback, which is weaker.
- MySQL 8.0.26+: `mysql_native_password` is deprecated; MySQL 8.4 removed it from the default load. Flag any explicit re-enablement.
- MariaDB 10.4+: `unix_socket` is the default for root on Linux installs; this is safe for OS-restricted accounts but must not be combined with `skip-grant-tables`.
- `sql_mode = ''` (empty) disables strict mode — flag in production as it silently truncates data and suppresses errors.

## Common false positives

- `bind-address = 0.0.0.0` in a `docker-compose.yml` with `ports:` not mapped to the host (internal Docker network only) — lower risk; verify docker-compose `ports:` section.
- `local_infile = ON` on a read-only analytics replica where application clients explicitly set `--local-infile=0` — risk is mitigated by client config; still prefer server-side OFF.
- `@'%'` host in `CREATE USER` when the MySQL port is not exposed externally and access is firewall-restricted to the application server only.
