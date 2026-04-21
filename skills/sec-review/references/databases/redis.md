# Redis

## Source

- https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/
- https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Redis 6.x and 7.x standalone and Sentinel deployments, including ACL
system, TLS, and the Lua scripting engine. Does not cover Redis Cluster
topology security or Redis Enterprise managed-service specifics.

## Dangerous patterns (regex/AST hints)

### No authentication configured — CWE-306

- Why: Redis without `requirepass` (< 6.x) or without ACL users (6.x+) allows any client with network access to read, write, or delete all data and execute CONFIG commands.
- Grep: `requirepass\s*$|# requirepass|requirepass\s*""`
- File globs: `**/redis.conf`, `**/*.conf`
- Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### Bind to 0.0.0.0 without protected-mode — CWE-668

- Why: `bind 0.0.0.0` without `protected-mode yes` exposes Redis to all network interfaces; an unauthenticated Redis reachable from the internet is trivially exploitable.
- Grep: `bind\s+0\.0\.0\.0|bind\s+\*`
- File globs: `**/redis.conf`, `**/*.conf`
- Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### EVAL with user-controlled Lua scripts — CWE-94

- Why: Passing user-controlled strings to `EVAL` allows execution of arbitrary Lua code in the Redis server context; while sandboxed, historical Lua sandbox escapes (Debian/Ubuntu CVE-2022-0543) have achieved RCE.
- Grep: `EVAL\s+.*req\.|\.eval\s*\(.*req\.|client\.eval\s*\(.*user`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`
- Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### CONFIG SET used to enable RCE via replication — CWE-78

- Why: An authenticated (or unauthenticated) client can use `CONFIG SET dir` and `CONFIG SET dbfilename` to write files to arbitrary paths, enabling cron-based or SSH key RCE.
- Grep: `CONFIG\s+SET\s+dir|CONFIG\s+SET\s+dbfilename|config\.set\s*\(['"]dir|config\.set\s*\(['"]dbfilename`
- File globs: `**/*.sh`, `**/*.py`, `**/*.js`
- Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

## Secure patterns

```conf
# redis.conf — production hardening
bind 127.0.0.1 -::1
protected-mode yes
requirepass "long-random-password-from-secrets-manager"

# Rename or disable dangerous commands
rename-command CONFIG  ""
rename-command FLUSHALL ""
rename-command DEBUG   ""

# TLS (Redis 6+)
tls-port 6380
port 0
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file  /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-auth-clients yes
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

```conf
# ACL-based access control (Redis 6+)
# /etc/redis/users.acl
user default off nopass nocommands nokeys
user appuser on >app-strong-password ~app:* +@read +@write +@string -@dangerous
user readonlyuser on >ro-password ~* +@read
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/

## Fix recipes

### Recipe: Enable requirepass / ACL authentication — addresses CWE-306

**Before (dangerous):**

```conf
# redis.conf
# requirepass not set
protected-mode no
```

**After (safe):**

```conf
requirepass "$(openssl rand -base64 32)"
protected-mode yes
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### Recipe: Restrict bind interface — addresses CWE-668

**Before (dangerous):**

```conf
bind 0.0.0.0
```

**After (safe):**

```conf
bind 127.0.0.1 10.0.1.5   # loopback + specific private interface
protected-mode yes
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### Recipe: Disable CONFIG and FLUSHALL via rename-command — addresses CWE-78

**Before (dangerous):**

```conf
# No command restrictions
```

**After (safe):**

```conf
rename-command CONFIG   ""
rename-command FLUSHALL ""
rename-command FLUSHDB  ""
rename-command DEBUG    ""
rename-command SLAVEOF  ""
rename-command REPLICAOF ""
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### Recipe: Avoid EVAL with user input — addresses CWE-94

**Before (dangerous):**

```python
r.eval(user_script, 0)
```

**After (safe):**

```python
# Use pre-loaded scripts with EVALSHA from developer-owned scripts only
sha = r.script_load(DEVELOPER_OWNED_LUA_SCRIPT)
r.evalsha(sha, 0)
# Never pass user-controlled strings as the script argument
```

Source: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

## Version notes

- Redis 6.0+: ACL system replaces single `requirepass`; new deployments should use ACLs for per-user privilege separation. `requirepass` still works and sets the `default` user password.
- Redis 7.0+: `loglevel` and `ACL LOG` are available for auditing; enable for production.
- CVE-2022-0543 (Debian/Ubuntu packages only): Lua sandbox escape was possible due to the `package` global being exposed; patched in redis 6.0.16 / 6.2.6 / 7.0.0. Check distribution package version.
- `rename-command` is incompatible with Redis Sentinel and Cluster for certain commands (e.g., `CONFIG`); use ACL `nocommands` / `-@dangerous` instead in clustered setups.

## Common false positives

- `bind 0.0.0.0` in a `docker-compose.yml` without a `ports:` mapping to the host — container is isolated in a Docker bridge network; still prefer explicit binding.
- `requirepass` appearing commented out in an example or template config file — verify whether the deployed config inherits or overrides it.
- `CONFIG SET` in admin/ops scripts that run only with DBA credentials, not reachable by application code.
