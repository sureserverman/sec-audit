# Environment Variable Leakage

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet
- https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables — Kubernetes envFrom pitfalls
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html — OWASP Error Handling Cheat Sheet
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 Application Container Security Guide

## Scope

Covers runtime exposure of secret values stored in environment variables: `/proc/<pid>/environ` on Linux, `docker inspect` output, debug log statements that echo env, crash dumps, error pages that render environment context, and child-process inheritance. Applies to any language running on Linux or inside containers. Does not cover secrets committed to source control (see `secrets/secret-sprawl.md`) or secrets stored in a vault (see `secrets/vault-patterns.md`).

## Dangerous patterns (regex/AST hints)

### Logging or printing environment variables — CWE-532

- Why: Log lines containing `os.environ`, `process.env`, `System.getenv()`, or equivalent dump secret values into log aggregators accessible to many people.
- Grep: `print.*os\.environ|log.*os\.environ|logger.*getenv|console\.log.*process\.env|System\.out.*getenv|fmt\.Print.*os\.Getenv`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Error page or debug endpoint rendering env — CWE-209

- Why: Web framework debug modes (Django `DEBUG=True`, Flask debug, Spring Boot `/actuator/env`) expose all environment variables in error responses or API responses accessible to clients.
- Grep: `DEBUG\s*=\s*True|DEBUG\s*=\s*true|debug:\s*true`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.yaml`, `**/*.yml`, `**/*.conf`, `**/*.properties`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

### Secrets passed to subprocess via env inheritance — CWE-214

- Why: Child processes inherit the parent's environment by default; if a subprocess is attacker-influenced (e.g. shell injection), the inherited secrets are exposed.
- Grep: `subprocess\.Popen|subprocess\.run|exec\.Command|Runtime\.exec|child_process\.exec`
- File globs: `**/*.py`, `**/*.go`, `**/*.js`, `**/*.java`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Docker inspect leaking env — CWE-214

- Why: `docker inspect <container>` outputs all `--env` values in plaintext; any user with Docker socket access can read them.
- Grep: `docker inspect|docker run.*-e\s+(PASSWORD|SECRET|TOKEN|KEY)=`
- File globs: `**/*.sh`, `Makefile`, `docker-compose*.yml`
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.1.3)

### Spring Boot actuator `/env` endpoint exposed — CWE-200

- Why: The `/actuator/env` endpoint lists all environment variables and configuration properties; even with partial masking, variable names reveal what secrets exist and values may be unmasked on older versions.
- Grep: `management\.endpoints\.web\.exposure\.include.*env|endpoints\.env\.sensitive.*false`
- File globs: `**/application.properties`, `**/application.yml`, `**/application.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

## Secure patterns

Pass only required env vars to subprocesses (Python):

```python
import os
import subprocess

# Build a minimal environment — do not inherit parent env wholesale
safe_env = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
}
subprocess.run(["external-tool", "--flag"], env=safe_env, check=True)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

Mount Kubernetes secret as file instead of envFrom:

```yaml
volumes:
  - name: api-key
    secret:
      secretName: myapp-api-key
      defaultMode: 0400
containers:
  - name: app
    volumeMounts:
      - name: api-key
        mountPath: /run/secrets/api-key
        readOnly: true
    # Do NOT use:
    # envFrom:
    #   - secretRef:
    #       name: myapp-api-key
```

Source: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables

Disable Django debug and configure proper error handling:

```python
# settings/production.py
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]

# Use a structured logger — never log request.META wholesale
import logging
logger = logging.getLogger(__name__)
# ✓ logger.info("request from %s", request.user)
# ✗ logger.debug("env: %s", dict(os.environ))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

Spring Boot actuator — restrict env endpoint:

```yaml
# application.yml (production)
management:
  endpoints:
    web:
      exposure:
        include: health,info   # never include "env" in production
  endpoint:
    health:
      show-details: never
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

## Fix recipes

### Recipe: Remove env var logging — addresses CWE-532

**Before (dangerous):**

```python
import os
import logging

logging.basicConfig(level=logging.DEBUG)
logging.debug("Starting with env: %s", dict(os.environ))
```

**After (safe):**

```python
import logging

logging.basicConfig(level=logging.INFO)
logging.info("Application starting (use structured config logging for non-secret settings)")
# Log only specific, non-secret config values by name if needed
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Recipe: Pass minimal env to subprocess — addresses CWE-214

**Before (dangerous):**

```go
cmd := exec.Command("converter", inputFile)
// inherits all os.Environ() including DB_PASSWORD, API_TOKEN, etc.
cmd.Run()
```

**After (safe):**

```go
cmd := exec.Command("converter", inputFile)
cmd.Env = []string{
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "HOME=/tmp",
}
cmd.Run()
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Recipe: Use secret file mount instead of env var in Kubernetes — addresses CWE-214

**Before (dangerous):**

```yaml
containers:
  - name: app
    env:
      - name: DB_PASSWORD
        valueFrom:
          secretKeyRef:
            name: db-secret
            key: password
```

**After (safe):**

```yaml
volumes:
  - name: db-secret
    secret:
      secretName: db-secret
      defaultMode: 0400
containers:
  - name: app
    volumeMounts:
      - name: db-secret
        mountPath: /run/secrets/db
        readOnly: true
    # Application reads: os.ReadFile("/run/secrets/db/password")
```

Source: https://kubernetes.io/docs/concepts/configuration/secret/

## Version notes

- `/proc/<pid>/environ` is readable by the process owner and by root. In containers without user namespace remapping, container root = host root, so any process in the container can read another container's environ if they share the PID namespace.
- Linux kernel 5.6+ limits `/proc/<pid>/environ` access via `ptrace_may_access`; older kernels are more permissive within the same UID.
- Spring Boot Actuator 2.x masks common sensitive property keys in `/actuator/env` responses (keys containing `password`, `secret`, `key`, `token`, `credentials`, `vcap_services`), but this list is not exhaustive and earlier 1.x versions had no masking.
- Docker 20.10+ does not log `--env` values in the daemon log, but `docker inspect` still outputs them in plaintext.

## Common false positives

- `os.environ.get("PORT", "8080")` — reading non-secret operational config (port, log level) from env is fine; flag only reads of variables with names matching credential patterns.
- `process.env.NODE_ENV` in JavaScript — `NODE_ENV` is a non-secret runtime mode indicator; its value in logs is not a security issue.
- `DEBUG=True` in `.env.example` or `docker-compose.dev.yml` — acceptable for local development; flag only when found in production configuration files or environment definitions.
- `management.endpoints.web.exposure.include=health` — exposing only the `health` endpoint is low risk; flag only when `env`, `configprops`, or `*` is included.
