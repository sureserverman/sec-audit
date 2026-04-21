# Secret Sprawl

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet
- https://www.cisa.gov/sites/default/files/2023-12/fact-sheet-defending-against-software-supply-chain-attacks-508c.pdf — CISA Defending Against Software Supply Chain Attacks
- https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html — OWASP Key Management Cheat Sheet

## Scope

Covers accidental credential exposure across source control history, committed configuration files, CI/CD pipeline logs, Dockerfile layers, and developer environment files (`.env`). Applies to any language or framework whose secrets may be stored as strings. Does not cover runtime secrets management (see `secrets/vault-patterns.md`) or environment-variable leakage via process introspection (see `secrets/env-var-leaks.md`).

## Dangerous patterns (regex/AST hints)

### Committed .env file — CWE-312

- Why: `.env` files often contain database passwords, API keys, and OAuth secrets; once committed they persist in git history even after deletion.
- Grep: `\.env$|\.env\.(local|prod|production|staging|development)`
- File globs: `.env`, `.env.*`, `**/.env`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Hardcoded credential string in source — CWE-798

- Why: API keys, tokens, and passwords embedded in source code are exposed to every developer with repo access and persist in git history indefinitely.
- Grep: `(password|passwd|secret|api_key|apikey|token|auth_token|access_key)\s*=\s*['"][^'"]{8,}['"]`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.rb`, `**/*.php`, `**/*.env`, `**/*.conf`, `**/*.yaml`, `**/*.yml`, `**/*.json`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Secret in Dockerfile ARG or ENV layer — CWE-312

- Why: Docker image build history stores ARG/ENV values in plaintext; anyone who can pull the image can run `docker history --no-trunc` to recover them.
- Grep: `ARG\s+(PASSWORD|SECRET|TOKEN|KEY|PASS|API_KEY|CREDENTIALS)|ENV\s+(PASSWORD|SECRET|TOKEN|KEY|PASS|API_KEY|CREDENTIALS)`
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### No pre-commit hook for secret scanning — CWE-312

- Why: Without automated pre-commit scanning, secrets can be committed undetected until a later audit or breach.
- Grep: (check for absence of `.pre-commit-config.yaml` containing `gitleaks` or `trufflehog` or `detect-secrets`)
- File globs: `.pre-commit-config.yaml`, `.gitleaks.toml`, `.trufflehog.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### High-entropy string that may be a key — CWE-798

- Why: Long random-looking strings in config files or source code may be API keys or private keys committed accidentally.
- Grep: `[A-Za-z0-9+/]{40,}={0,2}` (base64-like) or `[0-9a-f]{32,}` (hex key)
- File globs: `**/*.json`, `**/*.yaml`, `**/*.yml`, `**/*.conf`, `**/*.cfg`, `**/*.ini`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Secret in CI workflow environment block — CWE-312

- Why: Hardcoded secrets in workflow files are committed to the repository; they also appear in CI logs if echoed during debugging.
- Grep: `env:\s*\n\s+\w+:\s*['"][^'"]{8,}['"]`
- File globs: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`
- Source: https://www.cisa.gov/sites/default/files/2023-12/fact-sheet-defending-against-software-supply-chain-attacks-508c.pdf

## Secure patterns

Pre-commit hook configuration using gitleaks:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.2
    hooks:
      - id: gitleaks
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

GitHub Actions using repository secrets (never hardcoded):

```yaml
jobs:
  deploy:
    steps:
      - name: Deploy
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: ./deploy.sh
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

.gitignore entries to prevent accidental commits:

```
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
credentials.json
secrets.yaml
secrets.yml
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Fix recipes

### Recipe: Remove secret from source and rotate — addresses CWE-798

**Before (dangerous):**

```python
DATABASE_URL = "postgresql://admin:S3cr3tP4ss@db.internal:5432/prod"
```

**After (safe):**

```python
import os
DATABASE_URL = os.environ["DATABASE_URL"]  # injected at runtime via secret manager
```

Then: rotate the exposed credential immediately — assume it is compromised from the moment it appeared in git.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Recipe: Replace committed .env with .env.example and gitignore — addresses CWE-312

**Before (dangerous):**

```
# .env (committed to repo)
DB_PASSWORD=hunter2
STRIPE_SECRET_KEY=sk_live_abc123
```

**After (safe):**

```
# .env.example (committed — no real values)
DB_PASSWORD=<set-from-secret-manager>
STRIPE_SECRET_KEY=<set-from-secret-manager>
```

```
# .gitignore (add these lines)
.env
.env.*
!.env.example
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Recipe: Replace Dockerfile ARG secret with BuildKit secret mount — addresses CWE-312

**Before (dangerous):**

```dockerfile
ARG NPM_TOKEN
ENV NPM_TOKEN=${NPM_TOKEN}
RUN npm ci
```

**After (safe):**

```dockerfile
# syntax=docker/dockerfile:1.6
RUN --mount=type=secret,id=npm_token,target=/root/.npmrc \
    npm ci
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Version notes

- gitleaks v8+ supports `.gitleaks.toml` for custom rule tuning and allowlisting; earlier versions used `--config` flags.
- `git filter-repo` (successor to `git filter-branch`) is the recommended tool for removing secrets from git history; after rewriting, all collaborators must re-clone and all previously issued tokens must be rotated.
- GitHub secret scanning (now "push protection") automatically blocks pushes containing known token patterns for GitHub-integrated services; enable it at the organization level.
- CISA guidance (2023) recommends establishing a secret rotation cadence of no more than 90 days for long-lived credentials.

## Common false positives

- High-entropy strings in test fixtures or mock data files — confirm by checking whether the file path includes `test`, `mock`, `fixture`, or `example`.
- `API_KEY=placeholder` or `TOKEN=changeme` in `.env.example` — these are intentional placeholder values, not real secrets; verify no actual token format matches.
- Base64-encoded public certificates in YAML config — PEM-encoded certs are not secret; flag only private keys.
- `password` as a variable name in schema files or ORM model definitions — a field *named* password is not a hardcoded credential; check whether the value is non-empty and non-placeholder.
