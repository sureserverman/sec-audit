# Vault and Secrets Manager Patterns

## Source

- https://developer.hashicorp.com/vault/docs/concepts/auth — HashiCorp Vault auth methods
- https://developer.hashicorp.com/vault/docs/secrets/databases — Vault dynamic database secrets
- https://developer.hashicorp.com/vault/docs/secrets/transit — Vault transit (encryption-as-a-service)
- https://developer.hashicorp.com/vault/docs/audit — Vault audit devices
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html — AWS Secrets Manager overview
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html — AWS Secrets Manager rotation
- https://getsops.io/docs/ — SOPS documentation
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet

## Scope

Covers secrets retrieval and lifecycle management using HashiCorp Vault (OSS and Enterprise), AWS Secrets Manager, and SOPS/age for file-based secrets encryption. Focuses on authentication patterns, dynamic credentials, audit trails, and rotation. Does not cover static secret storage in plain environment variables (see `secrets/secret-sprawl.md`) or Kubernetes-specific secret exposure (see `containers/kubernetes.md`).

## Dangerous patterns (regex/AST hints)

### Vault root token used in application — CWE-250

- Why: The Vault root token has unrestricted access to all secrets and operations; using it in application code or CI bypasses all policy enforcement.
- Grep: `VAULT_TOKEN\s*=\s*['"]?s\.` (root tokens begin with `s.` in Vault OSS) or `hvs\.` (Vault 1.10+)
- File globs: `**/*.env`, `**/*.yaml`, `**/*.yml`, `**/*.sh`, `.github/workflows/*.yml`
- Source: https://developer.hashicorp.com/vault/docs/concepts/auth

### Long-lived Vault token with no TTL — CWE-613

- Why: Tokens without a TTL or with `period` set to 0 never expire; a stolen token remains valid indefinitely.
- Grep: `"ttl":\s*"0"` or absence of `ttl` in token creation calls
- File globs: `**/*.json`, `**/*.hcl`, `**/*.tf`
- Source: https://developer.hashicorp.com/vault/docs/concepts/auth (Token TTL section)

### AWS Secrets Manager secret without rotation — CWE-613

- Why: Secrets that are never rotated remain valid even after a compromise; rotation limits the window of exposure.
- Grep: `RotationEnabled.*false|rotation_enabled.*false` or absence of `rotation_rules` in Terraform `aws_secretsmanager_secret`
- File globs: `**/*.tf`, `**/*.json`, `**/*.yaml`
- Source: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html

### SOPS file committed without encryption — CWE-312

- Why: A SOPS-managed file that was saved before encryption (plaintext YAML/JSON) exposes secrets in the repository.
- Grep: `sops:` absent from a `.yaml` or `.json` file that should be SOPS-managed, or `ENC\[` absent when SOPS encryption is expected
- File globs: `secrets/**/*.yaml`, `secrets/**/*.json`, `**/*.sops.yaml`
- Source: https://getsops.io/docs/

### Vault AppRole secret-id stored in plaintext — CWE-312

- Why: The AppRole secret-id is the credential used to obtain a Vault token; if stored in plaintext it functions as a long-lived password.
- Grep: `VAULT_SECRET_ID\s*=\s*['"][\w-]{20,}['"]`
- File globs: `**/*.env`, `**/*.sh`, `.github/workflows/*.yml`
- Source: https://developer.hashicorp.com/vault/docs/concepts/auth

## Secure patterns

Vault Kubernetes auth (recommended for workloads running in Kubernetes):

```hcl
# Vault policy — least privilege
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

# Kubernetes auth role binding
vault write auth/kubernetes/role/myapp \
    bound_service_account_names=myapp \
    bound_service_account_namespaces=production \
    policies=myapp-policy \
    ttl=1h
```

Source: https://developer.hashicorp.com/vault/docs/concepts/auth

Dynamic database credentials via Vault (short-lived, per-request):

```hcl
vault secrets enable database

vault write database/config/mydb \
    plugin_name=postgresql-database-plugin \
    allowed_roles="myapp-role" \
    connection_url="postgresql://{{username}}:{{password}}@db.internal:5432/prod" \
    username="vault-admin" \
    password="<vault-admin-password>"

vault write database/roles/myapp-role \
    db_name=mydb \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

Source: https://developer.hashicorp.com/vault/docs/secrets/databases

SOPS-encrypted secrets file (age key):

```bash
# Encrypt
sops --encrypt --age age1<recipient-pubkey> secrets.yaml > secrets.enc.yaml

# Decrypt at runtime (key from environment or key file)
SOPS_AGE_KEY_FILE=/run/secrets/age.key sops --decrypt secrets.enc.yaml
```

Source: https://getsops.io/docs/

AWS Secrets Manager with automatic rotation (Terraform):

```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "prod/myapp/db_password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

Source: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html

## Fix recipes

### Recipe: Replace Vault root token with AppRole + short TTL — addresses CWE-250, CWE-613

**Before (dangerous):**

```bash
export VAULT_TOKEN="hvs.ROOTTOKEN..."
vault kv get secret/myapp/config
```

**After (safe):**

```bash
# CI: exchange a wrapped secret-id for a short-lived token
VAULT_TOKEN=$(vault write -field=token auth/approle/login \
    role_id="${VAULT_ROLE_ID}" \
    secret_id="${VAULT_SECRET_ID}")   # secret-id injected via CI secret store
export VAULT_TOKEN
# Token TTL: 15m, renewable up to 1h
```

Source: https://developer.hashicorp.com/vault/docs/concepts/auth

### Recipe: Enable Vault audit logging — addresses CWE-778

**Before (dangerous):**

```bash
# No audit device configured
vault audit list  # returns empty
```

**After (safe):**

```bash
vault audit enable file file_path=/var/log/vault/audit.log \
    log_raw=false       # never log raw secret values
vault audit enable syslog tag="vault" facility="AUTH"
```

Source: https://developer.hashicorp.com/vault/docs/audit

### Recipe: Enable AWS Secrets Manager rotation — addresses CWE-613

**Before (dangerous):**

```hcl
resource "aws_secretsmanager_secret" "api_key" {
  name = "prod/myapp/api_key"
  # no rotation configuration
}
```

**After (safe):**

```hcl
resource "aws_secretsmanager_secret" "api_key" {
  name                    = "prod/myapp/api_key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_rotation" "api_key" {
  secret_id           = aws_secretsmanager_secret.api_key.id
  rotation_lambda_arn = aws_lambda_function.api_key_rotation.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

Source: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html

## Version notes

- Vault 1.10+ uses `hvs.` token prefix (Vault-Signed); older versions use `s.`. Update grep patterns accordingly.
- Vault 1.13+ supports PKCE and OIDC STS for cloud auth; prefer these over AppRole for cloud workloads where supported.
- SOPS 3.8+ supports `age` natively without a plugin; earlier versions required `age` as an external binary and `--encryption-method=age` flag.
- AWS Secrets Manager cross-account access requires resource-based policies in addition to IAM; ensure the rotation Lambda also has cross-account permissions if relevant.

## Common false positives

- `VAULT_TOKEN` set to `root` in local Docker Compose dev environments (`docker-compose.dev.yml`) — acceptable for local development only; flag if found in production configs.
- SOPS `.sops.yaml` configuration file listing recipient public keys — this file is intentionally committed and contains only public keys, not secrets.
- Vault HCL policy files with `capabilities = ["read", "list"]` on broad paths — review the path; `secret/data/` with a wildcard is still a concern, but the capability list itself is not the risk.
- `rotation_enabled: false` on a Secrets Manager secret that stores a certificate/public key — public material does not require rotation on the same cadence as passwords or API keys.
