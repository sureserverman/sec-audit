# Terraform / Pulumi — Secrets Management and Remote State Hygiene

## Source

- https://developer.hashicorp.com/terraform/language — Terraform language reference
- https://developer.hashicorp.com/terraform/language/state/sensitive-data — Terraform sensitive data in state
- https://developer.hashicorp.com/terraform/language/state/remote — Terraform remote state backends
- https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output — Terraform `sensitive = true` for variables
- https://www.pulumi.com/docs/iac/concepts/ — Pulumi IaC concepts overview
- https://www.pulumi.com/docs/iac/concepts/secrets/ — Pulumi secrets management
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet

## Scope

Covers Terraform (all OSS versions) and Pulumi secrets management within IaC source: hardcoded credentials in `.tf` / `.tfvars` / `Pulumi.*.yaml` files, variable sensitivity markings, local-value leakage, remote-state backend encryption, state file tracking in git, and CI pipeline patterns that expose secret values through environment variables or log output. Out of scope: cloud-resource misconfiguration that does not directly involve secret or state exposure (see `iac-cloud-resources.md`); generic secrets scanning across non-IaC files (see `secrets/` packs); CI runner host security (planned separate lane).

## Dangerous patterns (regex/AST hints)

### Hardcoded AWS access key in `.tf` provider block — CWE-798

- Why: Static credentials embedded in HCL source are committed to version control and shared with every repository clone, giving any reader permanent access to the AWS account until the key is manually revoked.
- Grep: `access_key\s*=\s*"AKIA[0-9A-Z]{16}"|secret_key\s*=\s*"[A-Za-z0-9/+]{40}"`
- File globs: `**/*.tf`, `**/*.tfvars`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Variable missing `sensitive = true` with secret-shaped name — CWE-532

- Why: Without `sensitive = true`, Terraform prints the variable's value in `terraform plan` and `terraform apply` output, leaking the secret to CI logs and terminal history.
- Grep: `variable\s+"\w*(password|secret|token|key)\w*"` — confirm `sensitive\s*=\s*true` is absent from the same block
- File globs: `**/*.tf`
- Source: https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output

### Secret value assigned directly inside `locals` block — CWE-532

- Why: Terraform `locals` values inherit sensitivity only when the expression they reference is already marked sensitive. A literal string assigned in `locals` is never treated as sensitive; it appears in plaintext in state and plan output regardless of the variable name.
- Grep: `locals\s*\{[\s\S]*?(password|secret|api_key|token)\s*=\s*"[^"]+"`
- File globs: `**/*.tf`
- Source: https://developer.hashicorp.com/terraform/language/state/sensitive-data

### S3 backend without `encrypt = true` — CWE-311

- Why: Terraform state contains every resource attribute, including sensitive outputs and provider credentials. An S3 backend without server-side encryption stores this data at rest in plaintext.
- Grep: `backend\s+"s3"\s*\{[^}]*\}` — confirm `encrypt\s*=\s*true` is absent from the matched block
- File globs: `**/*.tf`
- Source: https://developer.hashicorp.com/terraform/language/state/remote

### Terraform state file tracked by git — CWE-312

- Why: `.tfstate` files contain every attribute of every managed resource, including passwords, private keys, and access tokens written as outputs or resource arguments. Any git clone, fork, or history export exposes them permanently.
- Grep: `git ls-files | grep -E '\.tfstate(\.backup)?$'`
- File globs: `**/*.tfstate`, `**/*.tfstate.backup`
- Source: https://developer.hashicorp.com/terraform/language/state/sensitive-data

### `TF_VAR_*` secret echoed or interpolated in CI — CWE-532

- Why: Shell `echo` and inline environment-variable assignments in CI YAML cause the secret value to appear in the runner's log stream, which is often readable by all repository members and retained indefinitely.
- Grep: `echo.*TF_VAR_|env.*TF_VAR_\w+\s*=\s*\$\{\{\s*secrets\.`
- File globs: `**/.github/workflows/*.yml`, `**/.gitlab-ci.yml`, `**/*.sh`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Pulumi `config set` without `--secret` — CWE-312

- Why: `pulumi config set <key> <value>` without the `--secret` flag writes the value in plaintext inside `Pulumi.<stack>.yaml`. If this file is committed, the secret is exposed in version control and to anyone with read access to the stack configuration.
- Grep: `pulumi config set\s+\S+\s+\S+` — confirm `--secret` flag is absent from the matched line
- File globs: `**/Pulumi.yaml`, `**/Pulumi.*.yaml`, `**/*.sh`, `**/.github/workflows/*.yml`
- Source: https://www.pulumi.com/docs/iac/concepts/secrets/

### `terraform apply -auto-approve` in CI without a prior secret-scanning gate — CWE-532

- Why: When an apply fails mid-run, Terraform logs the partial plan including any secret-valued attributes to stdout. Without a preceding scan step (tfsec, Checkov, or Trivy), misconfigured secret handling reaches the runner log before the failure is caught.
- Grep: `terraform apply -auto-approve` — confirm absence of a prior step matching `tfsec|checkov|trivy` in the same job
- File globs: `**/.github/workflows/*.yml`, `**/.gitlab-ci.yml`, `**/*.sh`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Secure patterns

Variable declared with `sensitive = true` so the value is redacted from plan and apply output:

```hcl
variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}
```

Source: https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output

S3 backend with encryption and DynamoDB state locking (no public access):

```hcl
terraform {
  backend "s3" {
    bucket         = "my-org-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
    dynamodb_table = "tfstate-lock"
  }
}
```

Source: https://developer.hashicorp.com/terraform/language/state/remote

Pulumi secret config set and retrieval (value encrypted in stack file, decrypted only at runtime):

```bash
# Store secret — encrypts the value in Pulumi.<stack>.yaml
pulumi config set --secret dbPassword "hunter2"

# Retrieve in program (TypeScript)
const dbPassword = cfg.requireSecret("dbPassword");
```

Source: https://www.pulumi.com/docs/iac/concepts/secrets/

## Fix recipes

### Recipe: Remove hardcoded AWS credentials; use instance/OIDC auth — addresses CWE-798

**Before (dangerous):**

```hcl
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

**After (safe):**

```hcl
provider "aws" {
  region = "us-east-1"
  # Credentials resolved from the environment in priority order:
  # 1. IAM role attached to the EC2/ECS/Lambda execution identity
  # 2. OIDC-federated role via GitHub Actions / GitLab CI
  # 3. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars injected
  #    from CI secret store — never hardcoded here
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Recipe: Add `sensitive = true` to secret-named variables — addresses CWE-532

**Before (dangerous):**

```hcl
variable "api_token" {
  description = "Third-party API token"
  type        = string
}
```

**After (safe):**

```hcl
variable "api_token" {
  description = "Third-party API token"
  type        = string
  sensitive   = true
}
```

Source: https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output

### Recipe: Remove state file from git tracking and add `.gitignore` entry — addresses CWE-312

**Before (dangerous):**

```bash
# File is tracked:
git ls-files terraform.tfstate  # → terraform.tfstate
```

**After (safe):**

```bash
# 1. Remove from index without deleting the local file
git rm --cached terraform.tfstate terraform.tfstate.backup 2>/dev/null || true

# 2. Add to .gitignore
cat >> .gitignore <<'EOF'
*.tfstate
*.tfstate.backup
.terraform/
EOF

# 3. Migrate to a remote backend (S3, GCS, Terraform Cloud)
#    so local state is no longer the source of truth
```

Source: https://developer.hashicorp.com/terraform/language/state/sensitive-data

## Version notes

- `sensitive = true` on `variable` blocks was introduced in Terraform 0.14. For 0.13 and earlier there is no suppression mechanism; upgrade is the only remediation.
- Pulumi stack config encryption uses a per-stack passphrase or a secrets provider (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault) configured at `pulumi stack init` time. The `--secret` flag has no effect if the stack's secrets provider is set to `passphrase` and the passphrase is empty.
- Terraform 1.6+ (HCP Terraform) supports ephemeral values via `ephemeral` resources; these do not persist to state at all and should be preferred over `sensitive` outputs where available.
- The S3 backend `kms_key_id` argument requires Terraform AWS provider ≥ 3.38 to accept KMS multi-region key ARNs (`mrk-` prefix).

## Common false positives

- `access_key = var.aws_access_key` — references a variable rather than a literal; flag only if the variable itself is traced to a hardcoded default.
- `secret_key` appearing inside a `data "aws_secretsmanager_secret_version"` or similar data-source block — this is retrieving a secret, not embedding one; review the destination instead.
- `sensitive = true` absent from a variable named `public_key` or `ssh_public_key` — public keys are not secrets; suppress unless the variable name matches a clearly private-key pattern.
- `TF_VAR_` appearing in a comment or in a `grep -v` exclusion line within a CI script — context indicates it is being explicitly filtered, not leaked.
- `Pulumi.<stack>.yaml` containing `secure:` prefixed values — this is the correct encrypted form; only flag if the value does NOT carry the `secure:` prefix.
