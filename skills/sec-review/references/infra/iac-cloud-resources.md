# Terraform / Pulumi IaC Cloud-Resource Security

## Source

- https://developer.hashicorp.com/terraform/language — Terraform language reference: resource blocks, expression syntax, meta-arguments, and provider schema
- https://developer.hashicorp.com/terraform/language/state/sensitive-data — Terraform state and sensitive data: what ends up in state files and how to limit exposure
- https://www.pulumi.com/docs/iac/concepts/ — Pulumi IaC concepts: stacks, resources, outputs, secrets, and provider configuration
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html — AWS S3 Security Best Practices: ACL removal, public-access block, encryption, versioning, and logging guidance
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html — AWS IAM Best Practices: least-privilege policies, condition keys, policy boundaries, and wildcard restrictions
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security Cheat Sheet: provider pinning, module integrity, and dependency management

## Scope

In-scope: static analysis of Terraform HCL (`.tf`, `.tfvars`, `.hcl`) and Pulumi programs (`Pulumi.yaml`, Python `__main__.py`, TypeScript `index.ts`) that declare AWS, GCP, or Azure cloud resources — specifically S3 buckets, IAM policies, RDS instances, EC2 security groups, GCP IAM bindings, Azure storage accounts, and CloudFront distributions. Out of scope: provider-block credential hygiene and remote-state backend encryption (covered by `iac-secrets-state.md`); container-image content and base-image vulnerabilities (covered by the containers reference pack); live-cloud API audits that require runtime access; networking-layer controls below the IaC abstraction (VPC flow logs, CloudTrail configuration).

## Dangerous patterns (regex/AST hints)

### S3 bucket with `acl = "public-read"` or `"public-read-write"` — CWE-732

- Why: Setting the S3 canned ACL to `public-read` or `public-read-write` grants anonymous Internet principals read (or read/write) access to every object in the bucket. AWS deprecated canned ACLs in favour of the S3 Block Public Access setting and bucket policies; enabling a public ACL on a bucket that also has Block Public Access disabled results in world-readable or world-writable object storage. Any object placed in such a bucket — including application configs, backups, or user-uploaded files — becomes instantly accessible without authentication.
- Grep: `resource\s+"aws_s3_bucket(_acl)?"\b.*acl\s*=\s*"(public-read|public-read-write)"` (also scan `aws_s3_bucket_acl` resources with `acl = "public-read"` or `acl = "public-read-write"`)
- File globs: `**/*.tf`, `**/*.tfvars`, `**/*.hcl`, `**/Pulumi.yaml`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### S3 bucket without `server_side_encryption_configuration` — CWE-311

- Why: An S3 bucket that lacks a `server_side_encryption_configuration` block (Terraform) or equivalent SSE setting stores objects in plaintext unless the uploader specifies per-object encryption headers. AWS did enable default SSE-S3 encryption for new buckets in January 2023, but older buckets and buckets managed by Terraform without an explicit `server_side_encryption_configuration` block may pre-date that change or may have the default overridden by apply-time destructive operations. Explicit IaC declaration ensures the encryption rule survives re-creation of the bucket resource.
- Grep: `resource\s+"aws_s3_bucket"\s+"\w+"` block that does not contain `server_side_encryption_configuration` — requires a block-level scan (grep for `aws_s3_bucket` resources, then check whether `server_side_encryption_configuration` appears within the same resource block or in an associated `aws_s3_bucket_server_side_encryption_configuration` resource referencing the same bucket)
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### IAM policy document with `Action = "*"` and `Resource = "*"` — CWE-732

- Why: A policy statement that combines `Action = "*"` (all API actions across all AWS services) with `Resource = "*"` (all resources in the account) grants unrestricted administrator-equivalent access. Any principal (IAM user, role, service) that carries this policy can exfiltrate data, delete resources, create credentials, or escalate their own privileges. Even when the `Effect` is `Allow` for a narrow use-case, the wildcard combination violates the principle of least privilege and is explicitly prohibited by AWS IAM Best Practices. Pulumi `aws.iam.PolicyDocument` inline objects are equally affected.
- Grep: `Action\s*=\s*"\*"` paired with `Resource\s*=\s*"\*"` within the same policy `statement` block; also catches HCL heredoc `jsonencode` blocks with `"Action": "*"` and `"Resource": "*"`
- File globs: `**/*.tf`, `**/*.tfvars`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### RDS instance without `storage_encrypted = true` — CWE-311

- Why: An `aws_db_instance` or `aws_db_cluster` resource that omits `storage_encrypted` (which defaults to `false`) stores the database volume, automated backups, read replicas, and snapshots in plaintext EBS storage. If an attacker gains access to the underlying EBS snapshot — via misconfigured snapshot sharing, an AWS account compromise, or a cloud provider incident — they can attach and read the volume without a decryption key. Encryption must be enabled at creation time; it cannot be applied to an existing unencrypted instance without a snapshot-restore cycle.
- Grep: `resource\s+"aws_db_instance"\b` or `resource\s+"aws_db_cluster"\b` blocks missing `storage_encrypted\s*=\s*true`; also match `storage_encrypted\s*=\s*false` explicitly
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### Security group ingress with `cidr_blocks = ["0.0.0.0/0"]` on sensitive ports — CWE-284

- Why: An EC2 security group ingress rule that opens a sensitive administrative or database port to `0.0.0.0/0` (all IPv4 addresses) exposes that service to the entire Internet. Ports 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), and 6379 (Redis) are continuously probed by automated scanners; any service on these ports must be restricted to known CIDR ranges (bastion IPs, VPN egress blocks, or peered VPC CIDR) rather than the open Internet. The same logic applies to `::/0` (all IPv6).
- Grep: `cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]` within an `ingress` block that also contains `from_port\s*=\s*(22|3389|3306|5432|6379)`; also flag `ipv6_cidr_blocks\s*=\s*\["::/0"\]` on the same ports
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### GCP IAM binding to `allUsers` or `allAuthenticatedUsers` — CWE-732

- Why: In GCP IAM, `allUsers` represents every person on the Internet (including unauthenticated principals) and `allAuthenticatedUsers` represents any Google-authenticated account in the world — not just accounts within the organisation. Binding either of these well-known members to any IAM role on a Cloud Storage bucket, Cloud Run service, Pub/Sub topic, or project-level policy makes that resource publicly accessible. This is a frequent cause of GCS data exposure incidents. Pulumi `gcp.storage.BucketIAMBinding` and Terraform `google_storage_bucket_iam_binding` resources are both affected.
- Grep: `members\s*=\s*\[.*"allUsers"` or `members\s*=\s*\[.*"allAuthenticatedUsers"`; also scan `member\s*=\s*"allUsers"` (singular form in `*_iam_member` resources)
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### Azure Storage Account with `allow_blob_public_access = true` — CWE-732

- Why: Setting `allow_blob_public_access = true` on an `azurerm_storage_account` resource allows individual blob containers within that account to be set to `blob` or `container` public access level, making their contents world-readable without an access key or Azure AD credential. Even if no container is currently set to public, the account-level flag acts as a standing permission that can be enabled at any time — including by misconfiguration of a downstream `azurerm_storage_container` resource. Microsoft recommends disabling this flag at the account level and enforcing it via Azure Policy.
- Grep: `resource\s+"azurerm_storage_account"\b` blocks containing `allow_blob_public_access\s*=\s*true`; also flag absence of `allow_blob_public_access = false` (the attribute defaults to `false` in newer provider versions but was `true` in older ones — confirm provider version)
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### CloudFront distribution with `viewer_protocol_policy = "allow-all"` — CWE-319

- Why: A CloudFront cache behaviour with `viewer_protocol_policy = "allow-all"` serves content over plain HTTP to any client that requests it, transmitting responses — including cookies, session tokens, and sensitive API payloads — in cleartext. An on-path attacker (coffee-shop network, compromised ISP router) can intercept or modify this traffic. Setting the policy to `redirect-to-https` forces HTTP clients to the HTTPS endpoint transparently; `https-only` is stronger but breaks clients that cannot upgrade. Both are preferable to `allow-all`.
- Grep: `viewer_protocol_policy\s*=\s*"allow-all"`
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### S3 bucket versioning absent or disabled — CWE-404

- Why: An S3 bucket without versioning enabled cannot recover objects deleted or overwritten by a ransomware attack, insider threat, or accidental Terraform `destroy`. When an object is deleted from an unversioned bucket, it is immediately and irrecoverably gone. Versioning preserves all versions of every object, allowing point-in-time recovery. For buckets containing application state, database exports, audit logs, or IaC state files, the absence of versioning is a data-integrity risk. Bucket versioning must be enabled via a separate `aws_s3_bucket_versioning` resource in current AWS provider versions (≥ 4.x).
- Grep: absence of `resource\s+"aws_s3_bucket_versioning"` referencing the target bucket, or `status\s*=\s*"Disabled"` within a versioning configuration block; also `versioning\s*\{[^}]*enabled\s*=\s*false` in legacy inline versioning blocks (provider < 4.x)
- File globs: `**/*.tf`, `**/*.hcl`, `**/__main__.py`, `**/index.ts`
- Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

## Secure patterns

### (a) Hardened S3 bucket — encryption, versioning, public-access block, and ACL disabled

A Terraform configuration that applies all AWS-recommended S3 hardening controls as separate, composable resources using the current AWS provider (≥ 4.x) pattern:

```hcl
resource "aws_s3_bucket" "secure_store" {
  bucket = "example-secure-store-${data.aws_caller_identity.current.account_id}"
  # Do NOT set `acl` here — ACLs are disabled at the account level below.
}

# Block all public access at the bucket level.
resource "aws_s3_bucket_public_access_block" "secure_store" {
  bucket = aws_s3_bucket.secure_store.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable AES-256 server-side encryption with a customer-managed KMS key.
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_store" {
  bucket = aws_s3_bucket.secure_store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true   # reduces KMS request costs
  }
}

# Enable versioning so every object version is recoverable.
resource "aws_s3_bucket_versioning" "secure_store" {
  bucket = aws_s3_bucket.secure_store.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Disable ACLs — enforce access via bucket policies only.
resource "aws_s3_bucket_ownership_controls" "secure_store" {
  bucket = aws_s3_bucket.secure_store.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
```

Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### (b) Least-privilege IAM policy — scoped actions and resource ARN, no wildcards

An IAM policy document that grants only the minimum actions required for a Lambda function to read from one specific S3 prefix, with no wildcard actions or wildcard resources:

```hcl
data "aws_iam_policy_document" "lambda_s3_read" {
  statement {
    sid    = "AllowPrefixRead"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]

    # Scope to a specific prefix, not the entire bucket or "*".
    resources = [
      "${aws_s3_bucket.secure_store.arn}/data/input/*",
    ]
  }

  statement {
    sid    = "AllowBucketList"
    effect = "Allow"

    actions = [
      "s3:ListBucket",
    ]

    resources = [aws_s3_bucket.secure_store.arn]

    # Restrict ListBucket to the relevant prefix via a condition.
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["data/input/*"]
    }
  }
}

resource "aws_iam_policy" "lambda_s3_read" {
  name   = "lambda-s3-read-data-input"
  policy = data.aws_iam_policy_document.lambda_s3_read.json
}
```

Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

## Fix recipes

### Recipe: Replace public ACL with S3 Block Public Access — addresses CWE-732

**Before (dangerous):**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "example-uploads"
  acl    = "public-read"   # world-readable; any object is accessible anonymously
}
```

**After (safe):**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "example-uploads"
  # Remove the `acl` argument entirely.
}

resource "aws_s3_bucket_ownership_controls" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    object_ownership = "BucketOwnerEnforced"   # disables ACLs account-wide for this bucket
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

If the bucket genuinely needs to serve public content (e.g. a static website), serve it via a CloudFront distribution with an Origin Access Control (OAC) policy instead of a public bucket ACL. The bucket remains private; CloudFront holds the only read permission via a bucket policy scoped to the OAC principal. This eliminates direct public access while preserving content delivery.

Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

### Recipe: Restrict IAM wildcard policy to least-privilege actions — addresses CWE-732

**Before (dangerous):**

```hcl
data "aws_iam_policy_document" "bad" {
  statement {
    effect    = "Allow"
    actions   = ["*"]       # all API actions across every AWS service
    resources = ["*"]       # all resources in the account
  }
}
```

**After (safe):**

```hcl
data "aws_iam_policy_document" "good" {
  statement {
    sid    = "AllowOnlyRequiredActions"
    effect = "Allow"

    # Enumerate only the specific API actions the principal legitimately calls.
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
    ]

    # Scope to specific resource ARNs, not "*".
    resources = [
      aws_s3_bucket.app_data.arn,
      "${aws_s3_bucket.app_data.arn}/*",
      aws_sqs_queue.app_queue.arn,
    ]
  }
}
```

Use AWS IAM Access Analyzer policy generation to bootstrap the allow-list: run it against CloudTrail logs for the principal in question over a representative time window, then prune any actions that are not observed in production. Add a `Condition` block with `aws:SourceAccount` or `aws:SourceArn` where the principal is an AWS service (Lambda, ECS task role) to prevent confused-deputy attacks.

Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### Recipe: Enable RDS storage encryption at resource declaration — addresses CWE-311

**Before (dangerous):**

```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-db-prod"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  username          = var.db_username
  password          = var.db_password
  # storage_encrypted is absent — defaults to false
}
```

**After (safe):**

```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-db-prod"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  username          = var.db_username
  password          = var.db_password

  storage_encrypted = true               # encrypt the EBS volume at rest
  kms_key_id        = aws_kms_key.rds.arn  # use a CMK for key rotation control

  # Encrypting an existing unencrypted instance requires:
  #   1. Take a snapshot of the existing instance.
  #   2. Copy the snapshot with encryption enabled.
  #   3. Restore a new instance from the encrypted snapshot.
  #   4. Promote the restored instance and update connection strings.
  # Plan a maintenance window; this cannot be done in-place.
}
```

Note: `storage_encrypted` must be set at instance creation. Changing it on an existing Terraform-managed resource forces a replacement (`# forces replacement` in `terraform plan` output), which destroys and recreates the instance — equivalent to the snapshot-restore procedure. Schedule this change during a planned maintenance window and verify backups before applying.

Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

## Version notes

- **AWS Provider ACL deprecation (≥ 4.0):** The inline `acl` argument on `aws_s3_bucket` was deprecated in AWS provider 4.x and moved to the standalone `aws_s3_bucket_acl` resource. In provider ≥ 5.0, setting `acl` on `aws_s3_bucket` produces a plan error. Audits should check both the legacy inline form and the standalone resource.
- **AWS Provider SSE split (≥ 4.0):** `server_side_encryption_configuration` was extracted from `aws_s3_bucket` into `aws_s3_bucket_server_side_encryption_configuration`. Codebases on provider < 4.x use the inline block; provider ≥ 4.x codebases that still use the inline block will emit deprecation warnings and may fail `terraform validate` on newer providers.
- **AWS default S3 encryption (January 2023):** AWS began applying SSE-S3 as the default for new buckets in January 2023. Buckets created before this date, or re-created by a `terraform destroy`/`terraform apply` cycle without an explicit encryption resource, may not carry the default. Explicit IaC declaration remains the only reliable posture.
- **Terraform `aws_s3_bucket_versioning` vs. inline versioning:** Provider < 4.x used a `versioning { enabled = true }` inline block. Provider ≥ 4.x uses the standalone `aws_s3_bucket_versioning` resource with `status = "Enabled"`. Grep patterns must cover both forms.
- **Pulumi AWS Classic vs. AWS Native:** Pulumi AWS Classic (`pulumi-aws`) wraps the Terraform AWS provider and exposes the same resource model and the same deprecated vs. current split. Pulumi AWS Native (`pulumi-aws-native`) uses the CloudFormation resource model and has different property names (e.g. `versioningConfiguration` instead of `versioning_configuration`). Flag the provider package version when raising findings.
- **Azure `allow_blob_public_access` default change:** The `azurerm` provider set `allow_blob_public_access` to `true` by default in versions prior to 3.0. From provider 3.0 onwards the default is `false`. Codebases pinned to `azurerm` < 3.0 are at higher risk; check the `required_providers` block for the version constraint.

## Common false positives

- `cidr_blocks = ["0.0.0.0/0"]` on port 80 or 443 in a security group — public HTTP/HTTPS ingress is expected for Internet-facing load balancers; flag only if paired with the sensitive administrative/database ports listed above.
- `acl = "public-read"` on an `aws_s3_bucket` that also has a `website` block and is explicitly serving a static website — evaluate whether a CloudFront + OAC pattern is feasible before escalating; some legacy deployments have a valid use-case for public-read buckets. Downgrade to informational if the bucket has `block_public_acls = false` intentionally documented.
- `members = ["allAuthenticatedUsers"]` in a GCP IAM binding on a resource tagged as a public data portal or open-data registry — confirm organisational policy and data classification before flagging; some government and research datasets are intentionally world-readable.
- `viewer_protocol_policy = "allow-all"` on a CloudFront behaviour that serves only public, non-sensitive static assets with no cookies or authentication — still raise as informational (no downside to `redirect-to-https`) but downgrade severity if the behaviour is for a purely public CDN origin with no session state.
- `storage_encrypted` absent on an `aws_db_instance` that uses a `db_subnet_group` fully inside a private VPC with no public accessibility (`publicly_accessible = false`) — encryption at rest is still recommended and required by many compliance frameworks (PCI-DSS, HIPAA); do not suppress the finding, but note the reduced exposure in the finding rationale.
- `aws_s3_bucket_versioning` absent on a bucket that is used exclusively as a Terraform remote-state backend — state-level versioning is covered by the `iac-secrets-state.md` pack; avoid double-counting, but still verify that the backend configuration enables versioning independently.
