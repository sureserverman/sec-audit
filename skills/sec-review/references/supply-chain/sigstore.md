# Sigstore (cosign, Rekor, Fulcio)

## Source

- https://docs.sigstore.dev/signing/overview/ — Sigstore signing overview
- https://docs.sigstore.dev/verifying/verify/ — Sigstore verification
- https://docs.sigstore.dev/logging/overview/ — Rekor transparency log
- https://docs.sigstore.dev/certificate_authority/overview/ — Fulcio certificate authority
- https://github.com/sigstore/cosign/blob/main/doc/cosign_sign.md — cosign sign reference
- https://github.com/sigstore/policy-controller — Sigstore policy-controller for Kubernetes
- https://slsa.dev/blog/2022/06/slsa-cosign-keyless — SLSA + cosign keyless signing

## Scope

Covers container image and artifact signing using cosign (keyless via OIDC and key-based), Rekor transparency log entries, Fulcio short-lived certificate issuance, and enforcement via policy-controller in Kubernetes. Applies to any OCI-compliant registry. Does not cover SLSA provenance generation (see `supply-chain/slsa.md`) or SBOM formats (see `supply-chain/sbom.md`).

## Dangerous patterns (regex/AST hints)

### Image deployed without signature verification — CWE-494

- Why: Pulling and running an image without verifying its cosign signature allows a compromised registry or man-in-the-middle to serve a malicious image.
- Grep: `docker pull|kubectl set image|helm upgrade` (check for absence of preceding `cosign verify`)
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `Makefile`, `**/*.sh`
- Source: https://docs.sigstore.dev/verifying/verify/

### cosign sign with a key stored in plaintext — CWE-312

- Why: A signing key stored as a plaintext file in the repository or as a CI secret without additional wrapping (KMS) can be exfiltrated and used to sign malicious artifacts.
- Grep: `cosign sign --key cosign\.key|cosign sign --key\s+\./`
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `Makefile`, `**/*.sh`
- Source: https://docs.sigstore.dev/signing/overview/

### Rekor transparency log entry not verified — CWE-345

- Why: An offline or pre-computed signature does not prove the signing event was recorded in the append-only Rekor log; verification must check the log entry (tlog-verify).
- Grep: `cosign verify(?!.*--insecure-ignore-tlog)` (absence of `--rekor-url` or reliance on default without checking tlog)
- File globs: `.github/workflows/*.yml`, `**/*.sh`, `Makefile`
- Source: https://docs.sigstore.dev/logging/overview/

### policy-controller not installed or set to audit-only — CWE-284

- Why: Without policy-controller (or equivalent admission webhook) set to `enforce` mode, Kubernetes will run unsigned images even if verification is part of the CI pipeline.
- Grep: `mode:\s*audit` in ClusterImagePolicy or absence of `policy.sigstore.dev` annotations
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://github.com/sigstore/policy-controller

## Secure patterns

Keyless cosign signing in GitHub Actions (OIDC — no long-lived key):

```yaml
jobs:
  sign:
    permissions:
      id-token: write   # for OIDC token to Fulcio
      packages: write   # to push signature to registry
    steps:
      - name: Install cosign
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20  # v3.5.0

      - name: Build and push image
        id: build
        uses: docker/build-push-action@...
        with:
          push: true
          tags: ghcr.io/myorg/myapp:${{ github.sha }}

      - name: Sign image with keyless cosign
        run: |
          cosign sign --yes \
            ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

Source: https://docs.sigstore.dev/signing/overview/ and https://slsa.dev/blog/2022/06/slsa-cosign-keyless

Verifying a container image signature before deployment:

```bash
cosign verify \
  --certificate-identity-regexp="^https://github.com/myorg/myrepo/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp@sha256:<digest>
```

Source: https://docs.sigstore.dev/verifying/verify/

Kubernetes ClusterImagePolicy with policy-controller (enforce mode):

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: myapp-signed-images
spec:
  images:
    - glob: "ghcr.io/myorg/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "^https://github.com/myorg/.*/.github/workflows/release.yml@refs/heads/main$"
      ctlog:
        url: https://rekor.sigstore.dev
```

Source: https://github.com/sigstore/policy-controller

## Fix recipes

### Recipe: Add keyless cosign signing to release workflow — addresses CWE-494

**Before (dangerous):**

```yaml
jobs:
  release:
    steps:
      - name: Build and push
        uses: docker/build-push-action@...
        with:
          push: true
          tags: myregistry/myapp:latest
      # image pushed without signing
```

**After (safe):**

```yaml
jobs:
  release:
    permissions:
      id-token: write
      packages: write
    steps:
      - name: Install cosign
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20  # v3.5.0

      - name: Build and push
        id: build
        uses: docker/build-push-action@...
        with:
          push: true
          tags: ghcr.io/myorg/myapp:${{ github.ref_name }}

      - name: Sign image
        run: |
          cosign sign --yes \
            ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

Source: https://docs.sigstore.dev/signing/overview/

### Recipe: Add cosign verify to deployment pipeline — addresses CWE-494

**Before (dangerous):**

```bash
# deploy.sh
docker pull myregistry/myapp:v1.2.3
docker run -d myregistry/myapp:v1.2.3
```

**After (safe):**

```bash
# deploy.sh
IMAGE="ghcr.io/myorg/myapp@sha256:<digest>"

cosign verify \
  --certificate-identity-regexp="^https://github.com/myorg/myrepo/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  "$IMAGE"

docker run -d "$IMAGE"
```

Source: https://docs.sigstore.dev/verifying/verify/

### Recipe: Replace plaintext key signing with KMS-backed key — addresses CWE-312

**Before (dangerous):**

```bash
cosign generate-key-pair         # produces cosign.key (plaintext)
cosign sign --key cosign.key myregistry/myapp:v1.2.3
```

**After (safe — prefer keyless; if key-based is required, use KMS):**

```bash
# AWS KMS
cosign sign --key awskms:///arn:aws:kms:us-east-1:123456789012:key/<key-id> \
  myregistry/myapp@sha256:<digest>

# Verify
cosign verify --key awskms:///arn:aws:kms:us-east-1:123456789012:key/<key-id> \
  myregistry/myapp@sha256:<digest>
```

Source: https://docs.sigstore.dev/signing/overview/

### Recipe: Set policy-controller to enforce mode — addresses CWE-284

**Before (dangerous):**

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
spec:
  mode: audit   # allows unsigned images, only logs violations
```

**After (safe):**

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
spec:
  mode: enforce   # rejects unsigned/unverified images at admission time
```

Source: https://github.com/sigstore/policy-controller

## Version notes

- cosign v2.0+ changed the default signature format; v1.x signatures are still verifiable with `--signature-digest-algorithm sha256` but new signs produce OCI referrers-based storage.
- Rekor's public instance (`rekor.sigstore.dev`) is the default transparency log; private Rekor instances are available for air-gapped environments via `--rekor-url`.
- Fulcio certificates are valid for 10 minutes (short-lived by design); the signature and Rekor entry are the durable artifacts.
- `cosign sign --yes` suppresses the interactive confirmation prompt; required in CI environments (non-interactive).
- policy-controller v0.9+ supports `ClusterImagePolicy` with the `v1beta1` API; earlier versions used `alpha` API versions with different field names.

## Common false positives

- `cosign verify` in a local development Makefile target without `--rekor-url` — development verification against a local registry without tlog is acceptable for inner-loop testing; flag only in production deployment scripts.
- `--insecure-ignore-tlog=true` in integration tests against a local registry — acceptable in isolated test environments; flag if present in production deployment pipelines.
- `id-token: write` in workflows that do not sign — this permission is shared with cloud OIDC auth (AWS/GCP); its presence alone does not indicate signing is configured.
- Image signatures stored as tags (`.sig` suffix) in older cosign versions — these are valid signature storage artifacts, not unusual files; do not flag as suspicious.
