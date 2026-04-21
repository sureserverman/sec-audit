# SLSA (Supply-chain Levels for Software Artifacts)

## Source

- https://slsa.dev/spec/v1.0/ — SLSA v1.0 specification
- https://slsa.dev/spec/v1.0/levels — SLSA levels 1–3 (v1.0)
- https://slsa.dev/provenance/v1 — SLSA provenance schema v1
- https://slsa.dev/blog/2023/05/slsa-v1-is-here — SLSA v1.0 announcement
- https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html — OWASP Vulnerable Dependency Management Cheat Sheet
- https://www.cisa.gov/resources-tools/resources/sbom-types — CISA software supply chain resources

## Scope

Covers SLSA framework levels 1–3 (v1.0 spec; note that SLSA v0.1 had 4 levels — see Version notes), provenance attestation generation, hermetic and reproducible build requirements, and integration with GitHub Actions OIDC and cosign for provenance signing. Does not cover artifact signing independent of SLSA provenance (see `supply-chain/sigstore.md`) or SBOM generation (see `supply-chain/sbom.md`).

## Dangerous patterns (regex/AST hints)

### No provenance attestation generated — CWE-1357

- Why: Without a provenance attestation, consumers cannot verify who built an artifact, when, from what source, or using what process; supply chain tampering is undetectable.
- Grep: Check for absence of `slsa-github-generator` or `attest-build-provenance` in workflow files
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Source: https://slsa.dev/spec/v1.0/levels

### Build environment not isolated (mutable or shared) — CWE-915

- Why: A shared or mutable build environment can be poisoned between builds; SLSA requires that each build runs in an isolated, ephemeral environment.
- Grep: `runs-on:\s*self-hosted` (self-hosted runners may be persistent and shared)
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Source: https://slsa.dev/spec/v1.0/levels (Build L2: hosted)

### Build inputs not pinned (non-deterministic) — CWE-829

- Why: If build inputs (base images, dependencies) are not pinned to digests, the build is not reproducible and provenance cannot be verified meaningfully.
- Grep: `FROM\s+\S+:(?!.*@sha256:)` or broad version ranges in dependency manifests
- File globs: `Dockerfile`, `Dockerfile.*`, `*.yaml`, `*.yml`
- Source: https://slsa.dev/spec/v1.0/ (Hermeticity requirement)

### SLSA provenance not verified before deploy — CWE-494

- Why: Generating provenance at build time but not verifying it at deploy time provides no protection; the verification step closes the loop.
- Grep: Check for absence of `slsa-verifier` or `cosign verify-attestation` in deployment workflows
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `Makefile`, `**/*.sh`
- Source: https://slsa.dev/provenance/v1

## Secure patterns

GitHub Actions workflow generating SLSA Level 3 provenance using the official generator:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ["v*"]

permissions:
  id-token: write       # for OIDC token (required for SLSA provenance)
  contents: write       # to upload release assets
  attestations: write   # to store attestation

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - name: Build artifact
        run: |
          make build
          sha256sum artifact.tar.gz > SHA256SUMS
      - id: hash
        run: |
          echo "digests=$(base64 -w0 SHA256SUMS)" >> "$GITHUB_OUTPUT"

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: ${{ needs.build.outputs.digests }}
```

Source: https://slsa.dev/spec/v1.0/levels

Verifying SLSA provenance before deploy:

```bash
slsa-verifier verify-artifact artifact.tar.gz \
  --provenance-path artifact.tar.gz.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.2.3
```

Source: https://slsa.dev/provenance/v1

## Fix recipes

### Recipe: Add SLSA provenance generation to release workflow — addresses CWE-1357

**Before (dangerous):**

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - name: Upload release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

**After (safe):**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: make build
      - id: hash
        run: |
          cd dist
          echo "digests=$(sha256sum * | base64 -w0)" >> "$GITHUB_OUTPUT"

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.digests }}"

  release:
    needs: [build, provenance]
    runs-on: ubuntu-latest
    steps:
      - name: Upload artifacts and provenance
        uses: softprops/action-gh-release@c062e08bd532815e2082a7e09ce9571a6b2350be
        with:
          files: |
            dist/*
            *.intoto.jsonl
```

Source: https://slsa.dev/spec/v1.0/levels

### Recipe: Add provenance verification step to deploy workflow — addresses CWE-494

**Before (dangerous):**

```bash
# deploy.sh — downloads artifact and deploys directly
curl -LO https://github.com/myorg/myrepo/releases/download/v1.2.3/artifact.tar.gz
./deploy.sh artifact.tar.gz
```

**After (safe):**

```bash
# download artifact and provenance
curl -LO https://github.com/myorg/myrepo/releases/download/v1.2.3/artifact.tar.gz
curl -LO https://github.com/myorg/myrepo/releases/download/v1.2.3/artifact.tar.gz.intoto.jsonl

# verify before use
slsa-verifier verify-artifact artifact.tar.gz \
    --provenance-path artifact.tar.gz.intoto.jsonl \
    --source-uri github.com/myorg/myrepo \
    --source-tag v1.2.3

./deploy.sh artifact.tar.gz
```

Source: https://slsa.dev/provenance/v1

### Recipe: Migrate self-hosted runner to GitHub-hosted for hermetic builds — addresses CWE-915

**Before (dangerous):**

```yaml
jobs:
  build:
    runs-on: self-hosted   # shared, persistent, mutable environment
```

**After (safe):**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest   # ephemeral, GitHub-hosted — satisfies SLSA Build L2
```

If self-hosted runners are required (e.g. for hardware access), ensure they are ephemeral (new runner per job) and network-isolated.

Source: https://slsa.dev/spec/v1.0/levels (Build L2 requirement)

## Version notes

- SLSA v1.0 (published May 2023) reorganized levels from 1–4 (v0.1) to 1–3, removing the former Level 4 (hermetic + reproducible) and renaming the tracks. Provenance schemas changed; v0.1 attestations are not compatible with v1.0 verifiers without migration.
- `slsa-github-generator` v2.0.0 targets SLSA v1.0 provenance format. Versions before v1.5 generated v0.1 format provenance.
- GitHub now has native `attest-build-provenance` action (GitHub artifact attestations, 2024) which is simpler but only supports GitHub consumers; use `slsa-github-generator` for cross-ecosystem verifiability.
- `slsa-verifier` v2.4+ supports verifying both v0.1 and v1.0 provenance; pin to a specific release digest when using in CI.

## Common false positives

- `runs-on: self-hosted` with label `ephemeral` — some organizations run ephemeral self-hosted runners (e.g. via Actions Runner Controller); check runner lifecycle policy before flagging.
- Missing provenance in pre-release or `-dev` workflow branches — provenance is typically only required for release artifacts, not every commit build; scope the finding to release workflows.
- `id-token: write` permission without SLSA generator — this permission is also required for cloud provider OIDC authentication (AWS, GCP) and is not itself a SLSA gap.
