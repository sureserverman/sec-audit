# Software Bill of Materials (SBOM)

## Source

- https://www.cisa.gov/sbom — CISA SBOM resources and EO 14028 alignment
- https://spdx.dev/specifications/ — SPDX specification (ISO/IEC 5962:2021)
- https://cyclonedx.org/specification/overview/ — CycloneDX specification
- https://github.com/anchore/syft — Syft SBOM generator (Anchore OSS)
- https://github.com/anchore/grype — Grype vulnerability scanner (Anchore OSS)
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 (container software inventory)

## Scope

Covers SBOM generation (syft, `docker sbom`, Trivy), SBOM formats (SPDX 2.3, CycloneDX 1.6), attaching SBOMs to OCI images as attestations, consuming SBOMs for vulnerability scanning (grype, Trivy), and alignment with US Executive Order 14028 software transparency requirements. Does not cover artifact signing (see `supply-chain/sigstore.md`) or SLSA provenance (see `supply-chain/slsa.md`).

## Dangerous patterns (regex/AST hints)

### No SBOM generated in build pipeline — CWE-1357

- Why: Without an SBOM, the exact components in a release artifact are unknown; vulnerability disclosure cannot be acted on quickly, and EO 14028 compliance cannot be demonstrated.
- Grep: Check for absence of `syft`, `trivy sbom`, `docker sbom`, or `cyclonedx-` in workflow files
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `Makefile`, `**/*.sh`
- Source: https://www.cisa.gov/sbom

### SBOM not attached to or distributed with the artifact — CWE-1357

- Why: An SBOM stored only in a CI artifact store and not attached to the released image or package cannot be consumed by downstream parties or deployment-time scanners.
- Grep: Check for absence of `cosign attest`, `syft attest`, or `oras push` following SBOM generation
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Source: https://spdx.dev/specifications/

### SBOM not scanned for known vulnerabilities — CWE-1035

- Why: Generating an SBOM without feeding it into a scanner (grype, Trivy) provides a component list but no actionable vulnerability findings.
- Grep: Check for absence of `grype`, `trivy image`, or `snyk` following SBOM generation steps
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `Makefile`
- Source: https://github.com/anchore/grype

### SBOM format not machine-parseable (narrative/ad-hoc) — CWE-1357

- Why: SBOM data in non-standard formats (plain text, bespoke JSON schemas) cannot be consumed by standard tooling; use SPDX or CycloneDX.
- Grep: SBOM output files not matching `*.spdx`, `*.spdx.json`, `*.cdx.json`, `bom.xml`
- File globs: `*.txt`, `*.md` (check if these are labeled as SBOM outputs)
- Source: https://cyclonedx.org/specification/overview/

## Secure patterns

Generate SPDX SBOM with syft and attach to OCI image as attestation:

```yaml
# .github/workflows/release.yml
- name: Install syft
  uses: anchore/sbom-action/download-syft@61119d458adab75f756bc0b9e4bde25725f86a7a  # v0.17.0

- name: Generate SBOM
  run: |
    syft ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }} \
      -o spdx-json=sbom.spdx.json

- name: Attest SBOM with cosign
  run: |
    cosign attest --yes \
      --predicate sbom.spdx.json \
      --type spdxjson \
      ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

Source: https://github.com/anchore/syft and https://spdx.dev/specifications/

Scan SBOM for vulnerabilities with grype:

```bash
# Scan image directly (grype generates an internal SBOM)
grype ghcr.io/myorg/myapp@sha256:<digest> --fail-on high

# Or scan a pre-generated SBOM
grype sbom:./sbom.spdx.json --fail-on critical
```

Source: https://github.com/anchore/grype

CycloneDX SBOM for a Python project:

```bash
pip install cyclonedx-bom
cyclonedx-py environment --of JSON -o bom.cdx.json
```

Source: https://cyclonedx.org/specification/overview/

Verify an attached SBOM attestation:

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp="^https://github.com/myorg/myrepo/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myapp@sha256:<digest> \
  | jq '.payload | @base64d | fromjson | .predicate'
```

Source: https://docs.sigstore.dev/verifying/verify/

## Fix recipes

### Recipe: Add syft SBOM generation and grype scan to release workflow — addresses CWE-1357, CWE-1035

**Before (dangerous):**

```yaml
jobs:
  release:
    steps:
      - name: Build and push
        uses: docker/build-push-action@...
        with:
          push: true
          tags: ghcr.io/myorg/myapp:v1.2.3
      # no SBOM, no vulnerability scan
```

**After (safe):**

```yaml
jobs:
  release:
    permissions:
      id-token: write
      packages: write
    steps:
      - name: Build and push
        id: build
        uses: docker/build-push-action@...
        with:
          push: true
          tags: ghcr.io/myorg/myapp:v1.2.3

      - name: Install syft
        uses: anchore/sbom-action/download-syft@61119d458adab75f756bc0b9e4bde25725f86a7a

      - name: Generate SBOM
        run: |
          syft ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }} \
            -o spdx-json=sbom.spdx.json

      - name: Scan SBOM for vulnerabilities
        run: |
          grype sbom:./sbom.spdx.json --fail-on high

      - name: Attest SBOM
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20
      - run: |
          cosign attest --yes \
            --predicate sbom.spdx.json \
            --type spdxjson \
            ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

Source: https://github.com/anchore/syft and https://www.cisa.gov/sbom

### Recipe: Switch from ad-hoc dependency listing to SPDX format — addresses CWE-1357

**Before (dangerous):**

```bash
# "SBOM" as a plain text list — not machine-parseable
pip freeze > dependencies.txt
```

**After (safe):**

```bash
# SPDX JSON — machine-parseable, standard format
pip install cyclonedx-bom
cyclonedx-py environment --of JSON -o bom.cdx.json

# Or with syft for a broader component scan
syft dir:. -o spdx-json=sbom.spdx.json
```

Source: https://cyclonedx.org/specification/overview/

### Recipe: Add grype vulnerability gate to CI — addresses CWE-1035

**Before (dangerous):**

```yaml
- name: Build image
  run: docker build -t myapp:latest .
# no vulnerability scan before push
```

**After (safe):**

```yaml
- name: Build image
  run: docker build -t myapp:latest .

- name: Scan image for vulnerabilities
  uses: anchore/scan-action@3343887d815d7b07465f6fdcd395bd66508d486a  # v4.2.0
  with:
    image: myapp:latest
    fail-build: true
    severity-cutoff: high
```

Source: https://github.com/anchore/grype

## Version notes

- SPDX 2.3 (ISO/IEC 5962:2021) is the current stable version; SPDX 3.0 is in draft. Syft generates 2.3 by default.
- CycloneDX 1.6 is the current specification; 1.4 is still widely supported. Grype can consume both.
- EO 14028 (US Executive Order on Improving the Nation's Cybersecurity, 2021) requires SBOMs for software sold to the US federal government; CISA defines minimum elements at https://www.cisa.gov/sbom.
- `docker sbom` (Docker Scout integration) was introduced in Docker CLI 20.10.x as a plugin; it calls syft internally. It is deprecated in favor of `docker scout sbom` in newer CLI versions.
- Grype 0.74+ updates its vulnerability database on each run by default; in air-gapped environments use `--db-only` to pre-download and `GRYPE_DB_UPDATE_URL` to point to a mirror.

## Common false positives

- High-severity grype findings in dev-only or test-only dependencies — check whether the vulnerable package is reachable in production; `grype --only-fixed` reduces noise by filtering findings with no available fix.
- SBOM attestation absent on internal development builds (non-release commits) — SBOM attestation requirements typically apply only to release artifacts; flag only for images tagged for production deployment.
- Multiple SPDX identifiers for the same component — package managers sometimes list the same library twice (e.g., wheels and source distributions); this is a data quality issue in the SBOM, not a security vulnerability.
- CycloneDX `bom-ref` UUIDs differing between two builds of the same source — these are generated identifiers and their non-reproducibility is expected; the component `name`/`version`/`purl` should be stable.
