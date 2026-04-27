# SBOM, Image Signatures, and Build Provenance

## Source

- https://spdx.dev/ — SPDX specification (canonical)
- https://cyclonedx.org/ — CycloneDX specification (canonical)
- https://slsa.dev/ — SLSA (Supply-chain Levels for Software Artifacts)
- https://www.sigstore.dev/ — Sigstore project (cosign + Rekor + Fulcio)
- https://github.com/sigstore/cosign — cosign canonical
- https://github.com/in-toto/attestation — in-toto attestation framework
- https://csrc.nist.gov/publications/detail/sp/800-218/final — NIST SP 800-218 (SSDF)
- https://www.executiveorder.us/ — US Executive Order 14028 (SBOM mandate context)
- https://www.cisa.gov/sbom — CISA SBOM resources

## Scope

Covers software-bill-of-materials (SBOM) format requirements, image
signature verification (Sigstore / cosign / GPG-signed manifests),
build-provenance attestation (SLSA, in-toto), and the integration
between these and the image-vulnerability lane. Out of scope:
SBOM-generation lifecycle (build-time tooling — operational
concern); legal license-compliance use of SBOMs (separate concern,
not security); attestation-policy backends (e.g. Sigstore policy
controller — operational).

## Dangerous patterns (regex/AST hints)

### Image artifact with no SBOM in the project — CWE-1357

- Why: An SBOM is the auditable inventory of what's inside a
  software artifact. Without one, downstream consumers cannot
  efficiently determine whether a newly-disclosed CVE affects
  the artifact — they must re-scan from scratch. CISA's SBOM
  guidance and EO 14028's federal procurement requirements
  treat SBOM presence as a baseline. The hardened pattern is
  to generate an SBOM at build time (Syft, Trivy) and ship it
  alongside the image (either embedded as an OCI artifact via
  cosign or as a separate file in releases). Detection: image
  tarball or OCI layout under target_path with NO accompanying
  SBOM file.
- Detection: presence of `*.tar` / OCI layout WITHOUT a
  matching `*.spdx.json` / `*.cyclonedx.json` / `*.sbom.json`
  file in the same directory.
- File globs: `images/*.tar`, `dist/*.tar`, `artifacts/`,
  `releases/`.
- Source: https://www.cisa.gov/sbom

### SBOM in a non-canonical format — CWE-1357

- Why: An SBOM in a custom JSON format (vendor-specific
  schema) is hard to consume by downstream tools. The two
  industry-canonical formats are SPDX (Linux Foundation,
  ISO/IEC 5962:2021) and CycloneDX (OWASP). Either is fine;
  proprietary formats are not. The hardened pattern is to
  generate at least one of SPDX-2.3+ or CycloneDX-1.5+ —
  both Syft and Trivy emit either format directly.
- Detection: project ships SBOM-shaped JSON that does NOT
  conform to SPDX or CycloneDX schema (top-level `spdxVersion`
  or `bomFormat` absent).
- File globs: `*.sbom.json`, `*.bom.json`, `bom.json`.
- Source: https://spdx.dev/

### Image without cosign / GPG signature — CWE-345

- Why: An unsigned image cannot be verified — a registry MITM
  or a registry-level account compromise lands a tampered
  image with no detection. Sigstore (cosign) provides
  keyless signing via OIDC + Rekor transparency log; the
  signing infrastructure is free and the deployment-side
  verification is one CLI call (`cosign verify`).
  Alternatively, GPG-signed manifests (Docker Content Trust
  / Notary v1, deprecated, or Notary v2 / Notation) provide
  the same property with traditional key management. The
  hardened pattern is `cosign sign` at release time + a
  Sigstore policy in the deployment path.
- Detection: image tarball / OCI layout without a
  `*.sig` / `*.cosign.sig` / `*.bundle` companion file, OR
  no `keyless` attestation in the OCI manifest.
- File globs: image tarballs without `*.sig` neighbours.
- Source: https://github.com/sigstore/cosign

### Build provenance attestation absent — CWE-1357 (SLSA Level < 1)

- Why: A build provenance attestation answers: WHICH builder
  built this image, WHEN, from WHICH source commit, with
  WHICH inputs? Without one, the supply-chain trust boundary
  is "trust the registry to have only ever served images
  built by trusted builders." With one (e.g. SLSA Level 3
  attestation from GitHub Actions OIDC), the verifier can
  programmatically confirm the image was built from an
  expected git ref by an expected workflow.
  in-toto / SLSA provenance is the canonical format
  (`in-toto.io/Statement v1` with `slsa.dev/Provenance v1`
  predicate type). Both Sigstore (via cosign attestation)
  and GitHub Actions' built-in provenance generator emit
  these.
- Detection: image without a `*.intoto.jsonl` / `*.att.json`
  companion file containing a SLSA provenance predicate.
- File globs: `*.intoto.jsonl`, `*.att.json`,
  `provenance.json`.
- Source: https://slsa.dev/

### SBOM declares a vendored library at no version (`NOASSERTION`) — CWE-1395

- Why: An SBOM with `NOASSERTION` in the version field for a
  bundled dependency makes vulnerability lookup impossible —
  the scanner cannot match (name, version) to known CVEs.
  This often happens when `syft` cannot determine the version
  of a vendored binary (no package-database record). The
  hardened pattern is to use a build process that records
  versions explicitly (e.g. `go mod` for Go binaries embeds
  the version in the binary; syft 0.96+ can extract it).
- Detection: SBOM contains `versionInfo: NOASSERTION` or
  `version: ""` for security-relevant components.
- File globs: `*.spdx.json`, `*.cyclonedx.json`.
- Source: https://spdx.dev/

### Image references a base by tag in deployment manifests — CWE-829

- Why: Already covered by `virt/docker-runtime.md`'s mutable-
  tag pattern. Cross-link only — the image lane catches the
  resolved-image's actual digest at scan time and emits the
  finding.
- Source: https://github.com/sigstore/cosign

## Secure patterns

Generating + signing + attesting an image (canonical
release-time pipeline):

```bash
# 1. Build the image:
docker buildx build -t myapp:v1.2.3 --output=type=docker .

# 2. Generate SBOM:
syft myapp:v1.2.3 -o spdx-json > myapp-v1.2.3.spdx.json
syft myapp:v1.2.3 -o cyclonedx-json > myapp-v1.2.3.cdx.json

# 3. Sign the image (keyless, OIDC):
cosign sign --yes ghcr.io/example/myapp:v1.2.3

# 4. Attach the SBOM as an OCI artifact:
cosign attach sbom --sbom myapp-v1.2.3.spdx.json \
    ghcr.io/example/myapp:v1.2.3

# 5. Attest build provenance (SLSA L3 from GitHub Actions):
cosign attest --yes \
    --predicate provenance.json \
    --type slsaprovenance \
    ghcr.io/example/myapp:v1.2.3

# 6. Verify on the deployment side:
cosign verify ghcr.io/example/myapp:v1.2.3 \
    --certificate-identity-regexp='^https://github.com/example/' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

Source: https://github.com/sigstore/cosign

GitHub Actions workflow that emits SLSA L3 provenance:

```yaml
jobs:
  build:
    permissions:
      id-token: write       # for keyless cosign
      contents: read
      packages: write       # to push to ghcr.io
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # v4.1.1
      - uses: docker/build-push-action@2cdde995de11925a030ce8070c3d77a52ffcf1c0   # v5.1.0
        with:
          push: true
          tags: ghcr.io/example/myapp:${{ github.sha }}
          provenance: mode=max
          sbom: true        # buildx emits CycloneDX SBOM as OCI artifact
```

Source: https://slsa.dev/

## Fix recipes

### Recipe: generate + ship SBOM alongside image — addresses CWE-1357

**Before (image with no SBOM):**

```bash
docker save myapp:v1.2.3 > artifacts/myapp-v1.2.3.tar
# Just the tarball — no SBOM.
```

**After (image + SBOM in the same artifact bundle):**

```bash
docker save myapp:v1.2.3 > artifacts/myapp-v1.2.3.tar
syft myapp:v1.2.3 -o spdx-json > artifacts/myapp-v1.2.3.spdx.json
syft myapp:v1.2.3 -o cyclonedx-json > artifacts/myapp-v1.2.3.cdx.json
```

Source: https://github.com/anchore/syft

### Recipe: cosign-sign images at release — addresses CWE-345

**Before (unsigned push to registry):**

```bash
docker push ghcr.io/example/myapp:v1.2.3
```

**After (cosign keyless signature + verification):**

```bash
docker push ghcr.io/example/myapp:v1.2.3
cosign sign --yes ghcr.io/example/myapp:v1.2.3

# Deployment-side verification:
cosign verify ghcr.io/example/myapp:v1.2.3 \
    --certificate-identity-regexp='^https://github.com/example/' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

Source: https://github.com/sigstore/cosign

### Recipe: emit SLSA L3 provenance from GitHub Actions — addresses CWE-1357

**Before (build with no provenance):**

```yaml
- run: docker build -t myapp:v1.2.3 .
- run: docker push ghcr.io/example/myapp:v1.2.3
```

**After (buildx with provenance + SBOM as OCI artifacts):**

```yaml
- uses: docker/build-push-action@2cdde995de11925a030ce8070c3d77a52ffcf1c0
  with:
    push: true
    tags: ghcr.io/example/myapp:${{ github.sha }}
    provenance: mode=max
    sbom: true
```

Source: https://slsa.dev/

## Version notes

- SPDX 2.3 (June 2023) added the `relationships` graph for
  build-time provenance; SPDX 3.0 (April 2024) is a structural
  rewrite — most tools are still emitting 2.3 by default.
- CycloneDX 1.6 (April 2024) added the `services` array and
  `formulation` block for build attestation; 1.5 is the most
  widely deployed.
- SLSA Build L3 (June 2023) requires non-falsifiable provenance
  generated by a hosted builder — practical answer is GitHub
  Actions with `permissions.id-token: write` + `provenance:
  mode=max` in `docker/build-push-action`.
- Cosign 2.0+ defaults to keyless signing via Sigstore Fulcio
  + Rekor; the 1.x key-pair workflow is still supported but
  legacy.

## Common false positives

- Test-fixture images intentionally without SBOMs — annotate.
- Internal-only images shipped exclusively to an air-gapped
  environment where the deployment surface is fully under
  operator control — annotate; the SBOM-presence finding is
  INFO not MEDIUM.
- Images signed with a corporate GPG key recorded in
  `gpg-pubring.kbx` rather than via Sigstore — the signature
  exists, just not via the keyless flow; flag as INFO if the
  GPG fingerprint chain is documented elsewhere.
- Old-format SBOMs (SPDX 2.0 or CycloneDX 1.0) — flag with
  upgrade recommendation; downgrade severity since some
  vulnerability cross-reference still works.
