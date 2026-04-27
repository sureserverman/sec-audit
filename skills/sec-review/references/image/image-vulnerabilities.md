# Container Image Vulnerabilities

## Source

- https://nvd.nist.gov/ — NIST National Vulnerability Database
- https://osv.dev/ — Open Source Vulnerabilities
- https://aquasecurity.github.io/trivy/ — Trivy documentation (canonical for image scanning)
- https://github.com/anchore/grype — Grype documentation (canonical OSS alternative)
- https://github.com/anchore/syft — Syft documentation (SBOM generation)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA KEV
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 (App Container Security)
- https://csrc.nist.gov/publications/detail/sp/800-204b/final — NIST SP 800-204B (Service Mesh Proxies)
- https://www.cisecurity.org/benchmark/docker — CIS Docker Benchmark

## Scope

Covers vulnerability classes that appear in **compiled container
images** but are NOT visible from source-tree analysis alone:
base-image OS-package CVEs (apt/yum/apk/dnf), language-runtime
CVEs (e.g. `python:3.9` shipping vulnerable openssl, `node:18`
shipping vulnerable libcurl), application-layer dependency CVEs
(installed via `pip install` / `npm install` / `apt-get install`
inside the Dockerfile), embedded-binary CVEs (vendored binaries
copied into the image), and image-metadata-level concerns
(missing labels, missing healthchecks, root user, exposed ports).

The lane consumes **local image artifacts** — image tarballs
(`docker save`-produced `.tar`), OCI layout directories, and
SBOMs (SPDX, CycloneDX) — without contacting any registry or
Docker daemon. Out of scope: live registry pulls, Docker daemon
queries, image diff between versions (single-run only),
base-image upgrade recommendations (requires registry access),
image-policy enforcement (separate concern).

## Dangerous patterns (regex/AST hints)

The lane operates on already-built artifacts, so "patterns" here
are **vulnerability classes detected in installed packages**, not
code-level regex. The patterns below describe the categories of
findings the runner emits + the canonical examples.

### OS package with known CVE in image base layer — CWE-1395

- Why: Base images (`debian:bullseye`, `alpine:3.18`,
  `ubuntu:22.04`) ship with hundreds of OS packages, many of
  which accumulate CVEs over time. An image built six months ago
  from `debian:bullseye` carries every CVE that has been
  disclosed against the packages in that snapshot since then —
  even if the application source is pristine. Trivy / Grype query
  the image's OS-package database (`/var/lib/dpkg/status` for
  Debian-family, `/lib/apk/db/installed` for Alpine,
  `/var/lib/rpm/Packages` for RPM-family) and cross-reference each
  installed package + version against vulnerability feeds. The
  hardened pattern is to (a) rebuild images frequently from a
  current base, (b) pin to digest not tag (covered in
  `virt/docker-runtime.md`), (c) prefer minimal / distroless base
  images (`gcr.io/distroless/*` / `scratch`-with-static-binary)
  that ship fewer packages and therefore fewer CVEs.
- Detection: trivy/grype output records the (package_name,
  installed_version, fixed_version, vuln_id) tuple per finding.
- File globs: image tarball `.tar`, OCI layout `index.json` +
  `blobs/sha256/`, SBOM `.json`.
- Source: https://aquasecurity.github.io/trivy/

### Language-runtime CVE shipping with the base — CWE-1395

- Why: `python:3.9-slim` includes openssl, libffi, sqlite, and
  a hundred other transitive native libraries. A CVE in any of
  those is reachable from any Python application running on
  that image — even when the application's `requirements.txt`
  contains nothing vulnerable. Same pattern applies to
  `node:18-slim` (libuv, OpenSSL, c-ares), `golang:1.21`
  (no pure-Go images solve this — the build tools are still
  vulnerable), `eclipse-temurin:17` (glibc + zlib + krb5).
  Distroless images shrink the surface but do not eliminate it
  (the distroless `base-debian12` still ships glibc + libssl).
- Detection: trivy/grype find these in the same package-database
  scan; the `fixed_version` field indicates which base-image
  upgrade closes the finding.
- Source: https://github.com/aquasecurity/trivy

### Application-layer dependency CVE installed inside the image — CWE-1395

- Why: A Dockerfile that runs `pip install requests==2.20.0`
  embeds requests 2.20.0 (with its CVE history) into the image.
  This CVE is ALSO visible from `requirements.txt` source
  analysis (already covered by sec-review's `python` lane via
  pip-audit + cve-enricher), but image scanning catches the
  same finding at the resolved-package level — useful when the
  source manifest disagrees with what was actually installed
  (e.g. `pip install --upgrade` running on the same line).
  Same pattern for `npm install`, `gem install`, `cargo
  install`, `apt-get install`. Image scanning is the AUTHORITATIVE
  ground-truth view; source manifests are intent.
- Detection: trivy/grype produce findings tagged with the
  language ecosystem (`pkg.PkgType` in trivy: `python-pkg`,
  `npm-pkg`, `gemspec`, `cargo-pkg`).
- Source: https://github.com/anchore/grype

### Vendored binary with CVE (no package manager record) — CWE-1395

- Why: A Dockerfile that does `RUN curl -L https://example.com/
  myapp-v1.2.3 -o /usr/local/bin/myapp` installs a binary that
  is NOT in any package database. OS-package scanners miss it.
  Trivy and Grype have separate scanners for this — Trivy's
  `--scanners vuln,license,secret,misconfig` includes a
  filesystem-walk pass that fingerprints binaries by sha256 and
  cross-references known-vulnerable hashes (Trivy's bundled DB
  + GHSA). This catches CVE-2021-44228-class vulnerabilities in
  vendored Java JARs even when the JAR is not declared in any
  manifest.
- Detection: tool-specific. Trivy's `--scanners vuln` includes
  this; grype's filesystem-walk does too.
- Source: https://aquasecurity.github.io/trivy/

### Image runs as root (`USER` not set) — CWE-250

- Why: Cross-link to the existing
  `containers/dockerfile-hardening.md` reference's CWE-250
  pattern. Image-scanning tools also flag this from the image's
  metadata (no `USER` instruction — runtime defaults to UID 0).
  trivy + grype both emit a `misconfig` finding for this when
  `--scanners misconfig` is enabled. The image lane treats this
  as duplicate signal with the existing virt/dockerfile-hardening
  reference; the runner deduplicates by ID before emitting
  findings.
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final

### Image with high-severity unpatched-but-fix-available CVE — CWE-1395 + KEV bonus

- Why: Findings where `fixed_version` is non-null AND the CVE
  is in CISA KEV (Known Exploited Vulnerabilities) carry the
  highest priority — the patch exists, the exploit is in active
  use. The cve-enricher's KEV cross-reference (already in place
  for the source-manifest path) extends naturally to image
  findings. trivy supports `--severity-source` to tune which
  vendor advisory dominates per package.
- Detection: tool finding + KEV cross-reference downstream.
- Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Secure patterns

Building a minimal-CVE image (distroless + scratch-with-static):

```dockerfile
# Pattern A: distroless for managed runtime
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/api ./cmd/api

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/api /api
USER 65532:65532
ENTRYPOINT ["/api"]

# Pattern B: scratch with fully-static binary (smallest CVE surface)
FROM scratch
COPY --from=build /out/api /api
USER 65532:65532
ENTRYPOINT ["/api"]
```

Source: https://github.com/GoogleContainerTools/distroless

Generating an SBOM at build time (Syft):

```bash
# Generate an SPDX SBOM for the image:
syft myapp:v1.2.3 -o spdx-json=myapp-v1.2.3.spdx.json

# Or CycloneDX:
syft myapp:v1.2.3 -o cyclonedx-json=myapp-v1.2.3.cdx.json
```

Source: https://github.com/anchore/syft

Scanning a local image tarball offline (Trivy):

```bash
# Save the image to a tarball:
docker save myapp:v1.2.3 -o myapp-v1.2.3.tar

# Scan the tarball offline (trivy bundles its DB):
trivy image --input myapp-v1.2.3.tar \
            --format json \
            --severity HIGH,CRITICAL \
            --exit-code 1 \
            > scan-report.json
```

Source: https://aquasecurity.github.io/trivy/

## Fix recipes

### Recipe: switch from `python:3.9` to `python:3.12-slim` — addresses CWE-1395

**Before (vulnerable base):**

```dockerfile
FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
```

**After (current base, smaller surface):**

```dockerfile
FROM python:3.12-slim AS deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY . .
USER 1000:1000
CMD ["python", "app.py"]
```

Source: https://github.com/aquasecurity/trivy

### Recipe: replace standard base with distroless — addresses CWE-1395 + CWE-250

**Before (large base, runs as root):**

```dockerfile
FROM golang:1.22
WORKDIR /src
COPY . .
RUN go build -o /api ./cmd/api
ENTRYPOINT ["/api"]
```

**After (multistage to distroless, non-root):**

```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/api ./cmd/api

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/api /api
USER 65532:65532
ENTRYPOINT ["/api"]
```

Source: https://github.com/GoogleContainerTools/distroless

### Recipe: pin base image by digest — addresses CWE-829 + CWE-1395

**Before (mutable tag):**

```dockerfile
FROM nginx:1.27
```

**After (digest pin):**

```dockerfile
FROM nginx@sha256:0a399eb16751829e1af26fea27b20c3ec28d7ab1fb72182879dcae1cca21206a   # 1.27.0
```

Source: https://aquasecurity.github.io/trivy/

## Version notes

- Trivy 0.50+ ships a self-contained vulnerability DB (no
  online lookups required when the DB is current); the
  `--db-repository ghcr.io/aquasecurity/trivy-db` and
  `--cache-dir` flags let CI bake the DB into a CI image.
- Grype + Syft 0.74+ similarly support offline-first; the
  `grype db update` step downloads the Anchore DB once.
- Both tools support **CycloneDX** and **SPDX** SBOM input —
  scan an SBOM file directly (`trivy sbom myapp.cdx.json`,
  `grype sbom:myapp.spdx.json`) when the image is not
  available locally but the SBOM is.
- Trivy's `--scanners` flag is multi-pass: `vuln`
  (CVE matching against installed packages), `secret` (token
  fingerprints in image layers — overlaps with the existing
  `secrets/` reference pack), `misconfig` (Dockerfile / K8s /
  Terraform IaC scanning — overlaps with `iac` and `virt`
  lanes), `license` (license-policy concerns). The image lane
  uses ONLY `vuln` to avoid duplication with other lanes.

## Common false positives

- Test-fixture images intentionally containing vulnerable
  dependencies (sec-review's own `vulnerable-*` fixtures) —
  annotate; flag only when the image lands in production
  paths.
- CVEs flagged against packages whose vulnerable code paths
  are unreachable from the application's entry points —
  reachability analysis is out of scope for trivy/grype's
  default mode; sec-expert can downgrade these post-hoc when
  the application's code clearly does not invoke the
  affected APIs.
- Base-image CVEs flagged against transitive system libraries
  (e.g. a CVE in `libldap` shipped in the base) when the
  application demonstrably does not use LDAP — same
  reachability gap.
- CVEs against vendor-disputed packages (e.g. some glibc
  CVEs disputed by upstream) — both trivy and grype flag
  these but mark `confirmed_by_vendor=false` in the output;
  the runner downgrades severity per the upstream tool's
  signal.
