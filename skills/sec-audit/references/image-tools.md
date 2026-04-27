# image-tools

<!--
    Tool-lane reference for sec-audit's image lane (v1.11.0+).
    Consumed by the `image-runner` sub-agent. Documents
    trivy + grype.
-->

## Source

- https://aquasecurity.github.io/trivy/ — Trivy canonical (Aqua Security; Go binary; comprehensive vulnerability + misconfig + secret + license scanner)
- https://github.com/aquasecurity/trivy — Trivy source
- https://github.com/anchore/grype — Grype canonical (Anchore; Go binary; OSS image vulnerability scanner; pairs with Syft for SBOM)
- https://github.com/anchore/syft — Syft (paired SBOM generator; OPTIONAL — image-runner does not invoke it directly but documents it as the canonical pre-image SBOM tool)
- https://docs.docker.com/scout/ — Docker Scout (the commercial inspiration for this lane; NOT used because of Docker-daemon dependency + Docker Hub login requirement)
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `image-runner` —
`trivy image --input <tarball>` (Trivy's image-tarball scan
mode; offline-capable; runs the `vuln` scanner only to avoid
duplication with the existing `iac` / `virt` / `secrets`
lanes) and `grype <input>` (Grype's image / SBOM scan mode;
accepts tarballs, OCI layout dirs, and SPDX/CycloneDX SBOMs).
Both tools are cross-platform Go binaries. Both are
offline-capable: their vulnerability databases download once
(at install time) and cache locally; subsequent scans need
no network.

This is the **OSS-equivalent of Docker Scout's CVE scanning
feature**. Docker Scout itself is not used because:
1. It requires Docker daemon access (host-gated; sec-audit
   contracts say no host dependencies).
2. It requires Docker Hub login for several features.
3. It is commercial freemium, not OSS — out of scope for a
   primary-source-cited static-analysis plugin.

Trivy + Grype combined cover the same scanning surface as
Docker Scout's `cves` and `recommendations` subcommands,
without those gates. Out of scope: live registry pulls (the
runner does NOT contact registries); image-diff between
versions (single-run only; no snapshot comparison);
base-image upgrade recommendations (require registry pulls);
policy enforcement (separate orchestration concern); license
scanning (license-compliance is not security).

## Canonical invocations

### trivy

- Install: `apt install trivy` / `brew install trivy` / `dnf install trivy` / pre-built binaries from GitHub Releases. Cross-platform Go binary; requires no Docker daemon.
- DB bootstrap (one-time, online): `trivy image --download-db-only` populates `~/.cache/trivy/`. After that, the runner can scan offline.
- Invocation:
  ```bash
  trivy image \
      --input "$image_tarball" \
      --format json \
      --scanners vuln \
      --severity HIGH,CRITICAL,MEDIUM,LOW \
      --skip-update \
      > "$TMPDIR/image-runner-trivy.json" \
      2> "$TMPDIR/image-runner-trivy.stderr"
  rc_tr=$?
  ```
  `--scanners vuln` restricts to vulnerability-matching
  (skipping misconfig + secret + license scanners that
  duplicate other lanes). `--skip-update` keeps the run
  fully offline; the runner expects the DB to be current
  (operator's responsibility).
- Output: JSON object with `Results: [{Target, Type, Vulnerabilities: [...]}]`. Each Vulnerability has `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `Title`, `Description`, `References`, `CweIDs`, `CVSS`.
- Tool behaviour: exits non-zero when any vulnerability fires (exit code = highest severity, configurable via `--exit-code`). Empty result is a `Results` array with no `Vulnerabilities`. NOT a crash — parse JSON regardless.
- Primary source: https://aquasecurity.github.io/trivy/

Source: https://aquasecurity.github.io/trivy/

### grype

- Install: `brew install grype` / `apt install grype` / pre-built binaries from GitHub Releases. Cross-platform Go binary; requires no Docker daemon.
- DB bootstrap (one-time, online): `grype db update`.
- Invocation (image tarball input):
  ```bash
  grype "$image_tarball" \
      --output json \
      --fail-on high \
      > "$TMPDIR/image-runner-grype.json" \
      2> "$TMPDIR/image-runner-grype.stderr"
  rc_gr=$?
  ```
  Or (SBOM input — when only an SBOM is available):
  ```bash
  grype sbom:"$sbom_file" \
      --output json \
      > "$TMPDIR/image-runner-grype-sbom.json"
  ```
- Output: JSON object with `matches: [{vulnerability, artifact, ...}]`. Each match has `vulnerability.id`, `vulnerability.severity`, `vulnerability.fix.versions[]`, `vulnerability.cvss[]`, `artifact.name`, `artifact.version`, `artifact.type`.
- Tool behaviour: exits non-zero per `--fail-on` threshold. Empty result is `matches: []`. NOT a crash — parse JSON regardless.
- Primary source: https://github.com/anchore/grype

Source: https://github.com/anchore/grype

## Output-field mapping

Every finding carries `origin: "image"`,
`tool: "trivy" | "grype"`, `reference: "image-tools.md"`.

### trivy → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"trivy:" + .Vulnerabilities[].VulnerabilityID` (CVE-… or GHSA-…) | `id`             |
| `.Severity` remap: `CRITICAL` → CRITICAL, `HIGH` → HIGH, `MEDIUM` → MEDIUM, `LOW` → LOW, `UNKNOWN` → LOW | `severity` |
| First entry from `.CweIDs[]` if present (formatted `"CWE-" + n`); else `"CWE-1395"` (vulnerable third-party component) | `cwe` |
| `.Title` (or first 80 chars of `.Description` if Title absent) | `title`                |
| Image-tarball path relative to target_path             | `file`                       |
| 0 (image findings have no source line)                | `line`                       |
| `.PkgName + " " + .InstalledVersion + " — " + .VulnerabilityID + (if .FixedVersion: " — fixed in " + .FixedVersion)` | `evidence` |
| First entry from `.References[]` if present; else `"https://nvd.nist.gov/vuln/detail/" + .VulnerabilityID` | `reference_url` |
| `if .FixedVersion: ("upgrade to >=" + .FixedVersion) else null` | `fix_recipe`        |
| `"high"` (trivy is deterministic; vulnerability-feed-backed)  | `confidence`         |

### grype → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"grype:" + .matches[].vulnerability.id`              | `id`                         |
| `.vulnerability.severity` remap: `Critical` → CRITICAL, `High` → HIGH, `Medium` → MEDIUM, `Low` → LOW, `Negligible`/`Unknown` → LOW | `severity` |
| `"CWE-1395"` (grype does not consistently ship per-vuln CWE)  | `cwe`                |
| `.vulnerability.description` truncated to 200 chars (or first line) | `title`        |
| Image-tarball path relative to target_path             | `file`                       |
| 0                                                      | `line`                       |
| `.artifact.name + " " + .artifact.version + " — " + .vulnerability.id + (if .vulnerability.fix.versions[0]: " — fixed in " + .vulnerability.fix.versions[0])` | `evidence` |
| `.vulnerability.dataSource` (URL to the upstream advisory; e.g. `https://nvd.nist.gov/vuln/detail/CVE-...`) | `reference_url` |
| `if .vulnerability.fix.versions[0]: ("upgrade to >=" + .vulnerability.fix.versions[0]) else null` | `fix_recipe` |
| `"high"`                                               | `confidence`                 |

### Deduplication

Trivy and Grype overlap heavily — they both detect most
CVEs in the same image. The runner deduplicates by
`(file, vulnerability_id, package_name)` tuple BEFORE
emitting; the first tool to fire owns the finding. Order of
preference: trivy first (broader feed coverage), then grype
(catches some Anchore-DB-only entries trivy misses). Both
tools' findings appear in `__image_status__` tool list when
both run.

## Degrade rules

`__image_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.11.0):

- `tool-missing` — the tool's binary is absent from PATH.
- `no-image-artifact` — NEW in v1.11; the tool is on PATH
  but target has no image-shaped artifact (no `*.tar` / OCI
  layout directory / SBOM file under target). Target-shape
  clean-skip; parallel to v0.10–v1.9 target-shape primitives.

No host-OS gate — both tools cross-platform. Network access
is NOT required for scanning (the DBs are pre-cached); the
runner sets `--skip-update` (trivy) / does not call `db
update` (grype) at run time.

## Version pins

- `trivy` ≥ 0.50 (stable JSON schema with `Results[]` shape;
  `--scanners` flag finalised; offline DB stable). Pinned
  2026-04. Older 0.40.x versions emit a different JSON shape
  with `ArtifactName` at top level — the runner's jq path
  tolerates both.
- `grype` ≥ 0.74 (stable JSON output with `matches[]` shape;
  `--fail-on` finalised). Pinned 2026-04.
