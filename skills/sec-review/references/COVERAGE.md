# COVERAGE

<!--
    Single-source-of-truth coverage enumeration for the sec-review
    plugin as of v1.5.0. This file is the authoritative "what does
    sec-review actually cover?" reference — read it before the per-
    lane packs to understand the plugin's shape.

    Structure: a header, a scope summary, one subsection per shipped
    lane, the ecosystem-to-feed routing table, and the complete skip-
    reason vocabulary.
-->

## Source

- `skills/sec-review/SKILL.md` — orchestrator; authoritative sequence of §1-§7
- `.claude-plugin/plugin.json` — plugin version and lane enumeration
- All per-lane reference packs under `skills/sec-review/references/`
- All per-lane sub-agents under `agents/`

## Scope

The sec-review plugin performs citation-grounded security review of
software projects across fourteen tool lanes plus sec-expert code
reasoning. It reads source trees and pre-built artifacts, emits
origin-tagged JSONL findings per lane, enriches with live CVE data,
and produces a prioritized markdown report. All fix recipes are
quoted verbatim from primary-source reference packs (vendor docs +
IETF RFCs + OWASP + CIS + NIST + Mozilla + OpenID + SLSA/Sigstore/
CISA).

## Lanes

The plugin dispatches up to fifteen review streams in parallel
(fourteen tool lanes plus the sec-expert code-reasoning stream).
Each inventory key in `§2 Inventory` maps to one dispatch target.
Two or more keys trigger multi-stack dispatch; see SKILL.md §3.0
Dispatch discipline.

### sec-expert — code reasoning

- **Target shape:** any source tree.
- **Tool:** no external binary; the sec-expert sub-agent (sonnet-
  pinned) applies the citation-grounded reference packs directly.
- **Reference packs loaded (conditionally per inventory):**
  `databases/`, `frameworks/`, `webservers/` (incl. IIS as of
  v0.4.0), `proxies/`, `frontend/`, `auth/`, `tls/`, `containers/`,
  `secrets/`, `supply-chain/`.
- **Host-OS gate:** none.
- **Skip reasons:** none (always dispatches when any source is
  detected; a target with no recognised signals produces a minimal
  report).
- **Origin tag:** absent — sec-expert findings have no `origin` field;
  this distinguishes them from runner-originated findings.
- **Shipped in:** v0.2.0 (six-agent architecture).

### sast

- **Target shape:** source tree.
- **Tools:** `semgrep` (OWASP Top Ten ruleset), `bandit` (Python).
- **Reference pack:** `references/sast-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"sast"`. Tool whitelist: `semgrep`, `bandit`.
- **Shipped in:** v0.4.0.

### dast

- **Target shape:** running HTTP(S) URL supplied via `target_url` /
  `$DAST_TARGET_URL`.
- **Tools:** OWASP ZAP baseline (via docker or local `zap-baseline.py`).
- **Reference pack:** `references/dast-tools.md`.
- **Host-OS gate:** none (docker-native).
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"dast"`. Tool whitelist: `zap-baseline`.
- **Shipped in:** v0.5.0.

### webext

- **Target shape:** Chrome MV3 or Firefox AMO browser-extension
  source tree (`manifest.json` with `manifest_version` key).
- **Tools:** `addons-linter` (Mozilla AMO validator), `web-ext lint`,
  `retire.js` (bundled-JS vuln scan).
- **Reference packs:** `references/frontend/webext-chrome-mv3.md`,
  `webext-firefox-amo.md`, `webext-shared-patterns.md`,
  `references/webext-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"webext"`. Tool whitelist: `addons-linter`,
  `web-ext`, `retire`.
- **Shipped in:** v0.6.0.

### rust

- **Target shape:** Rust/Cargo project (`Cargo.toml` with
  `[package]` or `[workspace]`).
- **Tools:** `cargo-audit` (RustSec DB), `cargo-deny`, `cargo-geiger`
  (unsafe-surface, hard-capped at INFO), `cargo-vet` (supply-chain
  attestation).
- **Reference packs:** `references/rust/cargo-ecosystem.md`,
  `references/rust/unsafe-surface.md`, `references/rust-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"rust"`. Tool whitelist: `cargo-audit`,
  `cargo-deny`, `cargo-geiger`, `cargo-vet`. cargo-geiger findings
  MUST be `severity: "INFO"` — enforced by contract-check.
- **Shipped in:** v0.7.0.

### android

- **Target shape:** Android source tree (`AndroidManifest.xml` OR
  `build.gradle(.kts)` with `com.android.application` /
  `com.android.library` plugin).
- **Tools:** `mobsfscan` (cross-platform Swift+Obj-C+Java+Kotlin),
  `apkleaks` (compiled APK secret scanner), `android-lint` (via
  gradle wrapper or standalone).
- **Reference packs:** `references/mobile/android-manifest.md`,
  `android-data.md`, `android-runtime.md`,
  `references/mobile-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `no-apk` (apkleaks needs compiled APK),
  `tool-missing`.
- **Origin tag:** `"android"`. Tool whitelist: `mobsfscan`,
  `apkleaks`, `android-lint`.
- **Shipped in:** v0.8.0.

### ios

- **Target shape:** iOS project (`Info.plist` with
  `MinimumOSVersion` or `UIDeviceFamily`, `*.xcodeproj`,
  `Package.swift`, `Podfile`).
- **Tools:** `mobsfscan` (shared with android), plus Apple-binary
  stack `codesign` / `spctl` / `xcrun notarytool` (macOS-host only).
- **Reference packs:** `references/mobile/ios-plist.md`,
  `ios-data.md`, `ios-codesign.md`, `references/mobile-tools.md`
  (iOS subsections).
- **Host-OS gate:** `requires-macos-host` for the three Apple tools;
  mobsfscan is cross-platform.
- **Skip reasons:** `requires-macos-host`, `no-bundle` (codesign /
  spctl need `.app`/`.framework`/`.xcarchive`), `no-notary-profile`
  (notarytool needs `$NOTARY_PROFILE`), `tool-missing`.
- **Origin tag:** `"ios"`. Tool whitelist: `mobsfscan`, `codesign`,
  `spctl`, `notarytool`.
- **Shipped in:** v0.9.0.

### linux (desktop)

- **Target shape:** systemd units / `debian/control` / `*.spec` /
  Flatpak manifest / `snapcraft.yaml`.
- **Tools:** `systemd-analyze security` (systemd-host + unit-present),
  `lintian` (debian/ source), `checksec` (ELF present).
- **Reference packs:** `references/desktop/linux-systemd.md`,
  `linux-sandboxing.md`, `linux-packaging.md`,
  `references/linux-tools.md`.
- **Host-OS gate:** `requires-systemd-host` for systemd-analyze;
  lintian and checksec are cross-platform.
- **Skip reasons:** `requires-systemd-host`, `no-debian-source`,
  `no-elf`, `no-systemd-unit`, `tool-missing`.
- **Origin tag:** `"linux"`. Tool whitelist: `systemd-analyze`,
  `lintian`, `checksec`.
- **Shipped in:** v0.10.0.

### macos (desktop)

- **Target shape:** macOS source tree / artifact (`Info.plist` with
  `LSMinimumSystemVersion` / `*.pkg` / `*.dmg` / Sparkle framework /
  `.app` with macOS deployment-target).
- **Tools:** `mobsfscan` (shared with android/ios), plus Apple-binary
  stack `codesign` / `spctl` / `pkgutil` / `stapler` (macOS-host only).
- **Reference packs:** `references/desktop/macos-hardened-runtime.md`,
  `macos-tcc.md`, `macos-packaging.md`, `references/mobile-tools.md`
  (iOS + macOS subsections — shared file with the iOS lane).
- **Host-OS gate:** `requires-macos-host` for the four Apple tools.
- **Skip reasons:** `requires-macos-host`, `no-bundle`, `no-pkg`
  (pkgutil needs `.pkg`), `no-notary-profile`, `tool-missing`.
- **Origin tag:** `"macos"`. Tool whitelist: `mobsfscan`, `codesign`,
  `spctl`, `pkgutil`, `stapler`.
- **Shipped in:** v0.11.0.

### windows (desktop)

- **Target shape:** .NET / C++ / Visual Studio source
  (`*.csproj`/`*.vcxproj`/`*.sln`/`*.nuspec`), WiX sources (`*.wxs`),
  MSIX manifests (`AppxManifest.xml`/`Package.appxmanifest`),
  compiled PE artifacts (`*.exe`/`*.dll`/`*.msi`/`*.msix`/`*.sys`),
  AppLocker/WDAC policy XML.
- **Tools:** `binskim` (cross-platform PE hardening scanner),
  `osslsigncode` (cross-platform Authenticode verifier), `sigcheck`
  (Sysinternals; Windows-host only).
- **Reference packs:** `references/desktop/windows-authenticode.md`,
  `windows-applocker.md`, `windows-packaging.md`,
  `references/windows-tools.md`.
- **Host-OS gate:** `requires-windows-host` for sigcheck only;
  binskim and osslsigncode are cross-platform.
- **Skip reasons:** `requires-windows-host`, `no-pe`, `tool-missing`.
- **Origin tag:** `"windows"`. Tool whitelist: `binskim`,
  `osslsigncode`, `sigcheck`.
- **Shipped in:** v0.12.0.

### k8s (Kubernetes admission)

- **Target shape:** any `*.yaml`/`*.yml` under target with both
  top-level `apiVersion:` AND `kind:` keys, where `kind:` matches
  a known K8s resource (Pod, Deployment, StatefulSet, DaemonSet,
  Job, CronJob, Service, Ingress, ConfigMap, Secret,
  ServiceAccount, Role/ClusterRole, RoleBinding/ClusterRoleBinding,
  NetworkPolicy, ValidatingWebhookConfiguration,
  MutatingWebhookConfiguration, CustomResourceDefinition).
- **Tools:** `kube-score` (Go binary; security-best-practice
  scoring), `kubesec` (Go binary; admission-style
  privilege-escalation + host-namespace scoring). Both
  cross-platform; neither requires a live cluster.
- **Reference packs:** `references/infra/k8s-workloads.md`,
  `references/infra/k8s-api.md`, `references/k8s-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"k8s"`. Tool whitelist: `kube-score`, `kubesec`.
- **Dep-inventory:** NOT affected — image references in manifests
  are not package-manifest dependencies; image CVE enrichment is
  future work.
- **Shipped in:** v1.1.0.

### iac (Infrastructure-as-Code)

- **Target shape:** Terraform / Pulumi / Terragrunt source under
  target — `*.tf`, `*.tfvars`, `*.hcl`, `Pulumi.yaml`,
  `Pulumi.<stack>.yaml`, or `terragrunt.hcl`.
- **Tools:** `tfsec` (Go binary, Terraform-focused; AWS/GCP/Azure
  rules with Aqua Vulnerability Database `AVD-*` IDs), `checkov`
  (Python, multi-IaC; complementary CKV-* policy library, run
  with `--framework terraform,pulumi`). Both cross-platform;
  neither requires a live cloud account.
- **Reference packs:**
  `references/infra/iac-cloud-resources.md`,
  `references/infra/iac-secrets-state.md`,
  `references/iac-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"iac"`. Tool whitelist: `tfsec`, `checkov`.
- **Dep-inventory:** NOT affected — Terraform/Pulumi declarations
  reference cloud resources and provider versions, not
  package-manifest dependencies; provider-version CVE enrichment
  is future work.
- **Shipped in:** v1.2.0.

### gh-actions (GitHub Actions workflows)

- **Target shape:** any `.github/workflows/*.yml`/`*.yaml` file
  under target whose contents declare both top-level `on:` and
  `jobs:` keys (the canonical Actions workflow shape).
- **Tools:** `actionlint` (Go binary; broad workflow lint with
  bundled `shellcheck` for script-injection detection), `zizmor`
  (Python; security-focused auditor for pinning, permissions,
  template-injection, dangerous-triggers, artifact-poisoning).
  Both cross-platform; neither contacts the GitHub API.
- **Reference packs:**
  `references/infra/gh-actions-permissions.md`,
  `references/infra/gh-actions-secrets.md`,
  `references/gh-actions-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`.
- **Origin tag:** `"gh-actions"`. Tool whitelist: `actionlint`,
  `zizmor`.
- **Dep-inventory:** NOT affected — workflow files reference
  action versions (`uses: org/repo@SHA`), not package-manifest
  dependencies; SHA-pinning compliance is enforced at the
  code-pattern layer (zizmor's `unpinned-uses` audit).
- **Shipped in:** v1.3.0.

### virt (virtualization / alternative-container-runtimes)

- **Target shape:** any of:
  - Docker runtime config — `docker-compose.y(a)ml`,
    `compose.y(a)ml`, vendored `daemon.json`, or Dockerfile /
    Containerfile / `*.dockerfile` / `*.containerfile`.
  - Podman / Quadlet — `*.container`, `*.volume`, `*.network`,
    `*.pod`, `*.kube`, `*.image`, `*.build`, or
    `policy.json` / `containers-policy.json`.
  - libvirt — `*.xml` with `<domain>` / `<network>` / `<pool>` /
    `<volume>` root element, or `qemu.conf`.
  - Apple Containers — `container.yaml`.
  - UTM — `*.utm/` directory containing `config.plist`.
- **Tools:** `hadolint` (Dockerfile / Containerfile linter with
  `DLxxxx` rule IDs + bundled shellcheck), `virt-xml-validate`
  (libvirt-clients XSD validator). Both cross-platform; neither
  contacts a Docker daemon, podman socket, libvirtd, or any
  registry.
- **Reference packs:** `references/virt/docker-runtime.md`,
  `virt/podman.md`, `virt/libvirt-qemu.md`,
  `virt/apple-containers.md`, `virt/utm.md`,
  `references/virt-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-containerfile` (NEW in
  v1.4 — target-shape; hadolint applicable), `no-libvirt-xml`
  (NEW in v1.4 — target-shape; virt-xml-validate applicable).
- **Origin tag:** `"virt"`. Tool whitelist: `hadolint`,
  `virt-xml-validate`.
- **Dep-inventory:** NOT affected — virt configurations
  reference image tags and host devices, not package-manifest
  dependencies; image-tag pinning compliance is enforced at the
  code-pattern layer (hadolint's `DL3007` rule + sec-expert
  reasoning over the runtime reference packs). The lane
  cross-links to the existing `containers/dockerfile-hardening.md`
  and `containers/docker.md` for Dockerfile-authoring patterns;
  the virt lane covers the runtime / VMM surface those packs do
  NOT.
- **Shipped in:** v1.4.0.

### go

- **Target shape:** Go module (`go.mod` at any project root with
  at least one `*.go` file under it). Distinguished by project
  shape: `["binary"]` if any `*.go` declares `package main`,
  `["library"]` for exported packages, `["workspace"]` if a
  `go.work` workspace file is present (with workspace members
  enumerated from the `use (...)` directive).
- **Tools:** `gosec` (security-focused linter; `Gxxx` rule IDs
  with CWE shipped inline via `.cwe.ID`/`.cwe.URL`),
  `staticcheck` (comprehensive bug-finding + simplifications +
  style; `SAxxxx`/`Sxxxx`/`STxxxx`/`Uxxxx`/`QFxxxx` rules).
  Both cross-platform Go binaries; neither contacts a Go module
  proxy or any registry. Runner sets `GOFLAGS=-mod=readonly` to
  prevent `go.sum` mutations.
- **Reference packs:** `references/go/stdlib-security.md`,
  `go/module-ecosystem.md`, `go/web-frameworks.md`,
  `references/go-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`. (No host-OS gate, no
  target-shape skip — the inventory rule guarantees `go.mod` +
  `*.go` presence before dispatch.)
- **Origin tag:** `"go"`. Tool whitelist: `gosec`, `staticcheck`.
- **Dep-inventory:** AFFECTED — `go.sum` (preferred, transitive)
  or `go.mod` (fallback, direct only) feeds cve-enricher as
  `{"ecosystem": "Go", "manifest": "go.sum"}`. OSV-native; no
  adapter change.
- **Shipped in:** v1.5.0.

## Ecosystems

CVE enrichment routing by inventory-detected ecosystem. OSV
`querybatch` is the primary feed; NVD 2.0 and GHSA serve as
fallbacks. CISA KEV cross-reference adds exploit-in-wild flags to
every CVE.

| Ecosystem     | OSV coverage             | Sourced from                         |
|---------------|--------------------------|--------------------------------------|
| PyPI          | native                   | `requirements.txt`, `poetry.lock`, `pyproject.toml` |
| npm           | native                   | `package.json`, `package-lock.json`  |
| Go            | native                   | `go.mod`, `go.sum`                   |
| Maven         | native                   | `build.gradle(.kts)`, `pom.xml`      |
| RubyGems      | native                   | `Gemfile(.lock)`                     |
| crates.io     | native                   | `Cargo.lock`, `Cargo.toml`           |
| NuGet         | native                   | `*.csproj` `<PackageReference>`      |
| Packagist     | native                   | `composer.json`, `composer.lock`     |
| retire        | best-effort via bundled-JS CVE mapping | webext lane `retire.js` output |
| CocoaPods     | best-effort via GHSA     | `Podfile.lock`                       |
| SwiftPM       | partial (OSV coverage limited) | `Package.resolved`             |
| Debian        | best-effort via Debian Security Tracker | `debian/control`      |

Partial-coverage ecosystems (CocoaPods, SwiftPM, Debian, retire) are
tolerated — cve-enricher emits a `status: "partial"` marker per
ecosystem entry when OSV returns a sparse result, so the report
surfaces the gap rather than silently missing CVEs.

## Skip-reason vocabulary

The structured skipped-list primitive introduced in v0.8 stands at
**12 canonical reason values** as of v1.4, grouped by semantic
category:

### Target-shape (9)

| Reason            | Lane(s)              | Meaning                                                                 |
|-------------------|----------------------|-------------------------------------------------------------------------|
| `no-apk`          | android              | No `*.apk` / `*.aab` under target (apkleaks-specific).                  |
| `no-bundle`       | ios, macos           | No `.app` / `.framework` / `.xcarchive` under target.                   |
| `no-pkg`          | macos                | No `.pkg` under target (pkgutil-specific).                              |
| `no-debian-source`| linux                | No `debian/control` under target (lintian-specific).                    |
| `no-elf`          | linux                | No ELF binary under target (checksec-specific).                         |
| `no-systemd-unit` | linux                | No `.service` under target (systemd-analyze-specific).                  |
| `no-pe`           | windows              | No PE artifact (.exe/.dll/.msi/.msix/.sys) under target.                |
| `no-containerfile`| virt                 | No Dockerfile / Containerfile under target (hadolint-specific).         |
| `no-libvirt-xml`  | virt                 | No XML with libvirt root element under target (virt-xml-validate).      |

### Host-OS-gated (3)

| Reason                  | Lane(s)        | Meaning                                                   |
|-------------------------|----------------|-----------------------------------------------------------|
| `requires-macos-host`   | ios, macos     | The runner is not on macOS; Apple binaries unavailable.   |
| `requires-systemd-host` | linux          | The runner host has no systemd; `systemd-analyze` unavailable. |
| `requires-windows-host` | windows        | The runner is not on Windows; `sigcheck` unavailable.     |

### Profile-absent (1)

| Reason               | Lane(s)  | Meaning                                                         |
|----------------------|----------|-----------------------------------------------------------------|
| `no-notary-profile`  | ios      | `$NOTARY_PROFILE` unset; `xcrun notarytool history` skipped.    |

### Universal catch-all (1)

| Reason          | Lane(s)  | Meaning                                                               |
|-----------------|----------|-----------------------------------------------------------------------|
| `tool-missing`  | ALL      | The binary is absent when its host+target preconditions otherwise held. |

Every skipped entry is a `{"tool": "<name>", "reason": "<reason>"}`
object — enforced by `tests/contract-check.sh`. Downstream consumers
(finding-triager, report-writer) treat host-OS-gated and target-shape
skips as informational metadata (review is partial-by-design) rather
than as actionable gaps; `tool-missing` is surfaced as a
reviewer-actionable "install this tool to deepen the review" banner.
