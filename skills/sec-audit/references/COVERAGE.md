# COVERAGE

<!--
    Single-source-of-truth coverage enumeration for the sec-audit
    plugin as of v1.12.0. This file is the authoritative "what does
    sec-audit actually cover?" reference — read it before the per-
    lane packs to understand the plugin's shape.

    Structure: a header, a scope summary, one subsection per shipped
    lane, the ecosystem-to-feed routing table, and the complete skip-
    reason vocabulary.
-->

## Source

- `skills/sec-audit/SKILL.md` — orchestrator; authoritative sequence of §1-§7
- `.claude-plugin/plugin.json` — plugin version and lane enumeration
- All per-lane reference packs under `skills/sec-audit/references/`
- All per-lane sub-agents under `agents/`

## Scope

The sec-audit plugin performs citation-grounded security review of
software projects across twenty tool lanes plus sec-expert
code reasoning. It reads source trees and pre-built artifacts, emits
origin-tagged JSONL findings per lane, enriches with live CVE data,
and produces a prioritized markdown report. All fix recipes are
quoted verbatim from primary-source reference packs (vendor docs +
IETF RFCs + OWASP + CIS + NIST + Mozilla + OpenID + SLSA/Sigstore/
CISA).

## v1.10 UX improvements (no new lanes)

v1.10 adds no new lanes. Two ergonomic improvements:

1. **Default-to-cwd invocation.** `/sec-audit` with no positional
   path argument resolves `target_path` to `$PWD` and proceeds —
   no longer prompts the user. Existing structural guards (refuse
   self-review when cwd is the plugin directory; surface error
   when cwd is unreadable) are preserved.
2. **Coverage-gap suggestions.** A new second pass during §2
   Inventory scans for technologies present in the project but
   NOT covered by any sec-audit lane (using
   `references/uncovered-tech-fingerprints.md`'s curated catalogue
   of sixteen known-but-uncovered technologies). Detected
   technologies are emitted as an `uncovered_tech` array on the
   `inventory.json` record and rendered by `report-writer`'s new
   Step 5.5 in a "Coverage-gap suggestions" section. The section
   is omitted when the array is empty.

## Lanes

The plugin dispatches up to twenty-one review streams in parallel
(twenty tool lanes plus the sec-expert code-reasoning stream).
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

### shell

- **Target shape:** any shell-shaped file under target —
  `*.sh`, `*.bash`, `*.zsh`, `*.ksh`, OR a file whose first
  line is a shell shebang (`#!/bin/sh`, `#!/bin/bash`,
  `#!/usr/bin/env bash`, `#!/usr/bin/env sh`, `#!/bin/dash`,
  `#!/bin/ksh`, `#!/bin/zsh`). Vendored-directory exclusions
  apply: `node_modules/`, `.venv/`, `vendor/`, `dist/`,
  `build/`, `target/`. Inventory value is `["scripts"]` (no
  further sub-shape distinction).
- **Tools:** `shellcheck` (Haskell binary; canonical static
  analyzer for bash/sh/dash/ksh with `SCxxxx` rule IDs).
  Single-tool lane — first since DAST (v0.5). Cross-platform.
- **Reference packs:** `references/shell/command-injection.md`,
  `shell/file-handling.md`, `shell/script-hardening.md`,
  `references/shell-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-shell-source` (NEW
  in v1.6 — target-shape; shellcheck applicable but no
  shell-shaped files under target after vendored-dir
  exclusions).
- **Origin tag:** `"shell"`. Tool whitelist: `shellcheck`.
  Single-tool lane has no `partial` status — only `ok` /
  `unavailable`.
- **Dep-inventory:** NOT affected — shell scripts have no
  package-manifest dependency graph; supply-chain risk for
  sourced remote scripts (the `curl | sh` antipattern) is
  enforced at the code-pattern layer via the
  `shell/file-handling.md` CWE-494 pattern.
- **Shipped in:** v1.6.0.

### python

- **Target shape:** Python project with manifest:
  `requirements.txt`, `requirements-*.txt`, `pyproject.toml`
  with `[tool.poetry]` / `[project]` / `[build-system]`,
  `setup.py`, `Pipfile`, OR a Python package shape (any
  `*.py` accompanied by `__init__.py` / `pyproject.toml` /
  `setup.py`). Inventory values: `["package"]` for an
  application, `["library"]` for a wheel-exporting package,
  `["scripts"]` for a tree of standalone scripts.
- **Tools:** `pip-audit` (PyPA-maintained PyPI vulnerability
  scanner with OSV-backed metadata + reachability-hint
  annotations), `ruff` (Rust-implemented Python linter
  running `S`-prefix flake8-bandit + `B`-prefix flake8-bugbear
  rule families). Both cross-platform; runner is read-only
  with respect to the environment (no `pip install`).
- **Reference packs:**
  `references/python/deserialization.md`,
  `references/python/subprocess-and-async.md`,
  `references/python/framework-deepening.md`,
  `references/python-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-requirements` (NEW
  in v1.7 — target-shape; pip-audit applicable but no
  manifest under target, OR ruff applicable but no `*.py`
  files).
- **Origin tag:** `"python"`. Tool whitelist: `pip-audit`,
  `ruff`.
- **Dep-inventory:** AFFECTED — the existing PyPI ecosystem
  entry (`{"ecosystem": "PyPI", "manifest": "requirements.txt"}`)
  feeds cve-enricher; the python lane's pip-audit pass
  augments cve-enricher's bulk scan with reachability-hint
  metadata.
- **Delineation from SAST lane (§3.6):** The SAST lane runs
  `bandit` + `semgrep` on every project. The python lane is
  additive — pip-audit adds reachability hints,
  ruff ships newer flake8-bandit rules, and the reference
  packs deepen sec-expert reasoning over Python-specific
  surfaces (Pickle/YAML deserialization, asyncio task
  swallowing, FastAPI DI bypass, Django ORM `.extra()`).
- **Shipped in:** v1.7.0.

### ansible

- **Target shape:** any of: a `*.yml` / `*.yaml` file with
  `hosts:` + `tasks:` (canonical playbook), a `roles/`
  directory with role-shape subdirectories, an
  `ansible.cfg`, a `collections/` directory, an inventory
  file or directory, or a `requirements.yml` with `roles:`
  / `collections:` entries.
- **Tools:** `ansible-lint` (Python-implemented Ansible
  playbook + role + collection linter; mature rule catalogue
  covering security like `risky-shell-pipe`,
  `no-log-password`, `command-instead-of-shell`,
  `partial-become`, plus idempotency, deprecation tracking).
  Single-tool lane like Shell (v1.6) and DAST (v0.5).
  Cross-platform; always invoked with `--offline` to suppress
  Galaxy collection lookups.
- **Reference packs:**
  `references/ansible/playbook-security.md`,
  `references/ansible/role-secrets-and-vault.md`,
  `references/ansible-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-playbook` (NEW in
  v1.8 — target-shape; ansible-lint applicable but no
  Ansible-shaped files under target).
- **Origin tag:** `"ansible"`. Tool whitelist: `ansible-lint`.
  Single-tool lane has no `partial` status — only `ok` /
  `unavailable`.
- **Dep-inventory:** NOT affected — Ansible role / collection
  dependencies are not in OSV's coverage; Galaxy
  supply-chain integrity (SHA256 verification against the
  Galaxy registry) is a separate future concern.
- **Shipped in:** v1.8.0.

### netcfg

- **Target shape:** any of the four sub-technologies — Tor
  `torrc` / `torrc-defaults` / `torrc.d/*.conf`; WireGuard
  `*.conf` with `[Interface]` + (`[Peer]` or `PrivateKey`
  or `ListenPort`); sing-box JSON with top-level
  `inbounds` + `outbounds` arrays AND sing-box-vocabulary
  inbound types (socks, http, mixed, vless, trojan,
  hysteria, hysteria2, tuic, naive, shadowsocks); Xray
  JSON with top-level `inbounds` + `outbounds` arrays AND
  Xray-vocabulary protocols (vless, vmess, trojan,
  shadowsocks, dokodemo-door, freedom, blackhole).
- **Tools:** `sing-box check` and `xray test -confdir` —
  STRUCTURAL validators (catch typos, schema violations,
  cross-field impossibilities), NOT security scanners.
  Cross-platform Go binaries. Tor (torrc) and WireGuard
  (*.conf) are NOT linted by any runner-invoked tool —
  sec-expert handles them entirely via reference packs.
- **Reference packs:** `references/netcfg/tor.md`,
  `references/netcfg/wireguard.md`,
  `references/netcfg/sing-box.md`,
  `references/netcfg/xray.md`,
  `references/netcfg-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-singbox-config`
  (NEW in v1.9 — target-shape; sing-box on PATH but no
  sing-box-shaped JSON), `no-xray-config` (NEW in v1.9 —
  target-shape; xray on PATH but no Xray-shaped JSON).
- **Origin tag:** `"netcfg"`. Tool whitelist: `sing-box`,
  `xray`.
- **Dep-inventory:** NOT affected — Tor / WireGuard /
  sing-box / Xray configurations are not package-manifest
  dependency graphs.
- **Runner-vs-sec-expert split:** the runner emits
  STRUCTURAL findings only (sing-box / xray invalid-config
  errors). All security-pattern findings (Tor ControlPort
  exposure, WG AllowedIPs scoping, sing-box CORS / Reality
  short_id, Xray VMess legacy / SS deprecated cipher) come
  from sec-expert reading the reference packs.
- **Shipped in:** v1.9.0.

### image (container image vulnerability scanning)

- **Target shape:** any of: image tarball (`*.tar` containing
  `manifest.json` Docker save format OR `index.json` OCI archive
  format), OCI image layout directory (`oci-layout` +
  `index.json` + `blobs/sha256/` shape), SPDX SBOM file
  (`*.spdx.json` with `spdxVersion` field), CycloneDX SBOM file
  (`*.cyclonedx.json` / `*.cdx.json` / `*.sbom.json` /
  `bom.json` with `bomFormat: "CycloneDX"`). Inventory values:
  `["tarball"]`, `["oci-layout"]`, `["sbom-spdx"]`,
  `["sbom-cyclonedx"]`, or combinations.
- **Tools:** `trivy image --input <tarball>` (Aqua Security;
  vulnerability scanner with `--scanners vuln` mode;
  offline-capable via pre-cached DB; `--skip-update` at run
  time), `grype <input>` (Anchore; accepts tarballs / OCI
  layouts / SBOMs). Both cross-platform Go binaries; neither
  requires Docker daemon, neither pulls from registries.
  Runner deduplicates trivy+grype overlap by `(file, vuln_id,
  package_name)` tuple — trivy wins on collision.
- **Reference packs:** `references/image/image-vulnerabilities.md`,
  `references/image/sbom-and-provenance.md`,
  `references/image-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-image-artifact` (NEW
  in v1.11 — target-shape; tool on PATH but no image
  tarball / OCI layout / SBOM under target).
- **Origin tag:** `"image"`. Tool whitelist: `trivy`, `grype`.
- **Dep-inventory:** AFFECTED post-hoc. Image findings carry
  CVE IDs inline (no enrichment needed for the match itself),
  but cve-enricher's CISA KEV cross-reference applies post-hoc:
  any image finding whose `vuln_id` is in KEV gets the +20-pt
  KEV bonus per §5's prioritization rubric.
- **Docker Scout positioning:** the OSS-equivalent of `docker
  scout cves`. Out of scope: live registry pulls, image-diff
  between versions, base-image-upgrade recommendations,
  policy enforcement, license scanning (out of scope per
  contract; some addressable at orchestration layer in
  future).
- **Shipped in:** v1.11.0.

### ai-tools (AI coding tool config audit)

- **Target shape:** any of: Claude Code plugin manifest
  (`.claude-plugin/plugin.json` / `.claude-plugin/marketplace.json`);
  Claude Code project settings (`.claude/settings.json` /
  `.claude/settings.local.json`); Claude Code subagents / skills /
  commands (`agents/*.md`, `skills/**/SKILL.md`, `commands/*.md`
  with YAML `name:` + `description:` frontmatter); MCP server config
  (`.mcp.json` at any depth); Cursor rules (`.cursor/rules/*.mdc` or
  `.cursorrules`); Codex agents/config (`AGENTS.md`,
  `.codex/config.toml`, `.codex/agents/*.md`); OpenCode config
  (`opencode.json` or `.opencode/`). Inventory values:
  `["claude-code"]`, `["cursor"]`, `["codex"]`, `["opencode"]`, or
  combinations. `AGENTS.md` fires both `codex` and `opencode`.
- **Tools:** `jq` (universal C-implemented JSON validator;
  `--exit-status .` mode for structural well-formedness check)
  AND `mcp-scan inspect --json` (Invariant Labs; rebranded
  `snyk-agent-scan` after the Snyk acquisition; Apache-2.0)
  for tool-poisoning + malicious-description detection on
  `.mcp.json` / `claude_desktop_config.json` / skill markdown
  trees. Static-only: the runner uses `inspect` mode and
  forbids the `scan` subcommand and
  `--dangerously-run-mcp-servers`, both of which would launch
  stdio MCP servers locally. Two-tool lane like SAST
  (semgrep + bandit) and webext (addons-linter + web-ext +
  retire). Cross-platform.
- **Reference packs:** `references/ai-tools/claude-code-plugin.md`,
  `references/ai-tools/claude-code-mcp.md`,
  `references/ai-tools/prompt-injection.md`,
  `references/ai-tools/cursor-rules.md`,
  `references/ai-tools/codex-opencode.md`,
  `references/ai-tools-tools.md`.
- **Host-OS gate:** none.
- **Skip reasons:** `tool-missing`, `no-ai-tool-config`
  (target-shape; tool on PATH but no in-scope file under
  target), `parse-failed` (NEW in v1.13 — mcp-scan ran but
  output JSON could not be parsed into a recognized issue
  list).
- **Origin tag:** `"ai-tools"`. Tool whitelist:
  `jq`, `mcp-scan`. As of v1.13 this is a two-tool lane,
  so all three status values apply: `ok` (both ran),
  `partial` (one ran, one missing or parse-failed),
  `unavailable` (both missing or no in-scope inputs).
- **Dep-inventory:** NOT affected — AI-tool config files
  reference MCP server packages (`npx <pkg>` / `uvx <pkg>`)
  and skill content but are not package-manifest dependency
  graphs in the OSV sense. Supply-chain risk for MCP server
  packages is enforced at the code-pattern layer via
  `claude-code-mcp.md`'s CWE-1395 unpinned-package rule.
- **Runner-vs-sec-expert split:** the runner emits STRUCTURAL
  findings only (jq parse errors on malformed manifests). All
  security-pattern findings (prompt injection in
  skill / agent / rule descriptions; `Bash(*)` wildcards in
  `allowed-tools`; `dangerouslyDisableSandbox: true`; HTTP MCP
  server URLs and unpinned `npx`/`uvx`; `alwaysApply: true`
  rules without `globs:`; `approval_policy = "never"` and
  `sandbox_mode = "danger-full-access"`; hardcoded `sk-ant-` /
  `sk-proj-` / `gho_` / AWS keys) come from sec-expert reading
  the per-platform reference packs.
- **Shipped in:** v1.12.0.

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
**20 canonical reason values** as of v1.13, grouped by semantic
category:

### Target-shape (16)

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
| `no-shell-source` | shell                | No shell-shaped files under target after vendored-dir exclusions.       |
| `no-requirements` | python               | No Python manifest or `*.py` files under target.                        |
| `no-playbook`     | ansible              | No Ansible-shaped files under target.                                   |
| `no-singbox-config`| netcfg              | No sing-box-shaped JSON under target (sing-box check applicable).       |
| `no-xray-config`  | netcfg               | No Xray-shaped JSON under target (xray test applicable).                |
| `no-image-artifact`| image               | No image tarball / OCI layout / SBOM under target (trivy/grype scope).  |
| `no-ai-tool-config`| ai-tools             | No AI-tool-config JSON shape under target (jq applicable; no plugin.json / .mcp.json / settings.json / opencode.json). |

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

### Tool-output (1, NEW in v1.13)

| Reason          | Lane(s)   | Meaning                                                                                                |
|-----------------|-----------|--------------------------------------------------------------------------------------------------------|
| `parse-failed`  | ai-tools  | mcp-scan ran but its output JSON could not be parsed into a recognized issue list. No findings emitted; tool reported only in skipped[]. |

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
