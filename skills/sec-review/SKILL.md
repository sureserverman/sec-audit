---
name: sec-review
description: Run a citation-grounded cybersecurity review of a web service, server, or web application. Use when the user asks for a "security review", "CVE scan", "audit dependencies", "harden this service", "check for vulnerabilities", "OWASP review", "scan for secrets", or wants a prioritized list of security fixes for a project. Scopes the target, inventories its tech stack (databases, frameworks, webservers, proxies, frontend, auth, TLS, containers, secrets, supply chain), dispatches the sec-expert subagent to produce structured findings, enriches with live CVE data from NVD 2.0 + OSV.dev + GitHub GHSA, prioritizes by CVSS / exposure / exploit-in-wild / auth-required, and writes a dated markdown report with quoted fixes from primary-source references. Degrades cleanly when CVE feeds are offline.
---

# sec-review — orchestrator skill

Drive a full, citation-grounded security review of a target project. The
skill's job is to coordinate: scope → inventory → dispatch sec-expert →
CVE-enrich → prioritize → report. The sec-expert subagent does the actual
code analysis; this skill orchestrates and enriches.

## Inputs

- `target_path` (required) — absolute path of the project to review.
  The slash command passes `$ARGUMENTS` here.
- `target_url` (optional) — HTTP(S) URL of a running instance of the
  same project, for the DAST lane (§3.7). When absent, DAST is
  skipped; static code analysis and CVE enrichment still run. Read
  from `$DAST_TARGET_URL` env var if unset.
- `only_lanes` (optional, v1.0.0+) — list of canonical lane names
  the caller wants to run exclusively. Valid values: `sec-expert`,
  `sast`, `dast`, `webext`, `rust`, `android`, `ios`, `linux`,
  `macos`, `windows`, `k8s` (added v1.1), `iac` (added v1.2),
  `gh-actions` (added v1.3), `virt` (added v1.4), `go` (added v1.5), `shell` (added v1.6), `python` (added v1.7), `ansible` (added v1.8). When set, the orchestrator dispatches
  ONLY the named lanes and records the filter in the
  Review-metadata block. Mutually exclusive with `skip_lanes`.
- `skip_lanes` (optional, v1.0.0+) — list of canonical lane names
  the caller wants to exclude. Same vocabulary as `only_lanes`.
  When set, the orchestrator dispatches every applicable lane
  EXCEPT the named ones. Mutually exclusive with `only_lanes`.
- `github_token` (optional) — used to raise the GHSA rate limit from 60/hr
  to 5000/hr. Read from `$GITHUB_TOKEN` env var if unset.
- `nvd_api_key` (optional) — raises NVD rate limit from ~5/30s to 50/30s.
  Read from `$NVD_API_KEY` env var if unset.

## Output

A markdown report written to
`<target_path>/sec-review-report-YYYYMMDD-HHMM.md`. The report is the
single user-facing deliverable — everything else (JSONL, CVE JSON blobs)
is internal working state.

---

## 1. Scope

Before touching anything, fix the scope and confirm it out loud.

- Confirm `target_path` is readable and is NOT the `sec-review` plugin
  itself. If the user points at the plugin directory, refuse and ask for
  the actual target.
- If `target_path` is a monorepo, ask whether to scope to a subdir
  (`services/api/`, `apps/web/`) or review the whole tree.
- Honor `.gitignore` — skip `node_modules/`, `.venv/`, `dist/`, `build/`,
  `target/`, vendored deps. These will be covered by dependency-pinning
  analysis, not code-pattern analysis.
- Respect project boundaries: if `target_path` contains multiple apps
  with independent stacks, dispatch one sec-expert per stack rather than
  one giant run.

State the final scope (paths included, paths excluded) in the report's
header block so the review is reproducible.

## 2. Inventory

Detect the technology stack. Read only — do not install or execute.

- **Manifests**: `package.json`, `requirements.txt`, `pyproject.toml`,
  `poetry.lock`, `Gemfile(.lock)`, `go.mod`/`go.sum`, `pom.xml`,
  `build.gradle(.kts)`, `Cargo.toml`/`Cargo.lock`, `composer.json`,
  `mix.exs`, `pubspec.yaml`.
- **Infra configs**: `Dockerfile`, `docker-compose.yml`, `kubernetes/*.yml`,
  `nginx.conf` (and `/etc/nginx/conf.d/*.conf`), `httpd.conf`, `Caddyfile`,
  `haproxy.cfg`, `traefik.yml`/`traefik.toml`, `envoy.yaml`.
- **Framework signals**: `settings.py`/`manage.py` (Django), `app.py`
  (Flask/FastAPI), `server.js`/`next.config.js` (Node), `config/routes.rb`
  (Rails), `pom.xml` with `spring-boot-starter-*` (Spring).
- **Frontend signals**: `src/**/*.{tsx,jsx,vue,svelte}`, templates
  (`templates/**/*.html`, `app/views/**/*.erb`, `resources/views/**/*.blade.php`).
- **Browser-extension signals**: `manifest.json` at project root AND the
  file contains a `"manifest_version"` key (2 or 3). Distinguish platform
  by `browser_specific_settings.gecko` (Firefox / AMO) vs absence
  (Chrome / Edge / Chromium). When detected, add `"webext"` to the
  inventory and load `references/frontend/webext-chrome-mv3.md`,
  `references/frontend/webext-firefox-amo.md`, and
  `references/frontend/webext-shared-patterns.md` as appropriate.
- **Android signals**: either `AndroidManifest.xml` anywhere in the
  tree (typically `app/src/main/AndroidManifest.xml` for gradle-based
  projects) OR a gradle build script (`build.gradle` or
  `build.gradle.kts`) that applies the `com.android.application` or
  `com.android.library` plugin. When detected, add `"android"` to the
  inventory with values reflecting module shape — `"android": ["app"]`
  for application modules, `"android": ["library"]` for library
  modules, or `"android": ["app", "library"]` for multi-module
  projects with both. Load `references/mobile/android-manifest.md`,
  `references/mobile/android-data.md`, `references/mobile/android-runtime.md`,
  and the tool-lane reference `references/mobile-tools.md`.
  `ecosystems` gains an entry
  `{"ecosystem": "Maven", "manifest": "build.gradle"}` (OSV-native,
  no enricher change). Transitive deps are covered when the project
  commits a resolved lockfile (`gradle.lockfile`); direct
  `build.gradle` parsing gives top-level deps only.
- **iOS / Apple-platform signals**: any of
  `Info.plist` (anywhere in the tree — typically at
  `<App>/Info.plist` or `<App>/Resources/Info.plist`), a `*.xcodeproj`
  directory, `Package.swift` (SwiftPM manifest), or `Podfile`
  (CocoaPods). When detected, add `"ios"` to the inventory with values
  reflecting project shape — `"ios": ["app"]` for application
  targets, `"ios": ["library"]` for SwiftPM/CocoaPod-producing
  libraries, or `"ios": ["app", "library"]` for multi-target
  projects. Load `references/mobile/ios-plist.md`,
  `references/mobile/ios-data.md`,
  `references/mobile/ios-codesign.md`, and the tool-lane reference
  `references/mobile-tools.md`. `ecosystems` gains one or both of
  `{"ecosystem": "CocoaPods", "manifest": "Podfile.lock"}` and
  `{"ecosystem": "SwiftPM", "manifest": "Package.resolved"}`. Note
  both ecosystems have partial OSV coverage (CocoaPods: via GHSA
  fallback; SwiftPM: best-effort) — document as a known limit rather
  than a blocker; cve-enricher's multi-feed routing handles the gap.
- **macOS desktop signals**: distinguished from iOS by macOS-specific
  markers — `Info.plist` containing `LSMinimumSystemVersion` (macOS
  deployment target key; iOS uses `MinimumOSVersion` or
  `UIDeviceFamily`), OR a `*.pkg` installer / `*.dmg` disk image
  file under the target, OR a `Sparkle.framework/` directory or
  `SUFeedURL` key in Info.plist (Sparkle auto-update framework), OR
  a `.app` bundle whose Info.plist has the macOS deployment-target
  key. When detected, add `"macos"` with values reflecting the
  artifact shape — `"macos": ["app"]` / `["pkg"]` / `["framework"]`
  / `["app", "pkg"]`. Cross-platform SwiftPM packages (targeting
  both iOS and macOS) MAY emit BOTH `ios` and `macos` keys
  simultaneously — the two lanes dispatch independently and render
  in separate report sections. Load
  `references/desktop/macos-hardened-runtime.md`,
  `references/desktop/macos-tcc.md`,
  `references/desktop/macos-packaging.md`, and the shared
  `references/mobile-tools.md` (iOS/macOS subsections).
- **Kubernetes signals**: any `*.yaml`/`*.yml` file containing both
  top-level `apiVersion:` AND `kind:` keys where `kind:` matches a
  known K8s resource (Pod, Deployment, StatefulSet, DaemonSet, Job,
  CronJob, Service, Ingress, ConfigMap, Secret, ServiceAccount,
  Role, RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy,
  ValidatingWebhookConfiguration, MutatingWebhookConfiguration,
  CustomResourceDefinition). Scan common paths: `k8s/`, `deploy/`,
  `manifests/`, `kustomize/`, `helm/templates/`, repo root. Emit
  `"k8s"` with values indicating resource mix — `["workloads"]` if
  Pods/Deployments present, `["rbac"]` if Role/ClusterRole present,
  `["network"]` if NetworkPolicy/Ingress present, or combinations.
  Load `references/infra/k8s-workloads.md`, `infra/k8s-api.md`,
  `references/k8s-tools.md`. No ecosystem entry (K8s manifests are
  image-references, not package-manifest dependencies — image CVE
  enrichment is a separate future concern).
- **Windows-desktop signals**: any of the following triggers the
  `windows` inventory key:
  - .NET project files (`*.csproj`, `*.vbproj`), C++ project files
    (`*.vcxproj`), Visual Studio solutions (`*.sln`), or NuGet
    package specs (`*.nuspec`).
  - WiX installer sources (`*.wxs`, `*.wxi`).
  - MSIX / Appx manifests (`AppxManifest.xml`,
    `Package.appxmanifest`).
  - Compiled PE artifacts under target — `*.exe`, `*.dll`, `*.msi`,
    `*.msix`, `*.sys`.
  - AppLocker / WDAC policy XML files — path or filename matching
    `AppLocker*.xml` or `WDAC*.xml`, or XML content containing
    `<AppLockerPolicy>` / `<SiPolicy>` root elements.
  When detected, add `"windows"` with values reflecting the
  artifact/source shape — `"windows": ["exe"]` / `["msi"]` /
  `["msix"]` / `["applocker"]` / `["wdac"]` / `["source"]` or
  combinations. Load
  `references/desktop/windows-authenticode.md`,
  `references/desktop/windows-applocker.md`,
  `references/desktop/windows-packaging.md`, and the tool-lane
  reference `references/windows-tools.md`. `ecosystems` gains a
  `{"ecosystem": "NuGet", "manifest": "packages.lock.json"}` entry
  when `.csproj` with `<PackageReference>` is present; NuGet is
  OSV-native so cve-enricher handles it without adapter change.
- **Linux-desktop signals**: any of the following triggers the
  `linux` inventory key:
  - Systemd units anywhere in the tree — `*.service`, `*.socket`,
    `*.timer` under `systemd/`, `debian/`, `etc/systemd/system/`, or
    `usr/lib/systemd/system/`.
  - Debian packaging — `debian/control` + `debian/rules`.
  - RPM packaging — `*.spec` at project root or under a `rpm/` or
    `packaging/rpm/` subdir.
  - Flatpak manifest — `*.flatpak` manifest file OR `*.y(a)ml` /
    `*.json` file under a `flatpak/` subdir whose contents declare
    an `id:` + `sdk:` pair (flatpak-builder manifest shape).
  - Snap manifest — `snapcraft.yaml` at project root or under
    `snap/`.
  When detected, add `"linux"` with values indicating the mechanism(s):
  `"linux": ["systemd"]`, `["deb"]`, `["rpm"]`, `["flatpak"]`,
  `["snap"]`, or combinations (`["systemd", "deb"]` is common).
  Load `references/desktop/linux-systemd.md`,
  `references/desktop/linux-sandboxing.md`,
  `references/desktop/linux-packaging.md`, and the tool-lane
  reference `references/linux-tools.md`. `ecosystems` gains a
  `{"ecosystem": "Debian", "manifest": "debian/control"}` entry when
  Debian packaging is detected (OSV partial via the Debian Security
  Tracker — best-effort coverage; document as a known limit).
- **Ansible signals**: any of the following triggers the
  `ansible` inventory key:
  - A `*.yml` / `*.yaml` file with top-level `hosts:` AND
    `tasks:` keys (the canonical playbook shape).
  - A `roles/` directory containing role subdirectories with
    the canonical `tasks/`, `handlers/`, `defaults/`, `vars/`,
    or `meta/main.yml` shape.
  - An `ansible.cfg` file at project root.
  - A `collections/` directory with subdirectories matching
    `<namespace>/<collection>/`.
  - An `inventory` file or `inventory/` directory (INI or YAML).
  - A `requirements.yml` with role / collection entries
    (presence of `roles:` or `collections:` keys at top level).
  When detected, add `"ansible"` with values reflecting the
  shape: `"ansible": ["playbook"]`, `["role"]`,
  `["collection"]`, `["inventory"]`, or combinations
  (`["playbook", "role"]` is common). Load
  `references/ansible/playbook-security.md`,
  `references/ansible/role-secrets-and-vault.md`, and the
  tool-lane reference `references/ansible-tools.md`. No
  ecosystem entry — Ansible role / collection dependencies
  are NOT in OSV's coverage; supply-chain risk for Galaxy
  collections is a future concern (separate runner that
  verifies SHA256 fingerprints against the Galaxy registry).
- **Python signals**: any of the following triggers the
  `python` inventory key:
  - A Python manifest at any project root: `requirements.txt`,
    `requirements-*.txt`, `pyproject.toml` with a `[tool.poetry]`
    or `[project]` or `[build-system]` table, `setup.py`,
    `Pipfile`, or `poetry.lock` / `Pipfile.lock`.
  - A package shape: any `*.py` file at a non-trivial depth
    (more than just a top-level helper script — accompanied by
    at least one `__init__.py`, `pyproject.toml`, or `setup.py`).
  When detected, add `"python"` with values reflecting the
  manifest shape: `"python": ["package"]` for a package /
  application (Django/Flask/FastAPI service typically),
  `"python": ["library"]` for a `pyproject.toml` with a
  package definition exporting a wheel,
  `"python": ["scripts"]` for a tree of standalone scripts
  with a `requirements.txt`. Load
  `references/python/deserialization.md`,
  `references/python/subprocess-and-async.md`,
  `references/python/framework-deepening.md`, and the
  tool-lane reference `references/python-tools.md` — load
  only the per-topic packs matching detected signals (e.g.
  load `framework-deepening.md` only when a Django / Flask /
  FastAPI signal also fires). The existing PyPI ecosystem
  entry (`{"ecosystem": "PyPI", "manifest": "requirements.txt"}`)
  remains the cve-enricher feed; the python lane's pip-audit
  invocation augments cve-enricher with reachability-hint
  metadata that the bulk OSV pass lacks.
- **Shell signals**: at least one shell-shaped file under
  target — `*.sh`, `*.bash`, `*.zsh`, or `*.ksh` — OR a file
  whose first line is a shell shebang (`#!/bin/sh`,
  `#!/bin/bash`, `#!/usr/bin/env bash`, `#!/usr/bin/env sh`,
  `#!/bin/dash`, `#!/bin/ksh`, `#!/bin/zsh`). Apply the
  standard §1 Scope `.gitignore` exclusions plus the
  vendored-directory list (`node_modules/`, `.venv/`,
  `vendor/`, `dist/`, `build/`, `target/`) — vendored
  scripts are out of scope for this lane. When detected,
  add `"shell"` to the inventory with the value `["scripts"]`
  (the lane has no further sub-shape distinction). Load
  `references/shell/command-injection.md`,
  `references/shell/file-handling.md`,
  `references/shell/script-hardening.md`, and the tool-lane
  reference `references/shell-tools.md`. No ecosystem entry
  — shell scripts have no package-manifest dependency
  graph; supply-chain risk for shell ecosystems (sourced
  remote scripts) is enforced at the code-pattern layer
  (the `curl | sh` antipattern in
  `shell/file-handling.md`).
- **Go signals**: `go.mod` at project root (or any subdir for
  multi-module monorepos) AND at least one `*.go` file under the
  same module root. Distinguish by project shape:
  - `package main` declaration in any `*.go` file under the
    module root → `"go": ["binary"]` (a Go program).
  - No `package main` declared, but the module exports types /
    functions that other modules import → `"go": ["library"]`.
  - `go.work` workspace file at root → `"go": ["workspace"]`,
    plus one nested entry per workspace member detected under
    `use (...)` directives.
  When detected, add `"go"` to the inventory and load
  `references/go/stdlib-security.md`,
  `references/go/module-ecosystem.md`,
  `references/go/web-frameworks.md`, and the tool-lane
  reference `references/go-tools.md`. `ecosystems` gains an
  entry `{"ecosystem": "Go", "manifest": "go.sum"}` (preferred)
  or `{"ecosystem": "Go", "manifest": "go.mod"}` when go.sum is
  absent — OSV's `querybatch` handles `Go` natively so
  cve-enricher needs no adapter change. `go.sum` presence is
  expected on any module that has been built; its absence is
  not a detection trigger, only a signal to the runner that
  cve-enricher will have less precision (only direct
  dependencies covered, not transitive).
- **Rust / Cargo signals**: `Cargo.toml` at project root (or any subdir
  for workspaces) AND the file contains `[package]` or `[workspace]`.
  Distinguish by project shape:
  - `[package]` only → `"rust": ["binary"]` or `"rust": ["library"]`
    (derive from `[lib]` / `[[bin]]` sections, or from `src/main.rs`
    vs `src/lib.rs`).
  - `[workspace]` → `"rust": ["workspace"]`, plus one nested entry per
    workspace member detected under `members = [...]`.
  When detected, add `"rust"` to the inventory and load
  `references/rust/cargo-ecosystem.md`, `references/rust/unsafe-surface.md`,
  and the tool-lane reference `references/rust-tools.md`. Cargo.lock
  presence is expected for binaries (commit the lockfile) and optional
  for libraries; its absence is not a detection trigger, only a signal
  to the runner that cargo-audit will have less to chew on.
- **GitHub Actions signals**: any `.github/workflows/*.yml` or
  `.github/workflows/*.yaml` file under target whose contents
  declare both top-level `on:` and `jobs:` keys (the canonical
  Actions workflow shape). When detected, add `"gh-actions"` with
  values reflecting the trigger surface — `"gh-actions": ["push"]`,
  `["pull_request"]`, `["pull_request_target"]`, `["workflow_call"]`,
  `["workflow_run"]`, `["schedule"]`, `["release"]`, or
  combinations. Load `references/infra/gh-actions-permissions.md`,
  `references/infra/gh-actions-secrets.md`, and the tool-lane
  reference `references/gh-actions-tools.md`. No ecosystem entry
  — workflow files reference action versions, not package-manifest
  dependencies; action SHA-pinning is enforced at the
  code-pattern layer, not via CVE feeds.
- **Virtualization / alternative-runtime signals**: any of the
  following triggers the `virt` inventory key:
  - **Docker runtime config** — `docker-compose.y(a)ml`,
    `compose.y(a)ml`, `*.compose.y(a)ml`, `*.stack.y(a)ml` files
    under target, OR a `daemon.json` file (typically under
    `etc/docker/` in source trees that vendor the daemon config),
    OR a Dockerfile / Containerfile / `*.dockerfile` /
    `*.containerfile` (drives hadolint dispatch — distinct from
    `containers/dockerfile-hardening.md`'s code-pattern reasoning
    surface).
  - **Podman / Quadlet** — `*.container`, `*.volume`,
    `*.network`, `*.pod`, `*.kube`, `*.image`, or `*.build` files
    under `containers/systemd/` or any subdir, OR a
    `policy.json` / `containers-policy.json` file, OR a
    `podman-compose.y(a)ml` file.
  - **libvirt / QEMU / KVM** — any `*.xml` file under target whose
    root element is `<domain ...>`, `<network ...>`, `<pool ...>`,
    or `<volume ...>` (the libvirt domain/network/storage XML
    schemas). Also triggers on `qemu.conf` files.
  - **Apple Containers** — `container.yaml` files at project root
    or under `containers/`, OR install scripts referencing the
    `apple/container` CLI.
  - **UTM (macOS)** — `*.utm` directories under target containing
    a `config.plist` (the canonical UTM bundle shape).
  When detected, add `"virt"` with values reflecting the
  technology mix: `"virt": ["docker"]`, `["podman"]`, `["libvirt"]`,
  `["apple-containers"]`, `["utm"]`, or combinations
  (`["docker", "libvirt"]` is common on Linux build hosts;
  `["apple-containers", "utm"]` on Apple-silicon dev machines).
  Load `references/virt/docker-runtime.md`,
  `references/virt/podman.md`,
  `references/virt/libvirt-qemu.md`,
  `references/virt/apple-containers.md`,
  `references/virt/utm.md`, and the tool-lane reference
  `references/virt-tools.md` — load only the per-technology packs
  matching detected values to keep the sec-expert context tight.
  No ecosystem entry — virt configurations reference image tags
  and host devices, not package-manifest dependencies. Image-tag
  pinning compliance is enforced at the code-pattern layer
  (sec-expert reasoning + hadolint's `DL3007` rule). Cross-link to
  the existing `containers/dockerfile-hardening.md` and
  `containers/docker.md` for Dockerfile-authoring patterns; the
  `virt` lane covers the runtime-and-VMM surface those packs do
  NOT.
- **IaC signals**: any of the following triggers the `iac`
  inventory key:
  - Terraform sources — `*.tf`, `*.tfvars`, `*.hcl` anywhere in the
    tree (typically under `terraform/`, `infrastructure/`,
    `infra/`, or repo root).
  - Pulumi project — `Pulumi.yaml` at project root or under a
    `pulumi/` subdir, or a `Pulumi.<stack>.yaml` stack-config file.
  - Terragrunt — `terragrunt.hcl` files.
  When detected, add `"iac"` with values reflecting the framework(s):
  `"iac": ["terraform"]`, `"iac": ["pulumi"]`, `"iac": ["terragrunt"]`,
  or combinations (`["terraform", "pulumi"]` is common in
  multi-cloud monorepos). Load
  `references/infra/iac-cloud-resources.md`,
  `references/infra/iac-secrets-state.md`, and the tool-lane
  reference `references/iac-tools.md`. No ecosystem entry — IaC
  declarations reference cloud resources and provider versions, not
  package-manifest dependencies; provider-version CVE enrichment is
  a separate future concern.
- **Auth / secrets signals**: occurrences of `jwt`, `oauth`, `passport`,
  `django-allauth`, `NextAuth`, `SECRET_KEY`, `.env*` files.

Emit an `inventory.json` record (in-memory only) like:

```json
{
  "frameworks":  ["django"],
  "databases":   ["postgres"],
  "webservers":  ["nginx"],
  "proxies":     [],
  "frontend":    ["django-templates"],
  "webext":      [],
  "android":     [],
  "ios":         [],
  "macos":       [],
  "windows":     [],
  "linux":       [],
  "k8s":         [],
  "iac":         [],
  "gh-actions":  [],
  "virt":        [],
  "go":          [],
  "shell":       [],
  "python":      [],
  "ansible":     [],
  "rust":        [],
  "auth":        ["django-sessions"],
  "containers":  ["docker"],
  "ecosystems":  [{"ecosystem": "PyPI", "manifest": "requirements.txt"}]
}
```

For a Rust target the `rust` key carries the detected project shape,
e.g. `"rust": ["binary"]`, `"rust": ["library"]`, or
`"rust": ["workspace", "binary", "library"]` for a workspace with
mixed members. `ecosystems` gains an entry
`{"ecosystem": "crates.io", "manifest": "Cargo.lock"}` (preferred) or
`{"ecosystem": "crates.io", "manifest": "Cargo.toml"}` when the lock
is absent — OSV's `querybatch` handles `crates.io` natively so
cve-enricher needs no adapter change.

For a browser-extension target the `webext` key carries the detected
platform(s), e.g. `"webext": ["chrome-mv3"]`, `"webext": ["firefox-amo"]`,
or `"webext": ["chrome-mv3", "firefox-amo"]` for a cross-browser
extension (one whose manifest has both a top-level MV3 shape and a
`browser_specific_settings.gecko.id`).

## 3. Code analysis — dispatch sec-expert subagent(s)

For each detected stack (usually one, multiple for monorepos), dispatch the
`sec-expert` agent defined at `agents/sec-expert.md`. For monorepos with
more than one independent stack, follow the `dispatching-parallel-agents`
skill: dispatch them concurrently as long as they don't share source files.

`sec-expert` is pinned to `model: sonnet` in its frontmatter — caller-model
choice (e.g. an Opus-session invocation of `/sec-review`) does NOT inflate
the agent's cost. The same pinning applies to `finding-triager` and
`report-writer` (both sonnet); `cve-enricher` is pinned to `haiku` because
its work is high-volume JSON extraction over HTTP.

Each `sec-expert` call receives:

- The stack-scoped `target_path` (subdir for monorepos, whole tree otherwise).
- The detected technologies (so the agent loads only relevant reference
  files — don't read `frameworks/rails.md` for a Django project).
- The plugin-root path so it can read `skills/sec-review/references/*.md`.

The agent returns JSONL findings per the schema documented in
`agents/sec-expert.md`. Collect all findings (including the final
`__dep_inventory__` object) into a list called `findings`. The dep
inventory feeds step 4.

### 3.0 Dispatch discipline (multi-stack default)

Multi-stack dispatch is the default behaviour. When §2 Inventory
detects ≥2 lane keys simultaneously (e.g. a Tauri app with `rust`
+ `webext` + `macos`/`windows`/`linux`; a Flutter app with
`android` + `ios`; a React-Native app with `android` + `ios` +
`webext`), ALL corresponding runners dispatch in parallel per the
`dispatching-parallel-agents` skill. This has been the de-facto
behaviour since v0.7; v1.0 makes it the documented contract.

**Invariants the orchestrator enforces:**

1. **Independent dispatch.** Each lane's runner reads only files it
   needs. Runners share no mutable state. Origin-tag isolation is
   enforced by `tests/contract-check.sh` — no `origin: "webext"`
   finding may carry a `rust` tool name, etc.
2. **Independent status records.** Each runner emits its own
   `__<lane>_status__` sentinel with its own `skipped` / `failed`
   lists. The report-writer renders each lane's findings in a
   separate section, headed by the per-lane summary row from
   §7 Report consolidation.
3. **Dep-inventory dedup.** When multiple lanes share an ecosystem
   (iOS + macOS both resolve CocoaPods; android depends on Maven
   which windows doesn't touch), the ecosystems list in the
   cve-enricher input deduplicates by `(ecosystem, manifest)`
   pair — no ecosystem is scanned twice.
4. **Lane filters (v1.0).** If the caller passed `only_lanes` or
   `skip_lanes` (see `## Inputs`), the orchestrator filters the
   dispatch list BEFORE step 3. Filtered-out lanes do not dispatch,
   do not emit status records, and are noted in the Review-metadata
   section as "Lane filter applied: ...". The two flags are mutually
   exclusive — the slash command rejects invocations setting both.
5. **Parallel-safe file access.** Runners are read-only against
   the target tree; the one exception is gradle's
   `./gradlew lintDebug` writing to `build/reports/` under target
   (documented in `agents/android-runner.md`). No two runners write
   to the same `$TMPDIR` subpath.
6. **Consolidated report.** §6 Report writing renders a per-lane
   summary table at the top of the Review-metadata block with one
   row per dispatched lane. See `agents/report-writer.md` Step 2.5.

The canonical lane list (18 total) is enumerated in
`references/COVERAGE.md` — the single source of truth for which
inventory keys map to which runners, reference packs, tools, and
skip reasons.

### 3.5 Triage findings — dispatch finding-triager

Before CVE enrichment, run the raw findings through the `finding-triager`
agent (`agents/finding-triager.md`, pinned to sonnet). It reads the
surrounding code/config context at each `file:line`, applies the
`## Common false positives` guidance from the matched reference pack, and
annotates each finding with:

- `confidence` — `high` / `medium` / `low`
- `fp_suspected` — boolean
- `triage_notes` — one short sentence of justification

The triager **only annotates** — it never drops findings and never
alters the `fix_recipe` string. The rubric in section 5 is the only
thing that downgrades a finding into the LOW bucket, driven by the
`confidence` field the triager sets here. The `__dep_inventory__` line
passes through unchanged.

Input to finding-triager: the raw JSONL stream from sec-expert plus the
plugin root path. Output: the same JSONL stream with the three extra
fields appended to each finding line.

### 3.6 SAST pass — dispatch sast-runner

After triage, run a separate SAST pass on the same `target_path` by
dispatching the `sast-runner` agent (`agents/sast-runner.md`, pinned
to haiku, tools: Read + Bash). The agent shells out to `semgrep` and
`bandit` using the canonical invocations in `references/sast-tools.md`,
parses their native JSON, and emits sec-expert-compatible JSONL on
stdout — every line carrying `origin: "sast"` and `tool: "semgrep"` or
`tool: "bandit"`.

The SAST stream runs in parallel with the sec-expert stream and is
independent of it: SAST findings are additive signal, not replacements.
Collect the SAST JSONL into a `sast_findings` list alongside the
triaged regex findings.

Skill-level invariants the orchestrator enforces on the SAST stream
(the agent reports these states; the skill decides what to do with
them):

- **`__sast_status__: "unavailable"`** — neither `semgrep` nor `bandit`
  was on PATH (or both failed). Add the `⚠ SAST tools unavailable —
  install semgrep and/or bandit to enable static-analysis pass` banner
  to the Review metadata block. Do NOT fabricate findings. Do NOT treat
  the absence as a clean scan.
- **`__sast_status__: "ok"`** — at least one tool ran successfully.
  Merge the SAST findings into the triaged stream. The triager's
  origin-aware rules (see `agents/finding-triager.md`) govern FP
  annotation for any SAST-origin findings that flow back through
  triage on a subsequent pass; by default the SAST findings carry the
  `confidence` the tool or the mapping table sets and are not
  downgraded.
- **Partial availability** — if `tools` in the status line omits a
  binary that was expected, note it in the Review metadata section
  (`SAST tools run: semgrep; bandit skipped — not on PATH`) so the
  absence is visible rather than silent.

The dep-inventory and CVE-enrichment paths are NOT affected by this
pass — SAST findings are code-pattern signal, not package-version
signal.

### 3.7 DAST pass — dispatch dast-runner

When the caller supplies a `target_url` input (an HTTP or HTTPS URL
of a running instance of the target), dispatch the `dast-runner`
agent (`agents/dast-runner.md`, pinned to haiku, tools: Read + Bash).
The agent shells out to OWASP ZAP baseline via docker
(`zaproxy/zap-stable`) or the local `zap-baseline.py`, parses ZAP's
native JSON output, and emits sec-expert-compatible JSONL on stdout —
every line carrying `origin: "dast"` and `tool: "zap-baseline"`.

DAST runs in parallel with sec-expert, sast-runner, and cve-enricher
— its input is a URL, not a file path or a dep inventory, so it
shares nothing with the other agents. Collect the DAST JSONL into a
`dast_findings` list alongside the other streams.

Skill-level invariants the orchestrator enforces on the DAST stream:

- **No `target_url` supplied** — skip DAST entirely. Do NOT fabricate
  a URL from the repo contents. Add a Review-metadata line
  `DAST: skipped — no target_url supplied` so the absence is visible.
- **`__dast_status__: "unavailable"`** — neither `docker` nor
  `zap-baseline.py` was on PATH, the URL was non-HTTP, or the ZAP
  run failed. Add the `⚠ DAST tools unavailable — install docker or
  zap-baseline to enable dynamic-analysis pass` banner to the Review
  metadata block. Do NOT fabricate findings.
- **`__dast_status__: "ok"`** — ZAP ran successfully. Merge the DAST
  findings into the triaged stream. DAST findings carry `file:
  <site hostname or URI>` and `line: 0` because DAST has no source
  line; the report-writer renders `Target: <method> <uri>` from the
  `notes` field instead of the conventional `file:line` locus.
- **DAST baseline is passive only.** The ZAP baseline profile never
  performs active exploitation. Any finding with CRITICAL severity
  must come from a different agent — DAST's maximum is HIGH
  (`riskcode: "3"`).

DAST findings are additive signal. They do NOT feed the dep-inventory
or CVE-enrichment paths; a live scan surfaces runtime issues that
static analysis cannot (reflected XSS, missing security headers on
rendered pages, mixed-content, server banners).

### 3.8 Browser-extension pass — dispatch webext-runner

When the inventory emitted by §2 contains `webext` (the `manifest.json`
+ `manifest_version` detection rule fired), dispatch the `webext-runner`
agent (`agents/webext-runner.md`, pinned to haiku, tools: Read + Bash).
The agent shells out to three Node-based CLIs — `addons-linter`,
`web-ext lint`, and `retire.js` — against the extension source
directory, parses each tool's native JSON output, and emits
sec-expert-compatible JSONL on stdout — every line carrying
`origin: "webext"` and `tool: "addons-linter" | "web-ext" | "retire"`.

webext-runner runs in parallel with sec-expert, sast-runner,
dast-runner, and cve-enricher — its input is the extension source
tree, which other agents may also read but do not mutate, so they
share nothing observable. Collect the webext JSONL into a
`webext_findings` list alongside the other streams.

Skill-level invariants the orchestrator enforces on the webext stream:

- **No `webext` in inventory** — skip this pass entirely. Do NOT probe
  for browser-extension tools on an unrelated project; the tools are
  node-based and noisy on server/backend trees.
- **`__webext_status__: "unavailable"`** — none of `addons-linter`,
  `web-ext`, or `retire` was on PATH, the target directory had no
  `manifest.json`, or every tool crashed. Add the `⚠ Browser-extension
  tools unavailable — install addons-linter, web-ext, or retire to
  enable WebExtension analysis pass` banner to the Review metadata
  block. Do NOT fabricate findings.
- **`__webext_status__: "partial"`** — some tools ran successfully
  and others were missing or crashed. Merge the findings from the
  tools that ran; note the missing/failed tools in the Review-metadata
  section (`WebExt tools run: addons-linter, retire; web-ext skipped —
  not on PATH`).
- **`__webext_status__: "ok"`** — every available tool ran. Merge the
  webext findings into the triaged stream. Webext findings carry
  `file: <relative path>` (e.g. `manifest.json`, `background/sw.js`)
  and `line: <integer>` when the tool supplied one; retire findings
  carry `line: 0` because the upstream advisory has no line.
- **Retire findings with a CVE** — when a retire finding's `id` is a
  `CVE-YYYY-NNNN` string, the cve-enricher MUST pick it up and attach
  CVSS / KEV / fix-version metadata just as it does for manifest-
  derived CVEs. The dep-inventory path in §4 is extended to include
  retire's `{component, version}` pairs.

Webext findings combine code-pattern signal (addons-linter rules) with
package-version signal (retire.js). The dep-inventory path IS affected:
retire's `{component, version}` pairs feed the cve-enricher as an
additional ecosystem entry with `ecosystem: "retire"` so OSV/NVD/GHSA
lookups run against them.

### 3.9 Rust toolchain pass — dispatch rust-runner

When the inventory emitted by §2 contains `rust` (the `Cargo.toml`
+ `[package]`/`[workspace]` detection rule fired), dispatch the
`rust-runner` agent (`agents/rust-runner.md`, pinned to haiku, tools:
Read + Bash). The agent shells out to four cargo subcommands —
`cargo audit`, `cargo deny`, `cargo geiger`, `cargo vet` — against
the Rust project root, parses each tool's native JSON output, and
emits sec-expert-compatible JSONL on stdout — every line carrying
`origin: "rust"` and `tool: "cargo-audit" | "cargo-deny" |
"cargo-geiger" | "cargo-vet"`.

rust-runner runs in parallel with sec-expert, sast-runner, dast-runner,
webext-runner, and cve-enricher — its input is the project tree (read
only, no mutation), so other agents may read the same files without
observable conflict. Collect the Rust JSONL into a `rust_findings` list
alongside the other streams.

Skill-level invariants the orchestrator enforces on the Rust stream:

- **No `rust` in inventory** — skip this pass entirely. Do NOT probe
  for cargo on an unrelated project; it is heavyweight to install and
  irrelevant to non-Rust targets.
- **`__rust_status__: "unavailable"`** — `cargo` was absent entirely,
  or none of the four subcommands responded to `--version`, or every
  subcommand crashed. Add the `⚠ Rust toolchain tools unavailable —
  install cargo + cargo-audit/deny/geiger/vet to enable Rust analysis
  pass` banner to the Review metadata block. Do NOT fabricate findings.
- **`__rust_status__: "partial"`** — some subcommands ran successfully
  and others were missing or crashed. Merge the findings from the ones
  that ran; note the missing/failed ones in the Review-metadata
  section (`Rust tools run: cargo-audit, cargo-geiger; cargo-deny
  skipped — not installed; cargo-vet failed — exit 2`).
- **`__rust_status__: "ok"`** — every available subcommand ran. Merge
  the Rust findings into the triaged stream. Rust findings carry
  `file: <Cargo.toml | Cargo.lock | crate-name>` and `line: <integer
  or 0>` depending on whether the tool reported a span.
- **cargo-audit findings with a CVE alias** — when the finding's `id`
  is a `CVE-YYYY-NNNN` string, the cve-enricher MUST pick it up and
  attach CVSS / KEV / fix-version metadata. cargo-audit populates
  `advisory.aliases[]` from the RustSec DB's CVE cross-reference.
- **cargo-geiger INFO ceiling** — geiger findings are INFO-severity
  signals, not defects. The report-writer renders them in a separate
  "Unsafe-code surface (informational)" bucket below the LOW severity
  bucket; they are NOT counted in the header severity tallies.

Rust findings combine code-pattern signal (deny bans, geiger unsafe
counts, vet unaudited entries) with package-version signal (audit
CVEs). The dep-inventory path IS affected: cargo-audit's package
list feeds the cve-enricher as an ecosystem entry
`{"ecosystem": "crates.io", "manifest": "Cargo.lock"}` — OSV's
`querybatch` endpoint handles crates.io natively, so no new feed
adapter is required. A Rust project with a Cargo.lock and cargo-audit
on PATH will have its advisories double-covered (RustSec DB via
audit + OSV via cve-enricher); that redundancy is expected and the
CVE dedupe logic in §4 handles it.

### 3.10 Android pass — dispatch android-runner

When the inventory emitted by §2 contains `android` (the
`AndroidManifest.xml` OR `com.android.application`/`com.android.library`
gradle-plugin detection rule fired), dispatch the `android-runner`
agent (`agents/android-runner.md`, pinned to haiku, tools: Read +
Bash). The agent shells out to three Android static-analysis tools —
`mobsfscan`, `apkleaks`, and `android-lint` (via the gradle wrapper
when available, else the standalone `lint` binary) — against the
project root, parses each tool's native output, and emits sec-expert-
compatible JSONL on stdout — every line carrying `origin: "android"`
and `tool: "mobsfscan" | "apkleaks" | "android-lint"`.

android-runner runs in parallel with sec-expert, sast-runner,
dast-runner, webext-runner, rust-runner, and cve-enricher. Collect
the Android JSONL into an `android_findings` list alongside the
other streams.

Skill-level invariants the orchestrator enforces on the Android stream:

- **No `android` in inventory** — skip this pass entirely. Do NOT
  probe for mobsfscan/apkleaks/android-lint on unrelated projects;
  the tools are heavy and irrelevant to non-Android targets.
- **`__android_status__: "unavailable"`** — none of the three tools
  responded, or the target_path had no Android signals, or every tool
  crashed. Add the `⚠ Android tools unavailable — install mobsfscan,
  apkleaks, and/or android-lint to enable the Android static-analysis
  pass` banner to the Review metadata block.
- **`__android_status__: "partial"`** — some tools ran successfully
  and others failed or were missing. Merge the findings; note
  missing/failed tools in the Review-metadata section (`Android tools
  run: mobsfscan, android-lint; apkleaks failed — exit 2`).
- **`__android_status__: "ok"`** — every available tool ran. Merge
  the Android findings into the triaged stream.
- **Clean-skip vs failure distinction (NEW in v0.8)** — the
  `android-runner` status line carries a `skipped` list, separate
  from `failed`. The canonical case is apkleaks-with-no-APK-found:
  apkleaks is on PATH, legitimately cannot run (no binary artifact
  exists in a source-only checkout), and this is recorded as
  `{"tool": "apkleaks", "reason": "no-apk"}` in the `skipped` list,
  NOT as a failure. The report-writer surfaces cleanly-skipped tools
  in a separate metadata line (`Android tools skipped: apkleaks
  (no-apk)`) so the reader distinguishes "couldn't run due to target
  shape" from "ran and crashed." This pattern may be reused by future
  lanes where tool applicability depends on target artifacts.

Android findings combine code-pattern signal (mobsfscan rules,
android-lint Security-category rules) with secret-scanner signal
(apkleaks when an APK is present). The dep-inventory path IS affected:
gradle-declared dependencies feed cve-enricher as an ecosystem entry
`{"ecosystem": "Maven", "manifest": "build.gradle"}` — OSV's
`querybatch` handles Maven natively, so no new feed adapter is
required. When a `gradle.lockfile` is present, transitive
dependencies are also enriched; without it, only direct declarations.

### 3.11 iOS pass — dispatch ios-runner

When the inventory emitted by §2 contains `ios` (any of the four iOS
signals: `Info.plist` / `*.xcodeproj` / `Package.swift` / `Podfile`),
dispatch the `ios-runner` agent (`agents/ios-runner.md`, pinned to
haiku, tools: Read + Bash). The agent shells out to up to four tools:
`mobsfscan` (cross-platform, same binary as §3.10's Android lane) +
Apple's `codesign`, `spctl`, and `xcrun notarytool` when the runner is
on a macOS host AND a `.app`/`.framework`/`.xcarchive` bundle is
present under the target.

ios-runner runs in parallel with every other pass agent. Collect the
iOS JSONL into an `ios_findings` list alongside the other streams.

Skill-level invariants:

- **No `ios` in inventory** — skip entirely. Do NOT probe for mobsfscan
  or any Apple binary on unrelated targets.
- **`__ios_status__: "unavailable"`** — no tool could run (all tools
  missing, OR no tool was applicable to the host+target combination,
  OR every available tool crashed).
- **`__ios_status__: "partial"`** — some tools ran successfully and
  others failed; `failed` + `skipped` lists document the partial state.
- **`__ios_status__: "ok"`** — every available tool ran; `skipped`
  list may still be present when tools were cleanly inapplicable.
- **Host-OS clean-skip (NEW in v0.9)** — when the runner is executed
  on Linux or Windows (common CI case), codesign / spctl / notarytool
  cannot run. The runner records them in `skipped` with
  `reason: "requires-macos-host"`. This is NOT a failure — it is a
  host-environment limitation, surfaced so the report reader knows the
  review was partial by design. This skip reason extends the v0.8
  apkleaks-no-apk primitive with a new subcategory: tool applicability
  depending on the RUNNER'S host rather than the TARGET'S artifacts.
- **Three skip reasons total (iOS lane)** — `requires-macos-host`,
  `no-bundle` (codesign/spctl require a `.app`/`.framework`/
  `.xcarchive` that a source-only target lacks), `no-notary-profile`
  (notarytool requires `$NOTARY_PROFILE`). All three preserve the
  structured `{tool, reason}` schema introduced in v0.8 — no contract-
  check schema change.

iOS findings combine code-pattern signal (mobsfscan on Swift/Obj-C) +
binary-signing signal (codesign entitlement audit + hardened-runtime
check) + Gatekeeper signal (spctl assessment) + notarization-history
signal (notarytool). The dep-inventory path IS affected: CocoaPods
and SwiftPM dependencies feed cve-enricher as
`{"ecosystem": "CocoaPods", "manifest": "Podfile.lock"}` and
`{"ecosystem": "SwiftPM", "manifest": "Package.resolved"}`. Both
ecosystems have best-effort OSV coverage (CocoaPods via GHSA
fallback; SwiftPM partial) — the orchestrator tolerates misses
rather than failing the pipeline.

### 3.12 Desktop Linux pass — dispatch linux-runner

When the inventory emitted by §2 contains `linux` (any of the five
signals: systemd units, `debian/control`, `*.spec`, Flatpak manifest,
or `snapcraft.yaml`), dispatch the `linux-runner` agent
(`agents/linux-runner.md`, pinned to haiku, tools: Read + Bash). The
agent shells out to up to three tools: `systemd-analyze security`
(when the runner is on a systemd host AND a `.service` unit exists
under the target), `lintian` (when `debian/control` exists under the
target), and `checksec` (when an ELF binary exists under the target).

linux-runner runs in parallel with every other pass agent. Collect
the Linux JSONL into a `linux_findings` list.

Skill-level invariants:

- **No `linux` in inventory** — skip entirely.
- **`__linux_status__: "unavailable"`** — no tool could run (all
  missing / no applicable targets / every run crashed).
- **`__linux_status__: "partial"`** — some tools ran, some failed;
  `failed` + `skipped` lists document.
- **`__linux_status__: "ok"`** — every available tool ran; `skipped`
  may still be populated for cleanly-inapplicable tools.
- **Six clean-skip reasons across the Linux lane (NEW in v0.10):**
  - `requires-systemd-host` — the runner is not on a systemd host
    (macOS/Windows/Alpine-without-systemd). Parallel to the v0.9
    `requires-macos-host` — this is the second host-OS-gated
    skip reason in the plugin.
  - `no-debian-source` — `debian/control` absent under the target;
    lintian has nothing to process. Parallel to v0.8 `no-apk` and
    v0.9 `no-bundle` — target-shape clean-skip.
  - `no-elf` — no ELF binary under the target; checksec has nothing
    to scan. Target-shape clean-skip.
  - `no-systemd-unit` — systemd-analyze available and host is
    systemd, but no `.service` in the target.
  - `tool-missing` — the tool is absent when its host/target
    preconditions held.
  The structured `{tool, reason}` skipped-list schema introduced in
  v0.8 absorbs these without contract-check schema change.

Linux findings combine code-pattern signal (systemd-analyze
per-directive scoring + lintian tag matches) with ELF-hardening
signal (checksec). The dep-inventory path IS affected when Debian
packaging is detected: `debian/control` declares Depends/Build-Depends,
which feed cve-enricher as
`{"ecosystem": "Debian", "manifest": "debian/control"}`. Debian
ecosystem OSV coverage is partial via the Debian Security Tracker —
document as best-effort, same tolerance as CocoaPods/SwiftPM in §3.11.

### 3.13 Desktop macOS pass — dispatch macos-runner

When the inventory emitted by §2 contains `macos` (Info.plist with
`LSMinimumSystemVersion` OR `*.pkg` / `*.dmg` OR Sparkle framework
markers OR `.app` with macOS deployment-target), dispatch the
`macos-runner` agent (`agents/macos-runner.md`, pinned to haiku,
tools: Read + Bash). The agent runs up to five tools: `mobsfscan`
(cross-platform Swift/Obj-C), plus the macOS-only Apple binaries
`codesign`, `spctl`, `pkgutil` (NEW for .pkg signature checks), and
`stapler` (NEW for notarization-ticket validation).

macos-runner is a SIBLING of ios-runner (§3.11) — both dispatch
codesign/spctl on .app bundles, but macos-runner adds pkgutil/stapler
for .pkg / .dmg release artifacts. Cross-platform SwiftPM packages
may satisfy BOTH iOS and macOS inventory signals simultaneously; in
that case both runners dispatch independently and the report-writer
renders findings in separate "iOS" and "macOS" sections.

Skill-level invariants:

- **No `macos` in inventory** — skip entirely.
- **`__macos_status__: "unavailable"`** — no tool could run.
- **`__macos_status__: "partial"`** — mix of successful runs + failures.
- **`__macos_status__: "ok"`** — every available tool ran; `skipped`
  list may be populated for cleanly-inapplicable tools.
- **Five clean-skip reasons:**
  - `requires-macos-host` (shared with iOS lane; codesign/spctl/
    pkgutil/stapler are macOS-only binaries).
  - `no-bundle` (codesign/spctl/stapler need a `.app`/`.framework`/
    `.dmg` artifact).
  - `no-pkg` (pkgutil needs a `.pkg`) — NEW in v0.11; target-shape
    parallel to Android's `no-apk` and iOS's `no-bundle`.
  - `no-notary-profile` (inherited from iOS; present only when
    macos-runner chooses to invoke notarytool for history lookups;
    v0.11's macos-runner skips notarytool — v0.12+ may add it).
  - `tool-missing`.

The dep-inventory path is NOT materially affected by this pass —
macOS uses the same CocoaPods/SwiftPM ecosystems as iOS, routed in
§3.11. When both `ios` and `macos` are in the inventory, the
ecosystems entry is emitted once per unique `manifest`, not
duplicated per lane.

### 3.14 Desktop Windows pass — dispatch windows-runner

When the inventory emitted by §2 contains `windows` (any of: .NET
project files, WiX sources, MSIX manifests, PE artifacts, or
AppLocker/WDAC policy XML), dispatch the `windows-runner` agent
(`agents/windows-runner.md`, pinned to haiku, tools: Read + Bash).
The agent runs up to three tools: `binskim` (Microsoft PE hardening
scanner — cross-platform via dotnet), `osslsigncode` (cross-platform
Authenticode verifier), and `sigcheck` (Sysinternals — Windows host
only). **Unlike the iOS/macOS lanes where most Apple binaries are
host-gated, only ONE of the Windows lane's three tools needs a
Windows host** — the other two produce useful output on Linux/macOS
CI.

windows-runner runs in parallel with every other pass agent. Collect
the Windows JSONL into a `windows_findings` list.

Skill-level invariants:

- **No `windows` in inventory** — skip entirely.
- **`__windows_status__: "unavailable"`** — no tool could run.
- **`__windows_status__: "partial"`** — mix of successful + failed
  tools.
- **`__windows_status__: "ok"`** — every available tool ran;
  `skipped` list may be populated for cleanly-inapplicable tools.
- **Three clean-skip reasons specific to this lane:**
  - `requires-windows-host` (sigcheck only) — NEW in v0.12, and the
    THIRD host-OS-gated reason after `requires-macos-host` (v0.9)
    and `requires-systemd-host` (v0.10). The three together cover
    every major desktop-OS runner gate.
  - `no-pe` (all three tools) — NEW in v0.12; source-only targets
    (`.csproj` + `.wxs` + manifests without compiled `.exe`/`.dll`/
    `.msi`) cleanly-skip. Target-shape parallel to `no-apk`/
    `no-bundle`/`no-pkg`/`no-elf`.
  - `tool-missing` — the binary is absent when its host+target
    preconditions held.

Windows findings combine PE-hardening signal (binskim), Authenticode
signature signal (osslsigncode), and deep-metadata signal (sigcheck).
The dep-inventory path IS affected when `.csproj` with
`<PackageReference>` is present — NuGet dependencies feed cve-
enricher as `{"ecosystem": "NuGet", "manifest": "packages.lock.json"}`.
OSV's `querybatch` handles NuGet natively, so no adapter change.

### 3.15 Kubernetes admission pass — dispatch k8s-runner

When the inventory emitted by §2 contains `k8s` (any YAML manifest
with `apiVersion:` + `kind:` at root), dispatch the `k8s-runner`
agent (`agents/k8s-runner.md`, pinned to haiku, tools: Read + Bash).
The agent shells out to `kube-score` and `kubesec` — both cross-
platform Go binaries with JSON output. Neither requires a live
cluster. No host-OS gate. No artifact-absence gate beyond manifest
discovery under target.

k8s-runner runs in parallel with every other pass agent. Collect
the findings into a `k8s_findings` list.

Skill-level invariants:

- **No `k8s` in inventory** — skip entirely.
- **`__k8s_status__: "unavailable"`** — neither tool on PATH, or
  both crashed.
- **`__k8s_status__: "partial"`** — one ran, one failed.
- **`__k8s_status__: "ok"`** — both ran cleanly.
- **Skip vocabulary (v1.1 adds no new reasons)** — only
  `tool-missing` is expected for this lane. The skipped-list schema
  is the same `{tool, reason}` structure used since v0.8.

K8s findings are code-pattern signal against manifests. **The dep-
inventory path is NOT affected by this lane** — K8s image references
(e.g. `image: nginx:1.21`) are not package-manifest dependencies and
would need a separate image-CVE enrichment path (future work). The
ecosystems list emitted to cve-enricher does NOT gain a K8s entry.

### 3.16 IaC pass — dispatch iac-runner

When the inventory emitted by §2 contains `iac` (any of: `*.tf`,
`*.tfvars`, `*.hcl`, `Pulumi.yaml`, `Pulumi.<stack>.yaml`, or
`terragrunt.hcl` under target), dispatch the `iac-runner` agent
(`agents/iac-runner.md`, pinned to haiku, tools: Read + Bash). The
agent shells out to `tfsec` (Go binary, Terraform-focused) and
`checkov` (Python, multi-IaC including Terraform + Pulumi). Both
tools are cross-platform — no host-OS gate. Neither requires a
live cloud account; both run as pure source-tree static scanners.

iac-runner runs in parallel with every other pass agent. Collect
the findings into an `iac_findings` list.

Skill-level invariants:

- **No `iac` in inventory** — skip entirely.
- **`__iac_status__: "unavailable"`** — neither tool on PATH, or
  both crashed.
- **`__iac_status__: "partial"`** — one ran, one failed.
- **`__iac_status__: "ok"`** — both ran cleanly.
- **Skip vocabulary (v1.2 adds no new reasons)** — only
  `tool-missing` is expected for this lane. Both tfsec and checkov
  are cross-platform with no host-OS gates and no
  artifact-absence preconditions beyond IaC source presence under
  target. The skipped-list schema is the same `{tool, reason}`
  structure used since v0.8.

IaC findings are code-pattern signal against declarative cloud
resource definitions. **The dep-inventory path is NOT affected by
this lane** — Terraform/Pulumi declarations reference cloud
resources and provider versions, not package-manifest
dependencies; provider-version CVE enrichment is a separate future
concern. The ecosystems list emitted to cve-enricher does NOT gain
an IaC entry. **Origin-tag isolation:** every iac finding carries
`origin: "iac"` and `tool: "tfsec" | "checkov"`. The
contract-check rejects any iac finding tagged with another lane's
tool (semgrep, kube-score, kubesec, etc.) — see
`tests/contract-check.sh`.

### 3.17 GitHub Actions pass — dispatch gh-actions-runner

When the inventory emitted by §2 contains `gh-actions` (any
`.github/workflows/*.y(a)ml` file with top-level `on:` + `jobs:`
keys), dispatch the `gh-actions-runner` agent
(`agents/gh-actions-runner.md`, pinned to haiku, tools: Read +
Bash). The agent shells out to `actionlint` (Go binary; broad
workflow lint with bundled shellcheck for script-injection
detection) and `zizmor` (Python; security-focused auditor for
pinning, permissions, template-injection, artifact-poisoning).
Both tools are cross-platform — no host-OS gate. Neither contacts
the GitHub API; both run as pure source-tree static scanners.

gh-actions-runner runs in parallel with every other pass agent.
Collect the findings into a `gh_actions_findings` list.

Skill-level invariants:

- **No `gh-actions` in inventory** — skip entirely.
- **`__gh_actions_status__: "unavailable"`** — neither tool on
  PATH, or both crashed.
- **`__gh_actions_status__: "partial"`** — one ran, one failed.
- **`__gh_actions_status__: "ok"`** — both ran cleanly.
- **Skip vocabulary (v1.3 adds no new reasons)** — only
  `tool-missing` is expected for this lane. Both actionlint and
  zizmor are cross-platform with no host-OS gates and no
  artifact-absence preconditions beyond `.github/workflows/`
  presence under target. The skipped-list schema is the same
  `{tool, reason}` structure used since v0.8.

GitHub Actions findings are code-pattern signal against workflow
YAML. **The dep-inventory path is NOT affected by this lane** —
workflow files reference action versions (`uses: org/repo@SHA`),
not package-manifest dependencies; SHA-pinning compliance is
enforced at the code-pattern layer (zizmor's `unpinned-uses`
audit) rather than via CVE feeds. The ecosystems list emitted to
cve-enricher does NOT gain a gh-actions entry. **Origin-tag
isolation:** every gh-actions finding carries
`origin: "gh-actions"` and `tool: "actionlint" | "zizmor"`. The
contract-check rejects any gh-actions finding tagged with another
lane's tool — see `tests/contract-check.sh`.

### 3.18 Virtualization pass — dispatch virt-runner

When the inventory emitted by §2 contains `virt` (any of the five
signals: Docker runtime config / Compose / Dockerfile, Podman /
Quadlet, libvirt domain/network/pool/volume XML, Apple Containers
`container.yaml`, or UTM `*.utm/config.plist`), dispatch the
`virt-runner` agent (`agents/virt-runner.md`, pinned to haiku,
tools: Read + Bash). The agent shells out to `hadolint`
(Haskell binary; Dockerfile / Containerfile static linter with
`DLxxxx` rule IDs and an embedded shellcheck pass) and
`virt-xml-validate` (libvirt-clients package; XSD validator that
checks libvirt domain / network / pool / volume XML against the
libvirt-shipped Relax-NG schemas). Both tools are cross-platform —
no host-OS gate. Neither contacts a Docker daemon, a podman
socket, a libvirtd, or any registry; both run as pure source-tree
static scanners.

virt-runner runs in parallel with every other pass agent. Collect
the findings into a `virt_findings` list.

Skill-level invariants:

- **No `virt` in inventory** — skip entirely.
- **`__virt_status__: "unavailable"`** — neither tool on PATH, or
  no virt-relevant artefact under target.
- **`__virt_status__: "partial"`** — one ran, one failed or
  cleanly-skipped.
- **`__virt_status__: "ok"`** — every available + applicable tool
  ran cleanly; `skipped` list may still be populated for
  cleanly-inapplicable tools.
- **Three skip reasons (v1.4 adds two NEW):**
  - `tool-missing` — the tool's binary is absent from PATH.
  - `no-containerfile` — NEW in v1.4; hadolint is on PATH but
    target has no Dockerfile / Containerfile / `*.dockerfile` /
    `*.containerfile` files. Target-shape clean-skip; parallel
    to v0.10's `no-debian-source`/`no-elf`, v0.11's `no-pkg`,
    and v0.12's `no-pe`.
  - `no-libvirt-xml` — NEW in v1.4; virt-xml-validate is on PATH
    but target has no XML files with a libvirt root element
    (`<domain>` / `<network>` / `<pool>` / `<volume>`).
    Target-shape clean-skip.

Virt findings are code-pattern signal against
container-runtime / VMM configuration and Containerfile
authorship. The hadolint pass overlaps with the existing
`containers/dockerfile-hardening.md` reference (which sec-expert
reads): hadolint operationalises the dockerfile-hardening
patterns with deterministic rule IDs, while sec-expert covers the
cross-Dockerfile reasoning (multi-stage build hygiene, base-image
selection rationale) and the four runtime/VMM packs that have no
first-party scanner (`virt/docker-runtime.md`, `virt/podman.md`,
`virt/apple-containers.md`, `virt/utm.md`) plus `virt/libvirt-qemu.md`.
**The dep-inventory path is NOT affected by this lane** — virt
configurations reference image tags and host devices, not
package-manifest dependencies; image-tag pinning compliance is
enforced at the code-pattern layer (hadolint's `DL3007` rule plus
sec-expert reasoning) rather than via CVE feeds. The ecosystems
list emitted to cve-enricher does NOT gain a virt entry.
**Origin-tag isolation:** every virt finding carries
`origin: "virt"` and `tool: "hadolint" | "virt-xml-validate"`.
The contract-check rejects any virt finding tagged with another
lane's tool — see `tests/contract-check.sh`.

### 3.19 Go pass — dispatch go-runner

When the inventory emitted by §2 contains `go` (the `go.mod`
+ at least one `*.go` file detection rule fired), dispatch
the `go-runner` agent (`agents/go-runner.md`, pinned to
haiku, tools: Read + Bash). The agent shells out to two Go
binaries — `gosec` (security-focused linter with mature
`Gxxx` rule IDs covering hardcoded credentials, SQL
injection, weak crypto, file permissions, command injection,
TLS config, HTTP servers without timeouts) and `staticcheck`
(comprehensive bug-finding + simplifications + style with
`SAxxxx`/`Sxxxx`/`STxxxx`/`Uxxxx`/`QFxxxx` rules) — against
the Go module root, parses each tool's native JSON output,
and emits sec-expert-compatible JSONL on stdout — every line
carrying `origin: "go"` and `tool: "gosec" | "staticcheck"`.

go-runner runs in parallel with every other pass agent.
Collect the findings into a `go_findings` list.

Skill-level invariants:

- **No `go` in inventory** — skip entirely. Do NOT probe for
  gosec or staticcheck on unrelated projects.
- **`__go_status__: "unavailable"`** — neither tool on PATH,
  or the target had no `*.go` files, or both tools crashed.
- **`__go_status__: "partial"`** — one ran, one failed.
- **`__go_status__: "ok"`** — both ran cleanly.
- **Skip vocabulary (v1.5 adds no new reasons)** — only
  `tool-missing` is expected for this lane. Both gosec and
  staticcheck are cross-platform Go binaries with no
  host-OS gates and no artifact-absence preconditions
  beyond `go.mod` + `*.go` source presence under target
  (which the inventory rule guarantees before dispatch).
  The skipped-list schema is the same `{tool, reason}`
  structure used since v0.8.

Go findings combine code-pattern signal (gosec's security
rule fires plus staticcheck's deprecated-symbol / leaked-
goroutine / unsafe-printf checks) with deprecation-tracking
signal (staticcheck SA1019 against the Go 1.21+ stdlib
deprecation set). The dep-inventory path IS affected:
`go.sum` (or `go.mod` when go.sum is absent) feeds the
cve-enricher as an ecosystem entry
`{"ecosystem": "Go", "manifest": "go.sum"}` — OSV's
`querybatch` endpoint handles `Go` natively, so no new feed
adapter is required. **Origin-tag isolation:** every go
finding carries `origin: "go"` and
`tool: "gosec" | "staticcheck"`. The contract-check rejects
any go finding tagged with another lane's tool — see
`tests/contract-check.sh`.

### 3.20 Shell pass — dispatch shell-runner

When the inventory emitted by §2 contains `shell` (any
shell-shaped file under target — `*.sh`/`*.bash`/`*.zsh`/
`*.ksh` or a file with a shell shebang on line 1, with
vendored-directory exclusions), dispatch the `shell-runner`
agent (`agents/shell-runner.md`, pinned to haiku, tools:
Read + Bash). The agent shells out to a single tool —
`shellcheck` (Haskell binary; canonical static analyzer for
bash/sh/dash/ksh with `SCxxxx` rule IDs covering quoting,
command injection, file handling, and control-flow
correctness) — against the shell-shaped files, parses
shellcheck's native JSON output, and emits sec-expert-
compatible JSONL on stdout — every line carrying
`origin: "shell"` and `tool: "shellcheck"`.

This is the **first single-tool lane in sec-review since
DAST (v0.5)**. shellcheck is the canonical mature
shell-script linter — adding a second tool for symmetry
would be overhead with no signal lift.

shell-runner runs in parallel with every other pass agent.
Collect the findings into a `shell_findings` list.

Skill-level invariants:

- **No `shell` in inventory** — skip entirely.
- **`__shell_status__: "unavailable"`** — shellcheck on PATH
  but no shell-shaped files under target, OR shellcheck
  absent entirely.
- **`__shell_status__: "ok"`** — shellcheck ran cleanly.
- **No `partial` state** — single-tool lane; either ran or
  did not.
- **Two skip reasons (v1.6 adds one NEW):**
  - `tool-missing` — shellcheck absent from PATH.
  - `no-shell-source` — NEW in v1.6; shellcheck on PATH but
    target has no shell-shaped files (after vendored-dir
    exclusions). Target-shape clean-skip; parallel to the
    v0.10–v1.4 target-shape primitives (`no-pe`, `no-elf`,
    `no-pkg`, `no-debian-source`, `no-containerfile`,
    `no-libvirt-xml`).

Shell findings are code-pattern signal against shell-script
quoting, injection, file-handling, and hardening hygiene.
**The dep-inventory path is NOT affected by this lane** —
shell scripts have no package-manifest dependency graph;
supply-chain risk for sourced remote scripts (the
`curl | sh` antipattern) is enforced at the code-pattern
layer via the `shell/file-handling.md` reference's CWE-494
pattern. The ecosystems list emitted to cve-enricher does
NOT gain a shell entry. **Origin-tag isolation:** every
shell finding carries `origin: "shell"` and
`tool: "shellcheck"`. The contract-check rejects any shell
finding tagged with another lane's tool — see
`tests/contract-check.sh`.

### 3.21 Python pass — dispatch python-runner

When the inventory emitted by §2 contains `python` (the
Python manifest + package-shape detection rule fired),
dispatch the `python-runner` agent
(`agents/python-runner.md`, pinned to haiku, tools: Read +
Bash). The agent shells out to two Python tools —
`pip-audit` (PyPA-maintained PyPI vulnerability scanner with
OSV-backed metadata + reachability-hint annotations) and
`ruff` (Rust-implemented Python linter; runs the `S`-prefix
flake8-bandit security ruleset + the `B`-prefix
flake8-bugbear bug-prone-pattern ruleset, faster than
running bandit alone) — against the project root, parses
each tool's native JSON output, and emits sec-expert-
compatible JSONL on stdout — every line carrying
`origin: "python"` and `tool: "pip-audit" | "ruff"`.

**Delineation from the SAST lane (§3.6).** The SAST lane
runs `bandit` and `semgrep` on every project; the python
lane is additive, not replacement. Three reasons it
deepens coverage:

1. **`pip-audit`** adds reachability-hint metadata that
   cve-enricher's bulk OSV pass lacks (cve-enricher matches
   versions only).
2. **`ruff`** is faster and ships flake8-bandit rules that
   postdate the pinned upstream `bandit` version — running
   both catches the gap.
3. **Reference packs** deepen sec-expert reasoning over
   Python-specific surfaces (Pickle/YAML deserialization,
   asyncio exception swallowing, FastAPI DI bypass, Django
   ORM `.extra()` injection) beyond bandit's rule set.

python-runner runs in parallel with every other pass agent.
Collect the findings into a `python_findings` list.

Skill-level invariants:

- **No `python` in inventory** — skip entirely.
- **`__python_status__: "unavailable"`** — neither tool on
  PATH, or no Python manifest under target.
- **`__python_status__: "partial"`** — one ran, one failed
  or cleanly-skipped.
- **`__python_status__: "ok"`** — both ran cleanly.
- **Two skip reasons:**
  - `tool-missing` — the tool's binary is absent from PATH.
  - `no-requirements` — NEW in v1.7; pip-audit applicable
    but no requirements.txt / pyproject.toml / setup.py /
    Pipfile under target, OR ruff applicable but no `*.py`
    files. Target-shape clean-skip; parallel to
    v0.10–v1.6 target-shape primitives.

Python findings combine code-pattern signal (ruff's `S`
and `B` rule fires) with package-version signal
(pip-audit's OSV-backed CVE matches). The dep-inventory
path IS already affected by the existing PyPI ecosystem
entry; the python lane's pip-audit pass augments
cve-enricher's bulk scan with reachability hints. **Origin-
tag isolation:** every python finding carries
`origin: "python"` and `tool: "pip-audit" | "ruff"`. The
contract-check rejects any python finding tagged with
another lane's tool — see `tests/contract-check.sh`.

### 3.22 Ansible pass — dispatch ansible-runner

When the inventory emitted by §2 contains `ansible` (any of:
playbook YAML with `hosts:` + `tasks:`, `roles/` directory,
`ansible.cfg`, `collections/`, inventory, or
`requirements.yml` with roles/collections entries),
dispatch the `ansible-runner` agent
(`agents/ansible-runner.md`, pinned to haiku, tools: Read +
Bash). The agent shells out to a single tool —
`ansible-lint` (Python-implemented Ansible playbook + role +
collection linter; mature rule catalogue covering security
like `risky-shell-pipe`, `no-log-password`,
`command-instead-of-shell`, `partial-become`, plus
idempotency and deprecation tracking) — against the
project, parses ansible-lint's native JSON output, and
emits sec-expert-compatible JSONL on stdout — every line
carrying `origin: "ansible"` and `tool: "ansible-lint"`.

This is a **single-tool lane** like Shell (v1.6) and DAST
(v0.5). ansible-lint is the canonical mature Ansible
linter — adding a second tool for symmetry would be
overhead with no signal lift.

ansible-runner runs in parallel with every other pass agent.
Collect the findings into an `ansible_findings` list.

Skill-level invariants:

- **No `ansible` in inventory** — skip entirely.
- **`__ansible_status__: "unavailable"`** — ansible-lint not
  on PATH OR target has no Ansible-shaped files.
- **`__ansible_status__: "ok"`** — ansible-lint ran cleanly.
- **No `partial` state** — single-tool lane.
- **Two skip reasons:**
  - `tool-missing` — ansible-lint absent from PATH.
  - `no-playbook` — NEW in v1.8; ansible-lint on PATH but
    target has no Ansible-shaped files. Target-shape
    clean-skip; parallel to v0.10–v1.7 target-shape
    primitives.
- **`--offline` mode mandatory.** The runner always passes
  `--offline` to ansible-lint to prevent Galaxy collection
  lookups — sec-review is source-only.

Ansible findings are code-pattern signal against playbook
authorship, role hygiene, and Vault secret handling.
**The dep-inventory path is NOT affected by this lane** —
Ansible role / collection dependencies are not currently in
OSV's coverage; Galaxy supply-chain integrity (SHA256
verification against the Galaxy registry) is a separate
future concern. The ecosystems list emitted to cve-enricher
does NOT gain an ansible entry. **Origin-tag isolation:**
every ansible finding carries `origin: "ansible"` and
`tool: "ansible-lint"`. The contract-check rejects any
ansible finding tagged with another lane's tool — see
`tests/contract-check.sh`.

## 4. CVE enrichment — dispatch cve-enricher

Dispatch the `cve-enricher` agent (`agents/cve-enricher.md`, pinned to
haiku). It consumes the dep inventory emitted by sec-expert and returns a
structured JSON document — one object per package with its CVEs and a
`status` field (`ok` / `offline` / `capped`). Moving CVE enrichment into a
haiku-pinned agent keeps the main skill context small and makes the
per-package I/O loop cheap.

The agent uses the OSV `querybatch` endpoint for the primary lookup (up
to 1000 queries per call, returning vuln IDs only), follows up with
per-id detail fetches, and falls back to NVD 2.0 and GHSA for packages
OSV doesn't cover. Endpoint URLs live in `references/cve-feeds.md` —
`cve-enricher` reads them at runtime; they are NOT inlined here or in
the agent body. That file is the single choke-point when feed schemas
change.

Skill-level invariants the orchestrator still enforces (the agent
reports these states; the skill decides what to do with them):

- **Per-package `status: "offline"`** — keep the package in the report,
  but mark `CVE(s): Unknown — feed offline` in its finding block.
- **Per-package `status: "capped"`** — we hit the 500-lookup cap; emit a
  `Limits hit: cve_lookup_cap_500` entry in the Review metadata section
  and ask the user to narrow scope on re-run.
- **All-feeds-offline run** — when every package has `status: "offline"`,
  add the `⚠ CVE enrichment offline — re-run with network to populate`
  banner at the top of the report. The report still lists the full
  finding set from sec-expert. Never fabricate CVE IDs from training
  data under any circumstance.
- **Retry and cap** — the agent enforces retry-once-with-2s-backoff and
  the 500 cap itself; the skill just validates the shape of what comes
  back.

Attach each CVE entry to the corresponding dep-level finding, and
promote HIGH/CRITICAL CVSS CVEs to top-level findings (not just footnotes
on the dep inventory).

## 5. Prioritize

Compute a numeric score 0–100 per finding and bucket it.

**Scoring rubric** (deterministic — show the math in the report):

- **CVSS** (0–40 pts): `min(40, cvss_base * 4)` if CVE-enriched; else use
  the sec-expert severity mapped to `CRITICAL=36 / HIGH=28 / MEDIUM=16 /
  LOW=6 / INFO=0`.
- **Exposure** (0–25 pts): `+25` if the affected file is reachable from an
  unauthenticated HTTP path, `+15` if authenticated, `+5` if internal-only
  (admin, cron, worker), `0` if test/fixture code.
- **Exploit-in-wild** (0–20 pts): `+20` if `cve.kev == true` (CISA KEV
  catalog, cross-referenced by `cve-enricher`); `+10` if there's a public
  PoC reference; `0` otherwise. Note: `cve.kev == null` means the KEV feed
  was offline — unknown is unknown, no points awarded.
- **Auth-required** (0–15 pts): `+15` if exploit requires no auth; `+8`
  if auth but no elevated privileges; `+2` if admin-only; `0` if attacker
  must already control the host.

Downgrade confidence one step if `cve_enrichment: "offline"` — an unknown
CVSS can't count against the user. Note: the base `confidence` field this
rubric reads is set by the `finding-triager` agent (section 3.5), not by
this skill. This skill's only confidence adjustment is the offline
downgrade above; all other confidence decisions belong to the triager.

**Buckets**:

| Score  | Bucket   |
|--------|----------|
| 90–100 | CRITICAL |
| 70–89  | HIGH     |
| 40–69  | MEDIUM   |
| 0–39   | LOW      |

Order the report by descending score, CRITICAL first.

## 6. Report — dispatch report-writer

Dispatch the `report-writer` agent (`agents/report-writer.md`, pinned to
sonnet) with the triaged findings, the cve-enricher output, and the
inventory. The agent writes
`<target_path>/sec-review-report-YYYYMMDD-HHMM.md` (timestamp in UTC) and
returns the absolute path to stdout so the orchestrator can confirm
placement.

This section documents the report template so it remains readable in the
skill source — but generation is **delegated** to the agent. Keeping the
template here is for humans reading the skill; the agent is the single
source of truth for actual report shape. Do not inline the markdown build
into this skill's context.

Template (the agent follows this exactly):

```markdown
# Security Review — <target_basename>

**Date (UTC):** 2026-04-21 14:32
**Scope:** <paths included>
**Excluded:** <paths excluded>
**Inventory:** <terse stack summary>
**CVE feeds:** OSV (ok), NVD (ok), GHSA (ok)   <!-- or "offline" -->
**Findings:** 1 CRITICAL, 4 HIGH, 7 MEDIUM, 3 LOW

---

## CRITICAL

### <title>
- **File:** `<path>:<line>`
- **CWE:** CWE-<n>
- **CVE(s):** CVE-YYYY-NNNNN (CVSS 9.8, source: OSV, fetched 2026-04-21T14:30Z)
- **Score:** 94 / 100 (CVSS 40 + Exposure 25 + Exploit 20 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <exact line from sec-expert>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > <verbatim Fix recipe from the reference file>
- **Sources:**
  - <primary-source URL from reference>
  - <CVE advisory URL(s)>

## HIGH
<...same shape...>

## MEDIUM
<...>

## LOW
<...>

---

## Dependency CVE summary

| Package | Version | CVEs | Max CVSS | Fixed in |
|---------|---------|------|----------|----------|
| django  | 2.2.0   | 7    | 9.8      | 3.2.25+  |

## Review metadata

- Plugin version: `sec-review 0.1.0`
- Reference packs loaded: <list>
- sec-expert runs: <n>
- Total CVE lookups: <n>
- Limits hit: <list or "none">
```

Each finding block MUST include `file:line`, the CWE, any matched CVE
IDs, the numeric score (with the breakdown), the evidence snippet, the
recommended fix (quoted verbatim from a reference file's `## Fix
recipes`), and primary-source URLs. The report is the only user-facing
deliverable — make it the thing a reviewer could hand to an engineer.
