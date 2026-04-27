# Uncovered Technology Fingerprints

<!--
    v1.10.0+ — Coverage-gap detection reference pack.

    Loaded by the orchestrator skill at §2 Inventory's
    "Uncovered-technology detection" step. Enumerates known-but-
    UNCOVERED technology fingerprints (manifest filenames, file-
    extension globs, header-line regex) plus suggested tooling for a
    future sec-audit lane. The orchestrator scans for each
    fingerprint's match conditions and emits an `uncovered_tech` array
    containing per-detected-technology suggestion records — the
    report-writer renders these in the "Coverage-gap suggestions"
    section so the user knows which technologies in their project are
    NOT being analysed and what tooling would close the gap.

    Curation rules:
    1. Every entry is a technology with a meaningful security-review
       surface (auth, deserialization, injection, dep-management).
    2. Every entry has at least ONE concrete static-analysis or
       vulnerability-scanning tool that could form a future lane.
    3. Every "suggested_lane" name follows the canonical lane-naming
       convention (single lowercase word or hyphenated pair).
    4. Detection patterns favour HIGH-precision (manifest presence) over
       file-extension globs alone — *.java alone is too broad; pom.xml
       + spring-boot-starter is more specific. Where extension is the
       only signal, document the FP risk in `notes`.
-->

## Source

- https://owasp.org/www-project-top-ten/ — OWASP Top Ten
- https://cwe.mitre.org/ — CWE catalogue (referenced for tool selection)
- Each tool entry below cites its canonical upstream documentation URL.

## Schema

Each detection entry follows this shape:

```yaml
- name: <human-readable technology name>
  suggested_lane: <canonical lane name>
  detection:
    - pattern: <regex / glob / manifest filename>
      kind: <"manifest" | "file-extension" | "shebang" | "content-regex">
      precision: <"high" | "medium" | "low">
  suggested_tools:
    - name: <tool binary name>
      url: <canonical doc URL>
      notes: <one-line description>
  rationale: <one-paragraph "why this tech needs its own lane">
  notes: <FP / scoping caveats>
```

## Detection entries

### Java server-side (non-Spring)

- **suggested_lane:** `java`
- **detection:**
  - `pom.xml` (manifest, high) WITHOUT `spring-boot-starter-*` content
  - `build.gradle(.kts)` (manifest, high) WITHOUT `org.springframework.boot` plugin
  - `*.java` (file-extension, medium) at non-trivial depth in a Maven/Gradle layout (`src/main/java/...`)
  - **Excluded** when Android plugin (`com.android.application` / `com.android.library`) is present — that's the existing `android` lane.
- **suggested_tools:**
  - `spotbugs` — https://spotbugs.github.io/ — Java static analyzer, successor to FindBugs.
  - `find-sec-bugs` — https://find-sec-bugs.github.io/ — SpotBugs plugin with security-focused detectors (CWE-89 SQLi, CWE-79 XSS, CWE-502 deserialization, CWE-611 XXE).
  - `pmd` (with `category/java/security.xml`) — https://pmd.github.io/ — multi-language linter with a Java security ruleset.
- **rationale:** Java server-side covers Tomcat, Quarkus, Micronaut, Helidon, Vert.x, JAX-RS — none of which are in `frameworks/spring.md`. Common security surfaces: Java deserialization (CVE-2015-7501 class), JNDI injection (CVE-2021-44228 Log4Shell class), XXE in `javax.xml.parsers`, Velocity / Freemarker SSTI.
- **notes:** Maven/Gradle dependencies are already covered by the `Maven` ecosystem entry feeding cve-enricher; the new lane would add code-pattern signal beyond dep-version CVE matching.

### C / C++ source

- **suggested_lane:** `cpp`
- **detection:**
  - `*.c` / `*.cc` / `*.cpp` / `*.cxx` / `*.h` / `*.hpp` / `*.hxx` (file-extension, medium)
  - `CMakeLists.txt` (manifest, high) — strong indicator of a C/C++ project
  - `Makefile` containing `gcc` / `g++` / `clang` / `clang++` invocations (content-regex, medium)
  - `*.vcxproj` / Visual Studio C++ project (medium) — overlap with `windows` lane (PE binaries) but distinct (source-only review)
- **suggested_tools:**
  - `cppcheck` — https://cppcheck.sourceforge.io/ — open-source static analyzer for C/C++.
  - `clang-tidy` — https://clang.llvm.org/extra/clang-tidy/ — LLVM-shipped linter with `clang-analyzer-security-*` checks.
  - `flawfinder` — https://dwheeler.com/flawfinder/ — security-focused scanner targeting `strcpy`, `gets`, `sprintf`, `system` family hazards.
- **rationale:** C/C++ source review covers buffer overflows (CWE-120/121/122), format-string bugs (CWE-134), use-after-free (CWE-416), integer overflow (CWE-190), and the canonical unsafe-libc-function family. The existing `windows` lane handles PE binaries (binskim runs on compiled artefacts), but pure C/C++ source has no static lane.
- **notes:** Every project has SOME `*.h` files (e.g. via vendored deps); pair extension detection with `CMakeLists.txt` / `Makefile` to reduce FPs. Exclude `node_modules/`, `.venv/`, `vendor/` per §1 Scope.

### Solidity (smart contracts)

- **suggested_lane:** `solidity`
- **detection:**
  - `*.sol` (file-extension, high — Solidity is the only meaningful consumer of `.sol`)
  - `hardhat.config.js` / `hardhat.config.ts` (manifest, high)
  - `truffle-config.js` / `truffle.js` (manifest, high)
  - `foundry.toml` (manifest, high)
- **suggested_tools:**
  - `slither` — https://github.com/crytic/slither — Trail of Bits' canonical Solidity static analyzer.
  - `mythril` — https://github.com/Consensys/mythril — symbolic-execution-based smart-contract security analyzer.
  - `solhint` — https://protofire.github.io/solhint/ — Solidity linter (style + some security rules).
- **rationale:** Smart-contract security is its own discipline: re-entrancy (CWE-841), integer overflow (Solidity ≤ 0.7), unchecked external calls, `tx.origin` auth, front-running. None of these map to existing lanes.
- **notes:** Niche unless the user works in DeFi / Web3 / NFT; flagging is INFO-by-default; user can decide whether to fund the lane.

### PHP (Laravel / Symfony / WordPress / generic)

- **suggested_lane:** `php`
- **detection:**
  - `composer.json` (manifest, high)
  - `*.php` (file-extension, medium) at non-trivial depth
  - `wp-config.php` (manifest, high — WordPress signal)
  - `artisan` (manifest, high — Laravel CLI entry point)
  - `bin/console` (manifest, medium — Symfony CLI entry point)
- **suggested_tools:**
  - `psalm` — https://psalm.dev/ — Vimeo's PHP static analyzer with `--taint-analysis`.
  - `phpstan` — https://phpstan.org/ — multi-level static analyzer.
  - `progpilot` — https://github.com/designsecurity/progpilot — PHP security-focused taint analyzer (CWE-89 / CWE-79 / CWE-78 / CWE-22).
- **rationale:** PHP is one of the most-deployed server-side languages globally. WordPress alone hosts 40%+ of the web. Existing coverage is via SAST lane's semgrep `p/php` ruleset only, which is shallow. A dedicated lane would deepen CWE-89 / CWE-79 / CWE-22 / CWE-78 detection via taint analysis.
- **notes:** `composer.json` deps are already covered by the `Packagist` ecosystem entry feeding cve-enricher.

### Ruby (non-Rails)

- **suggested_lane:** `ruby-non-rails`
- **detection:**
  - `Gemfile` (manifest, high) WITHOUT `gem 'rails'` content
  - `*.rb` (file-extension, medium) at non-trivial depth
  - `config.ru` (manifest, high — Rack apps including Sinatra, Hanami, Roda)
  - `*.gemspec` (manifest, high)
- **suggested_tools:**
  - `brakeman` — https://brakemanscanner.org/ — Rails-specific scanner; the upstream tool of choice for Ruby web security but Rails-only.
  - `bundler-audit` — https://github.com/rubysec/bundler-audit — gem advisory scanner (overlaps with cve-enricher's RubyGems pass).
  - `rubocop` with `rubocop-rails-omakase` / `rubocop-thread_safety` — https://docs.rubocop.org/ — multi-cop linter; specific cops cover security (e.g. `Lint/Open` flagging `open(uri)` SSRF).
- **rationale:** Brakeman is Rails-only — Sinatra/Hanami/Roda apps and pure-Ruby microservices have no equivalent. A non-Rails Ruby lane would cover Sinatra route-handler injection, Rack middleware ordering, and YAML.load (CWE-502).
- **notes:** Rails projects are partially covered by sec-expert + the existing `frameworks/rails.md` pack; this lane is for the non-Rails subset.

### .NET server-side (ASP.NET Core / Blazor)

- **suggested_lane:** `dotnet`
- **detection:**
  - `*.csproj` containing `<PackageReference Include="Microsoft.AspNetCore.*"` (manifest, high)
  - `Program.cs` with `WebApplication.CreateBuilder` (content-regex, high)
  - `appsettings.json` next to a `*.csproj` (manifest, high)
  - **Excluded** when the project is detected as `windows` desktop (WiX, MSIX, AppLocker) — that's the existing `windows` lane.
- **suggested_tools:**
  - `security-code-scan` — https://security-code-scan.github.io/ — Roslyn analyzer with security-focused diagnostics.
  - `devskim` — https://github.com/microsoft/DevSkim — Microsoft's pattern-based scanner.
  - `dotnet retire` (deprecated; mention as historical) — `dotnet list package --vulnerable` is the modern replacement.
- **rationale:** ASP.NET Core covers Razor Pages, Blazor Server, gRPC services, SignalR — none of which are in any existing lane. The `windows` lane handles compiled PE artefacts; ASP.NET Core source needs its own static-analysis surface.
- **notes:** NuGet deps are already covered by the `NuGet` ecosystem entry feeding cve-enricher.

### Lua / LuCI (router admin UI)

- **suggested_lane:** `lua`
- **detection:**
  - `*.lua` (file-extension, medium)
  - `luci/` directory (manifest, high — LuCI signal)
  - `*.luarocks.spec` (manifest, high — LuaRocks dep manifest)
  - `Makefile` containing `lua` / `luarocks` invocations (content-regex, medium)
- **suggested_tools:**
  - `luacheck` — https://github.com/lunarmodules/luacheck — Lua static analyzer; primarily style/correctness but flags some unsafe patterns.
  - LuCI ACL/menu.d audit — no canonical tool exists; would require a custom checker.
- **rationale:** OpenWrt / LuCI ships Lua web-admin UIs; security surfaces include template injection, ACL bypass, RPC-handler argument validation. Currently uncovered.
- **notes:** Most projects have NO Lua; flag only when the manifest signals fire.

### Elixir / Phoenix

- **suggested_lane:** `elixir`
- **detection:**
  - `mix.exs` (manifest, high)
  - `*.ex` / `*.exs` (file-extension, medium)
- **suggested_tools:**
  - `sobelow` — https://github.com/nccgroup/sobelow — NCC Group's Phoenix-focused security scanner (CWE-79, CWE-89, command injection).
  - `credo` — https://github.com/rrrene/credo — Elixir-specific linter.
- **rationale:** Phoenix's growing adoption (Discord, WhatsApp partial migration, Apple, etc.) makes Elixir security review a real demand. Not in any existing lane.
- **notes:** `mix.exs` deps via Hex.pm — currently NOT in OSV's coverage; cve-enricher would need a Hex feed adapter.

### Helm charts

- **suggested_lane:** `helm`
- **detection:**
  - `Chart.yaml` (manifest, high)
  - `templates/*.yaml` next to `Chart.yaml` (manifest, high)
  - `values.yaml` next to `Chart.yaml` (manifest, high)
- **suggested_tools:**
  - `helm template` (rendering) + `kube-score` / `kubesec` against the rendered output (the existing `k8s` lane covers this; Helm is the rendering-layer concern).
  - `kubeaudit` — https://github.com/Shopify/kubeaudit — Kubernetes audit tool with Helm-template support.
  - `polaris` — https://github.com/FairwindsOps/polaris — Kubernetes best-practices.
- **rationale:** Helm is a layer above raw K8s manifests — `values.yaml` parameterisation introduces injection-class concerns (string-interpolation into K8s YAML, `tpl` function abuse). The existing `k8s` lane scans rendered manifests but not Helm-template authoring.
- **notes:** Lower priority — `helm template` + the existing `k8s` lane catches most concrete misconfigurations.

### Jupyter notebooks (data science / ML)

- **suggested_lane:** `notebook`
- **detection:**
  - `*.ipynb` (file-extension, high — `.ipynb` is the only meaningful consumer)
- **suggested_tools:**
  - `nbqa bandit` — https://github.com/nbQA-dev/nbQA — runs bandit on `.ipynb` cells.
  - `nbqa ruff` — same wrapper for ruff's `S`-rule subset.
- **rationale:** ML / data-science notebooks frequently contain `pickle.load(model_url)`, `eval(user_input)`, `requests.get(verify=False)` — security surfaces identical to Python source but currently missed because the SAST lane's bandit+semgrep do not parse `.ipynb` JSON.
- **notes:** Could potentially be folded into the existing `python` lane via an nbqa wrapper rather than a new lane.

### GitLab CI / CircleCI / Jenkins (CI systems beyond GitHub Actions)

- **suggested_lane:** `gitlab-ci` / `jenkins-ci` / `circle-ci`
- **detection:**
  - `.gitlab-ci.yml` (manifest, high — GitLab CI)
  - `Jenkinsfile` (manifest, high — Jenkins declarative pipeline)
  - `.circleci/config.yml` (manifest, high — CircleCI)
  - `azure-pipelines.yml` (manifest, high — Azure Pipelines)
  - `bitbucket-pipelines.yml` (manifest, high — Bitbucket)
  - `.drone.yml` (manifest, high — Drone CI)
- **suggested_tools:**
  - `gitlab-ci-lint` — https://docs.gitlab.com/ee/ci/yaml/lint.html — CI-yaml structural validator.
  - `kics` — https://kics.io/ — multi-IaC scanner with GitLab CI / GitHub Actions / CircleCI rules.
  - Jenkins Job DSL Plugin's safe-mode (deployment concern, not source-static).
- **rationale:** The existing `gh-actions` lane covers GitHub Actions only. Each CI system has its own injection-class concerns (untrusted variable interpolation, secret-file handling, runner-host privilege).
- **notes:** A `kics`-driven multi-CI lane would cover several formats with one tool.

### Smart-contract languages beyond Solidity

- **suggested_lane:** `web3-langs`
- **detection:**
  - `*.move` (Move language — Aptos / Sui)
  - `*.cairo` (Cairo — StarkNet)
  - `*.vy` (Vyper — Ethereum alternative to Solidity)
  - `*.rs` next to `Anchor.toml` (Anchor framework — Solana programs in Rust)
- **suggested_tools:**
  - Vyper: `mythril` supports Vyper bytecode; source-level tools nascent.
  - Move: `move-lint` — https://aptos.dev/ — early-stage.
  - Cairo: `caracal` — https://github.com/crytic/caracal — Trail of Bits' Cairo static analyzer.
  - Anchor (Solana): `anchor-test` + `solana-fuzz`.
- **rationale:** Same threat-model class as Solidity (re-entrancy, integer overflow, unchecked calls) but different languages and tooling. Highly niche.
- **notes:** Defer until a user explicitly requests; tooling is immature for several of these.

### eBPF programs

- **suggested_lane:** `ebpf`
- **detection:**
  - `*.bpf.c` (file-extension, high — kernel-style eBPF source)
  - `bpf2go` references in `go.mod` (content-regex, medium — Go eBPF)
- **suggested_tools:**
  - `bpftool prog dump` — https://docs.kernel.org/bpf/ — kernel-shipped; verifies eBPF bytecode.
  - eBPF-verifier-bypass class CVEs are kernel-side; source-level review centres on memory-safety + helper-function misuse.
- **rationale:** Kernel-attached eBPF programs run with privileged kernel access; verifier bypasses are a documented CVE class. Source-level review for unsafe helper usage and pointer arithmetic warrants a lane for projects that ship eBPF.
- **notes:** Very niche — flag only when `*.bpf.c` is present; user decides.

### WebAssembly modules

- **suggested_lane:** `wasm`
- **detection:**
  - `*.wasm` files (file-extension, high — compiled binary)
  - `*.wat` (WebAssembly text format — high)
  - `wasmtime.toml` / `wasmer.toml` (manifest, high — WASM runtime config)
- **suggested_tools:**
  - `wasm-opt --check` — https://github.com/WebAssembly/binaryen — structural validation.
  - `wabt` toolkit — https://github.com/WebAssembly/wabt — `wasm-validate` for parse-level validation.
  - Capability-system review (WASI permission scoping) — manual at this stage.
- **rationale:** WASM is increasingly deployed for plugin systems (browser extensions via wasm-pack, server-side via Wasmtime, cloud function via Cloudflare Workers). Security surface includes WASI capability over-grant, host-function exposure, and memory-safety in WASM-imported native code.
- **notes:** Niche; flag only when `*.wasm` / `*.wat` is present.

### Make / CMake / build-systems beyond Gradle/Cargo/npm

- **suggested_lane:** `build-systems`
- **detection:**
  - `Makefile` / `GNUmakefile` (manifest, medium — many other lanes also have Makefiles)
  - `CMakeLists.txt` (manifest, high — primary C/C++ build system)
  - `meson.build` (manifest, high)
  - `BUILD.bazel` / `WORKSPACE` (manifest, high — Bazel)
  - `BUCK` (manifest, high — Buck)
  - `build.sbt` (manifest, high — Scala SBT)
- **suggested_tools:**
  - No canonical security-focused linter; would require pattern-based reviews of `wget` / `curl | sh` install steps, unverified-checksum patterns.
- **rationale:** Build systems frequently `curl | sh` install dependencies, fetch toolchains without checksum verification, and embed credentials in build args. The existing `shell` lane catches some of this when invoked via shell scripts; the build-system layer adds its own surface.
- **notes:** Lower priority — most concrete misconfigurations surface via the `shell` lane already.

## Common false positives (lane-suggestion FPs)

The detection patterns are tuned for HIGH-precision suggestions, but
some FP classes recur:

- A repository with a SINGLE `*.java` file in `tests/fixtures/` and
  no `pom.xml` — annotate as test fixture; do NOT suggest a Java
  lane.
- `Makefile` invoking `gcc` solely for compiling test C extensions
  to a Python project — annotate as a Python project, not a C/C++
  one.
- `*.rb` files inside `vendor/bundle/ruby/` — vendored gems, not
  user-authored Ruby; exclude per §1 Scope.
- `Dockerfile` references to a build-system base image (e.g. a
  `FROM gradle:7-jdk17` line) — that signals build provenance, not
  the project's own primary language.
- A repository that already enables one of the existing lanes
  (e.g. detected as `python` AND containing some `*.lua` script
  for build glue) — flag the Lua lane suggestion as INFO-tier (the
  primary language is already covered).
