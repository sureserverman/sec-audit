# Go Modules — Supply Chain Hardening

## Source

- https://go.dev/ref/mod — Go modules reference (canonical)
- https://go.dev/doc/security/vuln/ — Go vulnerability management (govulncheck)
- https://go.dev/ref/mod#authenticating — module authentication via GOSUMDB
- https://proxy.golang.org/ — Go module proxy
- https://sum.golang.org/ — Go checksum database
- https://go.dev/blog/module-mirror-launch — module-mirror launch announcement
- https://slsa.dev/spec/v1.0/requirements — SLSA v1.0
- https://owasp.org/www-project-top-10-ci-cd-security-risks/ — OWASP CI/CD Top 10

## Scope

Covers Go module ecosystem hygiene: `go.mod` / `go.sum` / `go.work` semantics, `replace` directive misuse, `GOPROXY` and `GOSUMDB` configuration, `vendor/` consistency, retract directives, dependency-version pinning, and `govulncheck`-driven advisory consumption. Out of scope: stdlib pattern review (covered by `go/stdlib-security.md`), web-framework-specific patterns (`go/web-frameworks.md`), and the live CVE-feed enrichment path (handled at the orchestrator layer via the `Go` ecosystem entry — OSV-native, no adapter needed).

## Dangerous patterns (regex/AST hints)

### `replace` directive pointing at a local path or unverifiable fork — CWE-829

- Why: `replace example.com/foo => ../my-fork` (or `=> ./vendored`) substitutes the remote module with a local one at build time. This is the standard mechanism for short-term hot-fixes during development, but production `go.mod` files committed to a release branch with active `replace` directives ship code that is NOT verifiable against `sum.golang.org` — the local source is whatever the committer's working tree contained. Combined with a missing `go.sum` entry for the local path (Go modules cannot record a checksum for a directory replace), the supply-chain integrity guarantee is fully bypassed. The fix is to fork the upstream to a real module path, publish a tagged version, and pin to that version.
- Grep: `^replace\s+[^=]+=>\s+(\.\.?/|[A-Za-z]:\\|/)` (path-replace targeting a local directory) in `go.mod` not under `tests/` or `examples/`.
- File globs: `go.mod`
- Source: https://go.dev/ref/mod

### `GONOSUMCHECK=*` or `GOFLAGS=-insecure` set in build pipeline — CWE-345

- Why: `GONOSUMCHECK` and `GOINSECURE` (and `GOFLAGS=-insecure`) disable checksum verification against `sum.golang.org`. Set globally, every dependency is fetched without integrity verification — a compromised proxy or MITM lands tampered source. Per-module `GONOSUMDB` exclusion is sometimes legitimate for genuinely private repositories (which `sum.golang.org` cannot index), but a wildcard exclusion or a disable in CI is a structural removal of the supply-chain check. The hardened pattern is `GONOSUMDB=corp.example.com/*` (narrow exclusion for the specific private registry) plus `GOSUMDB=sum.golang.org` for everything else.
- Grep: `GONOSUMCHECK\b`, `GOINSECURE\s*=\s*\*`, `GOFLAGS\s*=.*-insecure`, `GOSUMDB\s*=\s*off`.
- File globs: `Dockerfile`, `*.dockerfile`, `Makefile`, `.github/workflows/*.y(a)ml`, `.gitlab-ci.yml`, shell install scripts.
- Source: https://go.dev/ref/mod#authenticating

### `go.mod` declares a dependency without a corresponding `go.sum` entry — CWE-345

- Why: Every direct and indirect dependency in `go.mod` should have at least two `go.sum` entries (the module zip and the `go.mod` file of that version). A missing `go.sum` entry indicates either (a) the dependency was added without `go mod tidy` (which would have populated `go.sum`), or (b) `go.sum` was hand-edited to remove an entry — both of which break the verification chain. CI should run `go mod verify` to confirm all modules' downloaded contents match `go.sum`.
- Grep: `go.mod` with `require` blocks but no `go.sum` file in the same directory, OR a `go.mod` whose `require` count exceeds `go.sum`'s line count by more than 2× (a 2:1 ratio is normal: `.zip` + `.go.mod` per dep).
- File globs: `go.mod`, `go.sum`
- Source: https://go.dev/ref/mod

### Indirect dependency with a known-vulnerable version (govulncheck advisory) — CWE-1395

- Why: Go's official `govulncheck` (`golang.org/x/vuln/cmd/govulncheck`) cross-references the project's `go.sum` and call graph against the Go vulnerability database (`vuln.go.dev`, OSV-mirrored). A finding indicates BOTH a vulnerable version is imported AND the vulnerable symbol is reachable from `main`. This is more precise than naive `go.sum` ↔ CVE matching because it filters out unreachable vulnerable functions. Sec-review's `cve-enricher` performs the broader version-only match via OSV; `govulncheck`-style reachability analysis (when adopted into the lane) closes the false-positive gap.
- Grep: not regex-detectable — `go-runner`'s govulncheck invocation (when added) carries this signal directly. For the v1.5 lane, the OSV cve-enricher pass against the Go ecosystem (`go.sum`) provides the version-level signal.
- File globs: `go.sum`, `go.mod`
- Source: https://go.dev/doc/security/vuln/

### `go.mod` uses `+incompatible` versions without justification — CWE-1104

- Why: A `+incompatible` suffix appears when a dependency's major version is ≥2 but the dependency does NOT use the `/v2`+ module-path suffix that Go modules require for SemVer-major releases. Go tolerates this for backwards compatibility with pre-modules tags, but the dependency is signalling that its release process does not follow Go module semantics. Such a dependency may have unstable APIs, missing release tags, or a maintainer who is not actively shipping under Go-modules conventions — all of which raise supply-chain risk. Audit each `+incompatible` entry; prefer alternatives.
- Grep: `\+incompatible\b` in `go.mod`.
- File globs: `go.mod`
- Source: https://go.dev/ref/mod

### `vendor/` directory inconsistent with `go.mod` / `go.sum` — CWE-829

- Why: When a project uses `vendor/` (committed-vendored dependencies), `go build -mod=vendor` is the only mode that uses them. `go mod vendor` regenerates `vendor/` from `go.mod`/`go.sum`. A `vendor/` that has been hand-edited (a quick local patch) but not reflected in `go.mod`/`go.sum` ships modified third-party source under the original version label — auditors looking at `go.sum` see the upstream hash, but the actual code differs. The fix is `go mod vendor && git diff vendor/` in CI to detect drift.
- Grep: presence of `vendor/modules.txt` PLUS evidence that `go mod vendor` does not produce a clean tree (CI signal, not source-only).
- File globs: `vendor/modules.txt`, `vendor/*/`, `go.sum`
- Source: https://go.dev/ref/mod

## Secure patterns

Hardened `go.mod` for a binary:

```go
module example.com/api

go 1.22

require (
    github.com/go-chi/chi/v5 v5.0.12
    github.com/jackc/pgx/v5 v5.5.5
    golang.org/x/crypto v0.21.0
)

// Track upstream security advisories explicitly:
// retract v1.0.1 // contains broken JWT validation; use v1.0.2+
```

Source: https://go.dev/ref/mod

CI vulnerability scan with govulncheck:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck -mode=binary ./bin/api          # for compiled binary
govulncheck ./...                            # for source tree
```

Source: https://go.dev/doc/security/vuln/

## Fix recipes

### Recipe: remove local `replace` directive before release — addresses CWE-829

**Before (dangerous):**

```go
// go.mod (release branch, committed)
require example.com/foo v1.2.3
replace example.com/foo => ../my-local-fork
```

**After (safe):**

```go
// go.mod
require example.com/foo v1.2.3-fix.1
// (publish my-local-fork as a real module + tag, then pin to that version)
```

Source: https://go.dev/ref/mod

### Recipe: replace `GOSUMDB=off` with narrow `GONOSUMDB` exclusion — addresses CWE-345

**Before (dangerous):**

```dockerfile
ENV GOSUMDB=off
RUN go build ./...
```

**After (safe):**

```dockerfile
ENV GOSUMDB=sum.golang.org
ENV GONOSUMDB=corp.example.com/*    # narrow: only private registry skips checksum DB
ENV GOPRIVATE=corp.example.com/*    # (this also pulls these privately, not via proxy.golang.org)
RUN go build ./...
```

Source: https://go.dev/ref/mod#authenticating

### Recipe: enforce `go mod verify` in CI — addresses CWE-345

**Before (dangerous):**

```yaml
# .github/workflows/build.yml
- run: go build ./...
```

**After (safe):**

```yaml
- run: go mod download
- run: go mod verify        # checksum-DB cross-check; fails fast on tampered source
- run: go vet ./...
- run: go build ./...
```

Source: https://go.dev/ref/mod

## Version notes

- `go.work` (Go 1.18+) workspaces let multi-module repos share dependency graphs without a top-level `replace` directive. Workspaces are dev-time only — `go.work` is git-ignored by convention; never commit a `go.work` to a release branch.
- `govulncheck` (golang.org/x/vuln/cmd/govulncheck) requires Go 1.18+. The reachability-based filtering it performs is more precise than naive version matching; sec-review's cve-enricher does the version-level OSV match by default, and a future `go-runner` extension may add govulncheck for symbol-level reachability.
- `GOPROXY=direct` bypasses the module mirror (`proxy.golang.org`) entirely. Acceptable for fully air-gapped environments with a private mirror; for internet-connected builds, use `GOPROXY=https://proxy.golang.org,direct` (the comma-fallback chain).
- The Go vulnerability DB at `vuln.go.dev` is OSV-mirrored, so the cve-enricher's OSV `querybatch` pass against the `Go` ecosystem entry already covers it without an adapter change.

## Common false positives

- `replace` directives in test-only `go.mod` files (e.g. under `tests/integration/go.mod`) — these never reach release builds; downgrade.
- `+incompatible` versions for genuinely stable pre-modules dependencies (e.g. some `github.com/Sirupsen/logrus` legacy pins) — note the gap but acknowledge no upstream alternative; INFO not HIGH.
- A monorepo with a top-level `vendor/` and per-service `go.mod` files where the `vendor/` is NOT used (informational artefact only) — verify build mode before flagging.
