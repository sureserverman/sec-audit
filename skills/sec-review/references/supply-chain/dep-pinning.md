# Dependency Pinning and Lockfiles

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html — OWASP Third-Party JavaScript Management Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html — OWASP Vulnerable Dependency Management Cheat Sheet
- https://www.cisa.gov/resources-tools/resources/sbom-types — CISA SBOM resources (dependency tracking context)
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 (supply chain risk for container images)

## Scope

Covers lockfile hygiene, version pinning strategies, and supply-chain risks for npm/yarn (JavaScript), pip/poetry (Python), Cargo (Rust), Go modules, and Maven/Gradle (Java). Includes typosquatting and dependency-confusion attack vectors. Does not cover SBOM generation (see `supply-chain/sbom.md`) or build-artifact signing (see `supply-chain/sigstore.md`).

## Dangerous patterns (regex/AST hints)

### Lockfile absent from version control — CWE-829

- Why: Without a committed lockfile, `npm install` / `pip install` / `cargo build` can silently resolve to a newer (potentially malicious or vulnerable) version of a transitive dependency.
- Grep: Check for absence of `package-lock.json`, `yarn.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`, `requirements.txt` (with hashes)
- File globs: `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `pom.xml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

### Wildcard or overly broad version range — CWE-829

- Why: Ranges like `*`, `>=1.0`, or `^` (npm) / `~=` (pip) allow automatic upgrades to unreviewed versions that may introduce vulnerabilities or malicious code.
- Grep: `"[a-z\-]+"\s*:\s*"\*"|"[a-z\-]+"\s*:\s*">=\d|"[a-z\-]+"\s*:\s*"latest"`
- File globs: `package.json`, `requirements.txt`, `pyproject.toml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

### pip install without hash checking — CWE-494

- Why: `pip install` without `--require-hashes` does not verify the integrity of downloaded packages; a compromised PyPI mirror or CDN can serve altered packages.
- Grep: `pip install(?!.*--require-hashes)(?!.*-r requirements)`
- File globs: `Dockerfile`, `*.sh`, `.github/workflows/*.yml`, `Makefile`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

### Private package name without scoped registry — CWE-427

- Why: An unscoped package name (e.g. `internal-utils`) published only to a private registry can be hijacked via dependency confusion: an attacker publishes a higher-versioned package with the same name to the public registry, which package managers prefer by default.
- Grep: `"internal[-_]|"corp[-_]|"company[-_]` in `dependencies` or `devDependencies`
- File globs: `package.json`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

### GitHub Actions workflow pinned to branch/tag not digest — CWE-829

- Why: `uses: actions/checkout@v4` can be updated by the action author without notice; pinning to a commit SHA (`@sha256:...` or `@<full-commit-sha>`) prevents silent substitution.
- Grep: `uses:\s+[\w/-]+@(?![\da-f]{40})[^\s#]+`
- File globs: `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

## Secure patterns

npm: pin exact versions and commit lockfile, with `npm ci` in CI:

```json
{
  "dependencies": {
    "express": "4.19.2",
    "lodash": "4.17.21"
  },
  "engines": { "node": ">=20.0.0" }
}
```

```bash
# CI — never use npm install in CI; use npm ci which enforces lockfile
npm ci --ignore-scripts
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

Python: requirements.txt with hashes (generate with `pip-compile --generate-hashes`):

```
django==5.0.4 \
    --hash=sha256:abc123... \
    --hash=sha256:def456...
psycopg2-binary==2.9.9 \
    --hash=sha256:789...
```

```bash
pip install --require-hashes -r requirements.txt
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

GitHub Actions: pin actions to full commit SHA:

```yaml
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
  - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4.4.0
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

npm scoped private registry (prevent dependency confusion):

```json
{
  "name": "@mycompany/internal-utils",
  "publishConfig": {
    "registry": "https://registry.mycompany.internal"
  }
}
```

```bash
# .npmrc
@mycompany:registry=https://registry.mycompany.internal
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

## Fix recipes

### Recipe: Add lockfile hash verification to pip install — addresses CWE-494

**Before (dangerous):**

```dockerfile
RUN pip install -r requirements.txt
```

**After (safe):**

```dockerfile
COPY requirements.txt .
RUN pip install --require-hashes --no-deps -r requirements.txt
```

Generate the hashes file with: `pip-compile --generate-hashes requirements.in`

Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

### Recipe: Pin GitHub Actions to commit SHA — addresses CWE-829

**Before (dangerous):**

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
```

**After (safe):**

```yaml
steps:
  # actions/checkout v4.2.2
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
  # actions/setup-python v5.3.0
  - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

### Recipe: Replace npm wildcard versions with exact pins — addresses CWE-829

**Before (dangerous):**

```json
{
  "dependencies": {
    "axios": "^1.0.0",
    "lodash": "*"
  }
}
```

**After (safe):**

```json
{
  "dependencies": {
    "axios": "1.7.2",
    "lodash": "4.17.21"
  }
}
```

Then commit `package-lock.json` and use `npm ci` in CI pipelines.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

## Version notes

- npm 7+ generates `package-lock.json` lockfileVersion 2 with integrity hashes; lockfileVersion 1 (npm 6 and earlier) has weaker integrity guarantees.
- `poetry.lock` files embed content hashes for all resolved packages since Poetry 1.0; always commit the lockfile.
- `go.sum` provides cryptographic verification of module content since Go 1.11; removing or ignoring it is a supply-chain risk.
- Cargo.lock should be committed for binary crates (applications); the Cargo team recommends not committing it for library crates, but it is still advisable for reproducibility in CI.
- GitHub's Dependabot and Renovate both support automatic lockfile update PRs — prefer these over manual version bumps.

## Common false positives

- `"*"` in npm `peerDependencies` — peer dependency ranges are a compatibility declaration, not a resolution directive; the consuming project's lockfile determines the actual version installed.
- Broad version ranges in library `package.json` / `setup.cfg` — libraries intentionally use ranges to be compatible with multiple host project versions; flag pinning issues only in application-level manifests and CI configurations.
- `go.sum` with multiple checksums for the same module (h1: and h2:) — this is normal; both hash algorithms are recorded.
- Renovate/Dependabot PR branch names like `dependabot/npm_and_yarn/lodash-4.17.21` touching `package-lock.json` — automated lock updates are expected and safe if the PR pipeline runs tests.
