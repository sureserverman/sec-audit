# Malicious Packages (dependency malware, typosquatting, dependency confusion)

## Source

- https://github.com/ossf/malicious-packages — OpenSSF Malicious Packages (the curated dataset behind OSV `MAL-` advisories)
- https://owasp.org/www-project-dependency-check/ — OWASP dependency analysis guidance
- https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html — OWASP npm Security Cheat Sheet (install scripts, lockfiles, scopes)
- https://slsa.dev/spec/v1.0/ — SLSA v1.0 (provenance + build integrity against compromised releases)
- https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain — CISA software supply-chain guidance
- https://docs.pypi.org/attestations/ — PyPI Trusted Publishing + attestations
- https://github.blog/2021-02-12-avoiding-npm-substitution-attacks/ — npm dependency-confusion / substitution attacks (origin of the class)
- https://cwe.mitre.org/ — CWE index

## Scope

Covers the *malicious dependency* threat class for PyPI and npm projects
(GuardDog's ecosystems): install-time code execution, obfuscated/downloaded
payloads, exfiltration, typosquatting, dependency-confusion / substitution,
and compromised releases of otherwise-legitimate packages. This is the
behavioural / hygiene complement to the feed-based detection that
`cve-enricher` (OSV `MAL-` advisories) and the `supply-chain` tool lane
(GuardDog + OSV-Scanner) perform. Out of scope: known-CVE enrichment (the
`cve-feeds.md` pack), SBOM generation (`supply-chain/sbom.md`), provenance
signing (`supply-chain/slsa.md`, `supply-chain/sigstore.md`), and version
pinning hygiene (`supply-chain/dep-pinning.md`) — those are sibling packs.

## Dangerous patterns (regex/AST hints)

### Install-time code execution in npm lifecycle scripts — CWE-506

- Why: npm runs `preinstall` / `install` / `postinstall` scripts with the
  developer's privileges at `npm install` time. A compromised or malicious
  package uses these hooks to execute a payload before any application code
  imports it — the most common npm malware vector.
- Grep: `"(pre|post)?install"\s*:\s*".*(curl|wget|node\s+-e|base64|child_process|eval)`
- File globs: `**/package.json`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html

### Arbitrary code in `setup.py` / `setup.cfg` at build time — CWE-94

- Why: `pip install` executes `setup.py` (sdist) on the installing machine. A
  package whose `setup.py` calls `os.system`, `subprocess`, `exec`, or
  fetches and runs a remote payload achieves install-time RCE before import.
- Grep: `setup\.py` containing `os\.system|subprocess\.|exec\(|urlopen|requests\.get\(.*\)\.(content|text)`
- File globs: `**/setup.py`, `**/setup.cfg`
- Source: https://github.com/ossf/malicious-packages

### Obfuscated / encoded payloads in a dependency — CWE-506

- Why: base64/hex/XOR-encoded blobs decoded and `exec`'d at runtime are a
  hallmark of dependency malware hiding its true behaviour from review.
- Grep: `(exec|eval)\s*\(\s*(base64|codecs\.decode|bytes\.fromhex|Buffer\.from)`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`
- Source: https://github.com/ossf/malicious-packages

### Typosquatting / dependency-confusion candidate names — CWE-1357

- Why: a dependency one edit-distance from a popular package (`reqeusts`,
  `python-sqlite`, `crossenv`), or an *internal* package name resolvable from
  the *public* registry, lets an attacker substitute their package for the
  intended one. Dependency confusion exploits installers that prefer the
  higher public version over the private one.
- Grep: dependency names closely matching a top-package list, or unscoped
  names that look internal (`@company/...` declared but resolvable publicly)
- File globs: `**/package.json`, `**/requirements.txt`, `**/pyproject.toml`
- Source: https://github.blog/2021-02-12-avoiding-npm-substitution-attacks/

## Secure patterns

```jsonc
// package.json — disable lifecycle scripts for dependencies in CI installs.
// npm: install with --ignore-scripts; allow-list the few packages that
// genuinely need a build step.
{
  "scripts": { "preinstall": "echo 'no third-party install scripts'" }
}
// CI: npm ci --ignore-scripts
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html

```ini
# pip — install only from the intended index and pin hashes so a substituted
# (dependency-confusion) artifact with the same name cannot be installed.
# requirements.txt:
requests==2.32.3 --hash=sha256:<digest>
# Use a single trusted index; do not let an internal name resolve from PyPI.
```

Source: https://docs.pypi.org/attestations/

## Fix recipes

### Recipe: Disable third-party install scripts — addresses CWE-506

**Before (dangerous):**

```bash
npm install            # runs every dependency's pre/post-install hooks
```

**After (safe):**

```bash
npm ci --ignore-scripts     # no dependency lifecycle scripts run
# Then run only vetted, explicitly-needed build steps yourself.
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html

### Recipe: Defeat dependency confusion — addresses CWE-1357

**Before (dangerous):**

```
# .npmrc absent / registry unset — npm resolves @acme/* from the public
# registry, where an attacker has published a higher version.
```

**After (safe):**

```ini
# .npmrc — bind the private scope to the private registry; public registry
# never serves @acme/* names.
@acme:registry=https://registry.acme.internal/
//registry.acme.internal/:_authToken=${ACME_TOKEN}
```

Source: https://github.blog/2021-02-12-avoiding-npm-substitution-attacks/

### Recipe: Detect a compromised release — addresses CWE-506

**Before (dangerous):**

```
# Floating range silently pulls a freshly-compromised release.
"ua-parser-js": "^0.7.0"
```

**After (safe):**

```
# Pin exact version + integrity hash (lockfile); verify SLSA provenance /
# Sigstore attestation where the registry publishes it before bumping.
"ua-parser-js": "0.7.33"   // + package-lock.json integrity sha512-…
```

Source: https://slsa.dev/spec/v1.0/

## Version notes

- npm ≥ 7 writes `package-lock.json` v2/v3 with `integrity` hashes for the
  full graph — required for the pin-and-verify recipe above.
- pip ≥ 22 supports `--require-hashes`; combine with a single `--index-url`.
- PyPI Trusted Publishing + attestations (2024+) and npm provenance (2023+)
  let consumers verify a release was built from the claimed source — prefer
  packages that publish them for high-value dependencies.

## Common false positives

- A `postinstall` that only rebuilds a native addon (`node-gyp rebuild`) on a
  well-known package — expected; flag only when paired with network/exec
  obfuscation.
- An internal package whose name resembles a public one but resolves from a
  correctly-scoped private registry — typosquat heuristics fire but the
  resolution path is safe; downgrade.
- `exec`/`eval` in a code-generation or templating *library* whose documented
  purpose is dynamic execution — judge by whether the dependency is one your
  app deliberately uses for that, not a transitive surprise.
