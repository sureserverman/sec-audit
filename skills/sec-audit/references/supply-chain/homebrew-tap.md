# Homebrew Tap (Formula / Cask supply-chain hygiene)

## Source

- https://docs.brew.sh/Formula-Cookbook — Homebrew Formula Cookbook (`sha256`, `url`, stable/HEAD blocks)
- https://docs.brew.sh/Cask-Cookbook — Homebrew Cask Cookbook (`sha256`, `url`, `verified`, `postflight`/`preflight`)
- https://docs.brew.sh/Acceptable-Formulae — acceptable-source / HTTPS-URL requirements
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security
- https://cwe.mitre.org/ — CWE index

## Scope

Covers the *install-recipe* supply-chain threat class for a Homebrew tap — a
git repo of Ruby `Formula/*.rb` and `Casks/*.rb` definitions that `brew`
executes on the user's machine. A malicious or careless recipe fetches an
artefact over an unauthenticated channel, skips integrity verification, or runs
arbitrary Ruby during install. This is the Homebrew analogue of
`supply-chain/malicious-packages.md` (npm/PyPI) and `supply-chain/dep-pinning.md`
(version pinning). Out of scope: the upstream project's own source review (its
language lane), and CVE enrichment of the packaged software (the `cve-feeds`
pack). Homebrew's own `brew audit --strict --online` and `brew style` are the
canonical tools; this pack is the pattern reference a future `homebrew` lane or
the sec-expert applies when no tap-scanning tool is on PATH.

## Dangerous patterns (regex/AST hints)

### Checksum verification disabled — CWE-494

- Why: `sha256 :no_check` (Cask) or a missing `sha256` (Formula) tells Homebrew to install the download without verifying its integrity. A MITM or a compromised mirror can then substitute an arbitrary payload that runs on the user's machine. `:no_check` is only defensible for a `version :latest` cask with no stable artefact — and even then it is a documented risk.
- Grep: `sha256\s+:no_check` or a `url` block with no accompanying `sha256`
- File globs: `Casks/*.rb`, `Formula/*.rb`
- Source: https://docs.brew.sh/Cask-Cookbook

### Cleartext (non-HTTPS) download URL — CWE-319

- Why: An `http://` (or `ftp://`) `url` fetches the artefact over an unauthenticated channel; combined with weak or absent checksum verification it is trivially MITM-able. Homebrew requires HTTPS for acceptable formulae.
- Grep: `url\s+["']http://` or `url\s+["']ftp://`
- File globs: `Casks/*.rb`, `Formula/*.rb`
- Source: https://docs.brew.sh/Acceptable-Formulae

### Unpinned moving-tag / branch URL — CWE-829

- Why: A `url` pointing at a moving ref (`.../archive/refs/heads/main.tar.gz`, `.../releases/latest/...`, or a `:branch =>`/`branch:` git checkout) resolves to different content over time, so the committed `sha256` either drifts out of sync (breaking installs) or, worse, is `:no_check`. Pin to a tagged release + its checksum.
- Grep: `url\s+["'][^"']*(refs/heads/|/latest/|/main\.|/master\.)` or `branch:\s*["']`
- File globs: `Casks/*.rb`, `Formula/*.rb`
- Source: https://docs.brew.sh/Formula-Cookbook

### Arbitrary install-time Ruby (postflight / preflight / install) — CWE-506

- Why: `postflight`, `preflight`, `uninstall_postflight`, and Formula `install`/`def install` blocks run arbitrary Ruby (and often shell out via `system`) on the user's machine with the invoking user's privileges. `system "curl", ... | "sh"`, writes outside the prefix, or `sudo` escalation inside these blocks are supply-chain execution hazards that reviewers must read line by line.
- Grep: `(postflight|preflight|uninstall_postflight)\s+do` or `system\s+["'](curl|wget|bash|sh)\b` or `\bsudo\b`
- File globs: `Casks/*.rb`, `Formula/*.rb`
- Source: https://docs.brew.sh/Cask-Cookbook

### Cask without `verified` on an anonymous host — CWE-345

- Why: A cask whose `url` host differs from its `homepage` should carry a `verified "host/path"` stanza asserting the maintainer checked the source. Its absence on a third-party download host (S3 bucket, personal domain, file-sharing service) means no human vouched for the artefact origin.
- Grep: a `url` on a host not matching `homepage`, with no `verified` stanza in the same cask block
- File globs: `Casks/*.rb`
- Source: https://docs.brew.sh/Cask-Cookbook

## Secure patterns

A Cask pinned to a tagged release with a real checksum and a verified source:

```ruby
cask "example-app" do
  version "1.4.0"
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  url "https://github.com/acme/example-app/releases/download/v#{version}/example-#{version}.dmg",
      verified: "github.com/acme/example-app/"
  name "Example App"
  homepage "https://github.com/acme/example-app"

  app "Example.app"
end
```

Source: https://docs.brew.sh/Cask-Cookbook

A Formula pinned to a release tarball + checksum, no install-time network fetch:

```ruby
class ExampleTool < Formula
  desc "Example CLI"
  homepage "https://github.com/acme/example-tool"
  url "https://github.com/acme/example-tool/archive/refs/tags/v1.4.0.tar.gz"
  sha256 "a1b2c3d4e5f6...<64 hex>"
  license "MIT"

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end
end
```

Source: https://docs.brew.sh/Formula-Cookbook

## Fix recipes

### Recipe: Replace `sha256 :no_check` with a pinned checksum — addresses CWE-494

**Before (dangerous):**

```ruby
cask "example-app" do
  version :latest
  sha256 :no_check
  url "https://downloads.example.com/example.dmg"
```

**After (safe):**

```ruby
cask "example-app" do
  version "1.4.0"
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  url "https://downloads.example.com/example-#{version}.dmg",
      verified: "downloads.example.com/"
```

Compute the checksum with `shasum -a 256 <file>` against the exact release you pin.

Source: https://docs.brew.sh/Cask-Cookbook

### Recipe: Switch a cleartext URL to HTTPS — addresses CWE-319

**Before (dangerous):**

```ruby
url "http://downloads.example.com/example-#{version}.dmg"
```

**After (safe):**

```ruby
url "https://downloads.example.com/example-#{version}.dmg"
```

Verify the HTTPS endpoint serves the identical artefact and re-pin the `sha256`.

Source: https://docs.brew.sh/Acceptable-Formulae

## Version notes

- `brew audit --strict --online <name>` checks checksum presence, HTTPS URLs, and license fields; `brew audit --new` applies the stricter new-formula ruleset. Run in CI against every tap PR.
- `brew style` (RuboCop-backed) catches some correctness issues but is primarily style; it is not a security scanner.
- Homebrew removed `sha256 :no_check` acceptance for most new casks; existing `:no_check` casks are grandfathered but flagged by `brew audit`.

## Common false positives

- `version :latest` + `sha256 :no_check` on a genuinely versionless auto-updating cask (some browsers, some Electron apps) — documented Homebrew practice; flag as INFO and confirm the upstream has no stable versioned artefact.
- `system` calls inside `def install` that only invoke the project's own build (`make`, `cmake`, `go build`) — expected; the hazard is network fetches or `sudo`, not building.
- A `url` host differing from `homepage` **with** a `verified` stanza present — that is the correct, reviewed pattern, not a finding.
