# GitHub Actions — Token Permissions and Action Pinning

## Source

- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions — GitHub Actions security hardening guide (canonical)
- https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs — workflow `permissions:` key reference and default-permission table
- https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target — `pull_request_target` event reference: when it is safe and when it is not
- https://docs.github.com/en/actions/security-guides/automatic-token-authentication — `GITHUB_TOKEN` lifecycle and permission inheritance rules
- https://github.com/marketplace/actions/checkout — actions/checkout reference (the source of `persist-credentials` defaults)
- https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas — pinning third-party actions by full-length commit SHA
- https://owasp.org/www-project-top-10-ci-cd-security-risks/ — OWASP CI/CD Top 10 (CICD-SEC-04 Poisoned Pipeline Execution; CICD-SEC-07 Insufficient PBAC)
- https://slsa.dev/spec/v1.0/requirements — SLSA v1.0 build-platform requirements (provenance + tamper-resistance)

## Scope

Covers GitHub Actions workflow files (`.github/workflows/*.yml`, `*.yaml`) that declare `on:` and `jobs:` keys: token-permission grants on the workflow / job level, `pull_request_target` checkout patterns that lead to arbitrary code execution by an external contributor, third-party action pinning (tag vs SHA), and `GITHUB_TOKEN` propagation into untrusted scripts. Out of scope: secret-injection patterns (covered by `gh-actions-secrets.md`); self-hosted runner host hardening (separate operational concern); composite-action authoring (separate scope — focus is on consumers, not authors); GitHub Enterprise Server-specific configuration (covers .com behaviour).

## Dangerous patterns (regex/AST hints)

### `permissions: write-all` at workflow or job scope — CWE-732

- Why: Setting `permissions: write-all` grants the workflow's `GITHUB_TOKEN` write access to every API surface (contents, packages, pull-requests, issues, deployments, security-events, statuses, actions). A compromised step — for instance, an `npm install` of a package whose dependency was hijacked, or a malicious GitHub Action — inherits write-all and can push to branches, publish packages, or modify protected resources. The least-privilege principle in GitHub's hardening guide is to declare an explicit, minimal `permissions:` block at workflow level (or job level when scopes differ) and grant only the surfaces the job actually uses.
- Grep: `^\s*permissions:\s*write-all\b`
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs

### Missing top-level `permissions:` key (relies on repository default) — CWE-732

- Why: When a workflow does not declare `permissions:`, the `GITHUB_TOKEN` inherits the repository's *default* permission set, which on legacy repositories is `read/write` to every scope (the "permissive" default). New repositories created after Feb 2023 default to read-only contents, but inherited workflows on long-lived repos may still operate under the permissive default. Explicit declaration removes the dependency on a UI setting an attacker can flip via repo-admin compromise.
- Grep: workflow files where neither the top-level nor any `jobs.<id>.` block contains `permissions:` (block-level scan; flag any workflow with zero `permissions:` keys).
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/security-guides/automatic-token-authentication

### `pull_request_target` + `actions/checkout` of `github.event.pull_request.head.ref` — CWE-94

- Why: `pull_request_target` runs in the *base* repository's context with full secrets and a write-capable `GITHUB_TOKEN`. If the workflow then checks out the *head* commit (the unreviewed PR code) and runs any of it — `npm install`, `make`, `bundle exec`, even a setup script — an external contributor whose PR has not been reviewed can execute arbitrary code with the base repo's secrets and token. This is the canonical "Poisoned Pipeline Execution" class (CICD-SEC-04). The safe pattern is to use the default `pull_request` event for any workflow that runs PR code, OR to keep `pull_request_target` for label/comment automation that does NOT check out untrusted code.
- Grep: workflows containing both `on:\s*pull_request_target` AND `actions/checkout` with a `ref: \${{\s*github\.event\.pull_request\.head\.(ref|sha)\s*}}` input.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target

### Third-party action referenced by mutable tag (`@v1`, `@main`) instead of full SHA — CWE-829

- Why: Tags on GitHub are mutable — the maintainer (or anyone who compromises the maintainer's account) can re-point `v1` at a malicious commit, and every consumer pulling `@v1` runs that commit on the next workflow run. Pinning by full 40-char commit SHA (with the human-readable tag in a trailing comment for upgrade tracking) makes the dependency immutable: a tag re-point cannot affect already-pinned consumers, and Dependabot will open a PR when a new SHA is available so the upgrade is visible and reviewable. GitHub's own security-hardening guide and SLSA v1.0 both recommend SHA-pinning for third-party actions.
- Grep: `uses:\s*([^/]+)/([^@]+)@([a-zA-Z0-9._-]+)` where the third capture is NOT a 40-char hex SHA. Exempt: actions in the `actions/` org (first-party, but pinning is still recommended) and reusable workflows from `./` (in-repo).
- File globs: `.github/workflows/*.y?(a)ml`, `.github/actions/**/action.y?(a)ml`
- Source: https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas

### Workflow grants `contents: write` without justification — CWE-732

- Why: `contents: write` lets the workflow push to branches, create tags, and modify the repository tree. A workflow that only builds and tests does NOT need `contents: write` — `contents: read` is sufficient. Granting write enables a compromised step to push a malicious commit, alter `.github/workflows/` to install a long-term backdoor, or create a release with substituted artifacts. Apply `contents: write` only on jobs that explicitly need to push (release-cutting jobs, tag-creating jobs, `actions/stale` cleanup).
- Grep: `permissions:` blocks containing `contents:\s*write` in a workflow that does NOT also reference any of: `git push`, `softprops/action-gh-release`, `actions/create-release`, `peter-evans/create-pull-request`, `JamesIves/github-pages-deploy-action`, `release:` event, or `tags:` push trigger.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs

### Workflow uses `workflow_run` to trigger from another workflow's outputs — CWE-345

- Why: `workflow_run` fires when a *named* workflow completes; the triggered workflow runs in the base-repo context and can be designed to react to artifacts the triggering workflow produced. If the triggering workflow ran on a fork (`pull_request` from a fork), its artifacts are *unsigned* and *attacker-controlled*, but the `workflow_run` event itself carries the `GITHUB_TOKEN` of the base repo. Reading and acting on those artifacts without integrity verification (signature check, content sanitisation) is a Poisoned Pipeline Execution variant. Pin the triggering workflow's source events to non-fork-eligible events (`push`, `schedule`), OR validate artifact signatures before consuming.
- Grep: `on:\s*workflow_run` blocks that reference `actions/download-artifact` AND do not include any of `actions/attest-build-provenance`, `cosign`, `gpg --verify`, or a custom signature-verification step.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://owasp.org/www-project-top-10-ci-cd-security-risks/

## Secure patterns

Minimal explicit `permissions:` block at workflow level, narrowed at job level when needed:

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: npm ci && npm test

  release:
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    permissions:
      contents: write   # narrowed here, not workflow-wide
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: ./publish.sh
```

Source: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs

Safe `pull_request_target` for label-only automation (no checkout of PR code):

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  pull-requests: write   # add labels, comment

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9  # v5.0.0
        # NOTE: no actions/checkout step — we never run PR code in this context.
```

Source: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target

## Fix recipes

### Recipe: replace `write-all` with explicit minimal scopes — addresses CWE-732

**Before (dangerous):**

```yaml
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

**After (safe):**

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: npm ci && npm test
```

Source: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs

### Recipe: pin third-party action by full SHA — addresses CWE-829

**Before (dangerous):**

```yaml
- uses: tj-actions/changed-files@v44
```

**After (safe):**

```yaml
- uses: tj-actions/changed-files@4c5f5d698fbf2d763b8c8fd0e16b6e9a7e6e2c1f  # v44.5.7
  # Dependabot will open a PR when a newer SHA exists; review and merge.
```

Source: https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas

### Recipe: separate `pull_request_target` triage from `pull_request` build — addresses CWE-94

**Before (dangerous):**

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build-and-label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # runs PR code with base secrets
      - run: npm ci && npm test
      - uses: actions/labeler@v5
```

**After (safe):**

```yaml
# Workflow A — runs PR code, but with no secrets and a read-only token.
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: npm ci && npm test

# Workflow B — has secrets but never checks out PR code.
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  pull-requests: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9  # v5.0.0
```

Source: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target

## Version notes

- The repository-default permission flip (read-only contents for new repos) landed in GitHub.com in February 2023. Long-lived repositories may still operate under the legacy permissive default — explicit declaration is the only way to be sure.
- `permissions:` keys at the workflow level apply to every job unless a job overrides them; job-level keys REPLACE the workflow-level set rather than merging, so an explicit minimal job-level block must enumerate every scope it needs.
- Dependabot's `version-updates` ecosystem `github-actions` automates SHA-pin upgrades only when actions are pinned by SHA in the first place — tag-pinned actions get tag-bump PRs, which defeats the immutability of the pin.

## Common false positives

- `permissions: read-all` — the *read-only* counterpart is safe and explicit; do not flag.
- `actions/checkout` without `ref:` under `pull_request_target` — without a ref override, checkout pulls the BASE branch, not the PR head; this is safe (the typical `actions/labeler` pattern). Only flag when `ref:` overrides to the PR head.
- First-party `actions/*` pinned by tag — first-party actions follow GitHub's own release process and are lower-risk than third-party; the pin-by-SHA recommendation still applies, but downgrade confidence to medium for `actions/checkout@v4`-shaped references.
- Reusable workflows referenced by `./.github/workflows/foo.yml` (in-repo) — these are NOT third-party and are safe by tag (they live in the same repo). The grep pattern excludes leading `./`.
