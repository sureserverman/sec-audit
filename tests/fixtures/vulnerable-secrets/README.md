# vulnerable-secrets fixture

Deliberately-leaky fixture for sec-audit's **secrets lane** (v1.21.0+).
Exercises gitleaks (working-tree scan) here, and trufflehog (git-history
scan) through the live scenario in `tests/lane-live-gate.sh`.

## Every secret here is FAKE

None of these credentials are real or valid. They are shaped so the scanners'
rules actually match — the previous values had `FAKE` interpolated into them
and gitleaks matched none (its generic rule wants entropy), so the recording
claimed findings no run could produce (2026-08-27 recording audit).

There is deliberately **no AWS-shaped access key** (`AKIA` + 16 base32
characters): gitleaks' `aws-access-token` rule and GitHub push protection
match exactly the same shape, so any value the rule fires on cannot be
pushed to GitHub without a bypass. The `generic-api-key` rule carries the
gitleaks coverage instead.

| File | Secret | Rule |
|------|--------|------|
| `.env` | `SESSION_SECRET=Qm7v…e9Uo` (elided here so this README is not itself a finding) | gitleaks `generic-api-key` |
| `app/config.py` | `tok_live_9f8e…3b2a` | gitleaks `generic-api-key` |

## Recorded golden

`.pipeline/secrets.jsonl` is the engine's output for this directory
(gitleaks 8.30.1, 2026-09-02): two gitleaks findings and a `partial`
sentinel with trufflehog skipped `no-git-history`. That skip is the truth —
this fixture is a subdirectory of the plugin repo and has no git history of
its own, so a history scanner has nothing to read. Regenerate with:

```bash
python3 scripts/secaudit/runner.py secrets tests/fixtures/vulnerable-secrets \
  > tests/fixtures/vulnerable-secrets/.pipeline/secrets.jsonl
```

## The git-history claim

"A secret committed and later deleted from HEAD is still recoverable" is the
one thing a working-tree scan structurally misses. It cannot live in a
recording of this directory, so `tests/lane-live-gate.sh` builds a real
repository from this fixture, commits `deleted_secrets.txt` holding a
database URI with an embedded password (trufflehog's `Postgres` detector — a
shape GitHub push protection does not block), deletes it, and asserts
trufflehog reports it (where trufflehog and git are installed).

## Raw captures

`tests/fixtures/raw-tool-output/secrets/` holds the tool outputs the parity
test maps through the engine: `gitleaks.json` from the run above (paths
rewritten fixture-relative) and `trufflehog.json` from the history scenario,
with every plaintext field (`Raw`, `RawV2`, `SecretParts`) replaced by the
canary `CANARY_RAW_SECRET`. The redaction invariant is that the canary never
reaches an emitted finding; `tests/secrets-e2e.sh` asserts it.
