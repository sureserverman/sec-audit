# vulnerable-secrets fixture

Deliberately-leaky fixture for sec-audit's **secrets lane** (v1.21.0+).
Exercises gitleaks (working-tree scan) and trufflehog (git-history scan).

## Every secret here is FAKE

None of these credentials are real or valid. They are syntactically shaped to
trip the scanners but authenticate to nothing:

| File | Secret | Notes |
|------|--------|-------|
| `.env` | `AKIAZK5FAKEXAMPLE123` | Fake AWS access-key ID (matches `AKIA[0-9A-Z]{16}`). |
| `.env` | `wJalrFAKE…` | Fake AWS secret access key. |
| `app/config.py` | `tok_live_FAKE…zz` | Fake hardcoded generic API token. |

## Recorded golden

`.pipeline/secrets.jsonl` is the recorded golden output the e2e validates. It
was produced from the raw tool fixtures at
`tests/fixtures/raw-tool-output/secrets/` mapped through the engine. It contains
four findings (two gitleaks, two trufflehog) and the trailing
`__secrets_status__` sentinel.

The `deleted_secrets.txt` file referenced by a trufflehog finding in the golden
does NOT exist in the working tree on purpose: it represents a secret that was
committed and later deleted from HEAD but is still recoverable from git history
— exactly the class of leak a working-tree-only scan misses and trufflehog's
history scan catches.

## Redaction canary

The raw trufflehog fixture (`raw-tool-output/secrets/trufflehog.json`) carries a
canary string `CANARY_RAW_SECRET` in its `Raw` (plaintext) field. The redaction
invariant is that this canary is mapped away and NEVER appears in emitted
findings. `tests/secrets-e2e.sh` asserts the canary count in the golden is zero.
