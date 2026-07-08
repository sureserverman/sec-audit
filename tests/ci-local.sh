#!/usr/bin/env bash
# ci-local.sh — canonical hermetic test set for sec-audit.
#
# This is the SINGLE SOURCE OF TRUTH for what CI runs: .github/workflows/ci.yml
# invokes exactly `bash tests/ci-local.sh` and nothing else, so the local run and
# the CI run cannot drift. Every test here is hermetic — bash + python3 (stdlib)
# + jq only, no network, no external scanners, no pip install. The scanner-backed
# lanes are exercised through recorded fixtures and scrubbed-PATH degrade paths,
# never by invoking the real tools.
#
# Usage: bash tests/ci-local.sh
# Exit:  0 = all green; 1 = one or more failed (names listed).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

pass=0; fail=0; failed=""
run() {  # label, command...
  local label="$1"; shift
  if "$@" >"/tmp/ci-local-$label.log" 2>&1; then
    pass=$((pass+1)); printf '  PASS  %s\n' "$label"
  else
    fail=$((fail+1)); failed="$failed $label"
    printf '  FAIL  %s (see /tmp/ci-local-%s.log)\n' "$label" "$label"
  fi
}

echo "=== deterministic script suites ==="
for t in contract-check script-runner script-score script-inventory script-cve-enricher; do
  run "$t" bash "tests/$t.sh"
done

echo "=== per-lane e2e (recorded golden fixtures) ==="
for f in tests/*-e2e.sh; do
  run "$(basename "$f" .sh)" bash "$f"
done

echo "=== per-lane drills (scrubbed-PATH degrade contract) ==="
for f in tests/*-drill.sh; do
  run "$(basename "$f" .sh)" bash "$f"
done

echo ""
echo "ci-local: PASS=$pass FAIL=$fail"
if [ "$fail" -ne 0 ]; then
  echo "ci-local: FAILED:$failed" >&2
  exit 1
fi
echo "ci-local: OK"
