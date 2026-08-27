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
# ONE DOCUMENTED EXCEPTION to the hermeticity above: `lane-live-gate`. Every
# other per-lane gate reads a recorded fixture, and the 2026-08-27 audit
# (docs/plans-notes/pipeline-recording-audit.md) found that two lanes had
# stopped working while the suite stayed green, because nothing in the e2e path
# executes a lane. That gate therefore RUNS every lane and asserts invariants of
# the run — never finding counts, which is what rotted the recordings. It uses
# whatever scanners happen to be installed: on CI none are, so each lane still
# executes end to end (engine, lane JSON, bundled wrappers, sentinel contract)
# and the stronger assertions simply do not engage. Set SECAUDIT_LIVE_GATE=0 to
# skip it and keep the run fully hermetic.
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
    # Print the tail inline. On CI that /tmp log is never uploaded, so a
    # failure used to arrive as a bare test name with the reason discarded —
    # script-depinv was red for days behind exactly that.
    printf '  ---- last 25 lines of %s ----\n' "$label"
    tail -n 25 "/tmp/ci-local-$label.log" 2>/dev/null | sed 's/^/  | /'
    printf '  ---- end %s ----\n' "$label"
  fi
}

echo "=== deterministic script suites ==="
for t in fixtures-tracked contract-check script-runner script-score script-inventory script-cve-enricher \
         script-sarif script-diffscope script-statehome script-statestore \
         script-fingerprint script-changeset script-deltas script-depinv script-versions \
         script-agentscan \
         script-advisory-cache script-accepted; do
  run "$t" bash "tests/$t.sh"
done

echo "=== per-lane live gate (executes every lane) ==="
run "lane-live-gate" bash tests/lane-live-gate.sh

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
