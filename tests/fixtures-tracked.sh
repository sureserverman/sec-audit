#!/usr/bin/env bash
# fixtures-tracked.sh — every test fixture must be committed.
#
# Regression: tests/fixtures/depinv/cargo/Cargo.lock was matched by the generic
# `Cargo.lock` rule in .gitignore (added for Rust build output), so it existed
# on the author's disk and in no clone. script-depinv passed locally and failed
# on CI for as long as that was true, with the useful part of the error buried
# in a runner-local /tmp log that CI never uploaded.
#
# A fixture is test INPUT, not build output. This check treats "present on disk
# but not in the index" as a failure rather than something to notice later.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

fail=0
missing=0
checked=0

while IFS= read -r f; do
    checked=$((checked + 1))
    if ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
        reason="$(git check-ignore -v "$f" 2>/dev/null || true)"
        echo "fixtures-tracked: FAIL — untracked fixture: $f" >&2
        [ -n "$reason" ] && echo "                  ignored by: $reason" >&2
        missing=$((missing + 1))
        fail=1
    fi
done < <(find tests/fixtures -type f -not -path '*/.git/*' | sort)

[ "$checked" -gt 0 ] || { echo "fixtures-tracked: FAIL — no fixtures found; did the path move?" >&2; exit 1; }

if [ "$fail" -eq 0 ]; then
    echo "  all $checked fixture file(s) are tracked"
else
    echo "  $missing of $checked fixture file(s) would be missing from a clone" >&2
fi

# The specific file the regression removed, named so a future blanket ignore
# rule fails here with an explanation rather than as a lane assertion.
lock="tests/fixtures/depinv/cargo/Cargo.lock"
if [ -f "$lock" ]; then
    git ls-files --error-unmatch "$lock" >/dev/null 2>&1 || {
        echo "fixtures-tracked: FAIL — $lock is untracked again (check .gitignore)" >&2
        fail=1; }
    echo "  depinv cargo lockfile tracked (the file that broke CI)"
fi

[ "$fail" -eq 0 ] || exit 1
echo "fixtures-tracked: OK"
