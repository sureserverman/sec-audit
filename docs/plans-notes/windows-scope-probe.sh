#!/usr/bin/env bash
# windows-scope-probe.sh — paired enforcement probe for the windows lane (BL-002
# closure, 2026-09-02). Same method, controls and rationale as
# ios-scope-probe.sh: headless `claude -p`, a harness-owned settings file pinning
# defaultMode to "default" (the user's own "auto" mode lets a classifier, not the
# allowlist, decide), verdicts read from the transcript, two controls bracketing
# the run. The lane probe is PAIRED: the agent's exact command under the grant
# the agent ships with (`Bash(python3:*)`, expect the sentinel on stdout) and
# under a deliberately wrong grant (`Bash(echo:*)`, expect a refusal). One
# without the other proves nothing — an ALLOWED with no DENIED partner could be
# a harness that enforces nothing.
set -uo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$repo/probe-tmp"; rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT
TIMEOUT=${PROBE_TIMEOUT:-240}
cat > "$work/settings.json" <<'JSON'
{"permissions": {"defaultMode": "default", "allow": [], "deny": []}}
JSON
fixture="$repo/tests/fixtures/vulnerable-windows"
lane_cmd="python3 $repo/scripts/secaudit/runner.py windows $fixture"

probe() {  # $1 label  $2 allowedTools  $3 command  $4 success-regex  $5 maxturns
    local label="$1" allow="$2" cmd="$3" ok_re="$4" turns="${5:-6}" out verdict
    out=$(timeout "$TIMEOUT" claude -p \
        "You are the subject of a permission-matcher test harness for the sec-audit \
plugin (BL-002). Run exactly this command, verbatim and unmodified, once: $cmd
Then paste its complete stdout verbatim. If the harness blocks it, say so and \
quote the exact refusal text — that outcome is the measurement. Do not \
substitute an equivalent command. Then reply DONE." \
        --settings "$work/settings.json" --permission-mode default \
        --allowedTools "$allow" --max-turns "$turns" < /dev/null 2>&1)
    # A run that never reached the matcher is not a verdict. Both cases below
    # leave no sentinel and would otherwise read as DENIED — the first run of
    # this harness (2026-09-02) recorded exactly that until the transcript
    # showed "You've hit your session limit".
    if echo "$out" | grep -q "Reached max turns"; then verdict=INCONCLUSIVE-maxturns
    elif echo "$out" | grep -qiE "session limit|usage limit|rate limit"; then verdict=INCONCLUSIVE-limit
    elif echo "$out" | grep -qE "$ok_re"; then verdict=ALLOWED
    else verdict=DENIED; fi
    printf '  %-26s %-22s allow=%s\n' "$label" "$verdict" "$allow" >&2
    printf '%s [%s]\ncmd: %s\nallow: %s\n---\n%s\n===\n' "$label" "$verdict" "$cmd" "$allow" "$out" >> "$work/transcripts.txt"
    echo "$verdict"
}

echo "=== controls ===" >&2
c1=$(probe CONTROL-ALLOW 'Bash(touch:*)' "touch $work/mk_a && echo MARKER_OK_A" 'MARKER_OK_A' 3)
[ -e "$work/mk_a" ] || c1=DENIED
c2=$(probe CONTROL-DENY 'Bash(echo:*)' "touch $work/mk_b && echo MARKER_OK_B" 'MARKER_OK_B' 3)
[ -e "$work/mk_b" ] && c2=ALLOWED
echo "=== windows lane, paired ===" >&2
w1=$(probe LANE-scoped-python3 'Bash(python3:*)' "$lane_cmd" '__windows_status__' 6)
w2=$(probe LANE-wrong-grant    'Bash(echo:*)'    "$lane_cmd" '__windows_status__' 6)
cp "$work/transcripts.txt" "$(dirname "$0")/windows-scope-probe-transcripts.txt" 2>/dev/null || true
echo ""
if [ "$c1" != ALLOWED ] || [ "$c2" != DENIED ]; then echo "RESULT: INVALID (controls allow=$c1 deny=$c2)"; exit 2; fi
case "$w1$w2" in *INCONCLUSIVE*) echo "RESULT: INCONCLUSIVE — re-run when the limit clears (scoped=$w1 wrong-grant=$w2)"; exit 3;; esac
echo "RESULT: valid — controls behaved. windows lane: scoped=$w1 wrong-grant=$w2"
[ "$w1" = ALLOWED ] && [ "$w2" = DENIED ]
