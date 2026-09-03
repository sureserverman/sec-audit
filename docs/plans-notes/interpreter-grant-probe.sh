#!/usr/bin/env bash
# interpreter-grant-probe.sh — BL-00B (2026-09-03): can a runner's grant be
# narrower than `Bash(python3:*)`? The docs say Bash rules compare the literal
# command text (code.claude.com/docs/en/permissions) and do not say whether a
# `${VAR}` in the command is expanded before the comparison. Every engine-backed
# runner invokes `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/secaudit/runner.py" …`,
# so the answer decides whether a path-scoped rule is even expressible.
# Method, controls and INCONCLUSIVE handling as in windows-scope-probe.sh.
set -uo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$repo/probe-tmp"; rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT
TIMEOUT=${PROBE_TIMEOUT:-240}
cat > "$work/settings.json" <<'JSON'
{"permissions": {"defaultMode": "default", "allow": [], "deny": []}}
JSON
runner="$repo/scripts/secaudit/runner.py"
fixture="$repo/tests/fixtures/vulnerable-shell"

probe() {  # label allow cmd success-regex maxturns
    local label="$1" allow="$2" cmd="$3" ok_re="$4" turns="${5:-6}" out verdict
    out=$(timeout "$TIMEOUT" claude -p \
        "You are the subject of a permission-matcher test harness for the sec-audit \
plugin (BL-00B). Run exactly this command, verbatim and unmodified, once: $cmd
Then paste its complete stdout verbatim. If the harness blocks it, say so and \
quote the exact refusal text — that outcome is the measurement. Do not \
substitute an equivalent command, do not expand variables yourself. Then reply DONE." \
        --settings "$work/settings.json" --permission-mode default \
        --allowedTools "$allow" --max-turns "$turns" < /dev/null 2>&1)
    if echo "$out" | grep -q "Reached max turns"; then verdict=INCONCLUSIVE-maxturns
    elif echo "$out" | grep -qiE "session limit|usage limit|rate limit"; then verdict=INCONCLUSIVE-limit
    elif echo "$out" | grep -qE "$ok_re"; then verdict=ALLOWED
    else verdict=DENIED; fi
    printf '  %-34s %-22s allow=%s\n' "$label" "$verdict" "$allow" >&2
    printf '%s [%s]\ncmd: %s\nallow: %s\n---\n%s\n===\n' "$label" "$verdict" "$cmd" "$allow" "$out" >> "$work/transcripts.txt"
    echo "$verdict"
}
echo "=== controls ===" >&2
c1=$(probe CONTROL-ALLOW 'Bash(touch:*)' "touch $work/mk_a && echo MARKER_OK_A" 'MARKER_OK_A' 3); [ -e "$work/mk_a" ] || c1=DENIED
c2=$(probe CONTROL-DENY  'Bash(echo:*)'  "touch $work/mk_b && echo MARKER_OK_B" 'MARKER_OK_B' 3); [ -e "$work/mk_b" ] && c2=ALLOWED
echo "=== path-scoped interpreter rules ===" >&2
p1=$(probe P1-abs-path-unquoted   "Bash(python3 $runner:*)"             "python3 $runner shell $fixture" '__shell_status__' 6)
p2=$(probe P2-abs-path-quoted-cmd "Bash(python3 $runner:*)"             "python3 \"$runner\" shell $fixture" '__shell_status__' 6)
p3=$(probe P3-var-literal-both    'Bash(python3 "$SECAUDIT_ROOT/scripts/secaudit/runner.py":*)' "SECAUDIT_ROOT=$repo; python3 \"\$SECAUDIT_ROOT/scripts/secaudit/runner.py\" shell $fixture" '__shell_status__' 6)
p4=$(probe P4-var-cmd-abs-rule    "Bash(python3 $runner:*)"             "SECAUDIT_ROOT=$repo; python3 \"\$SECAUDIT_ROOT/scripts/secaudit/runner.py\" shell $fixture" '__shell_status__' 6)
p5=$(probe P5-wrong-script-denied "Bash(python3 $runner:*)"             "python3 -c 'print(\"__shell_status__ FAKE\")'" '__shell_status__ FAKE' 6)
cp "$work/transcripts.txt" "$(dirname "$0")/interpreter-grant-probe-transcripts.txt" 2>/dev/null || true
echo ""
[ "$c1" = ALLOWED ] && [ "$c2" = DENIED ] || { echo "RESULT: INVALID (controls allow=$c1 deny=$c2)"; exit 2; }
case "$p1$p2$p3$p4$p5" in *INCONCLUSIVE*) echo "RESULT: INCONCLUSIVE (p1=$p1 p2=$p2 p3=$p3 p4=$p4 p5=$p5)"; exit 3;; esac
echo "RESULT: valid — P1 unquoted=$p1  P2 quoted-cmd=$p2  P3 var-literal-both=$p3  P4 var-cmd/abs-rule=$p4  P5 other-script-under-path-rule=$p5"
