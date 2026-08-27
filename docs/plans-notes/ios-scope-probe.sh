#!/usr/bin/env bash
# ios-scope-probe.sh — second-generation matcher probe (2026-08-27).
#
# matcher-probe.sh (2026-07-25) answered the three questions that blocked
# BL-002. This one probes the constructs the SIX EXEMPT RUNNERS actually
# contain, and in doing so corrects one of that run's conclusions and finds the
# blocker neither run had isolated.
#
# Method, controls and rationale are inherited verbatim from matcher-probe.sh:
# headless `claude -p`, a harness-owned settings file pinning defaultMode to
# "default" (the user's own settings use "auto", where a safety classifier and
# not the allowlist decides — that invalidated an entire earlier run), verdicts
# read from a marker file on disk rather than the model's prose, and two
# controls bracketing every run.
#
# TWO ADDITIONAL CONTROLS THIS HARNESS ADDS, both learned from bad verdicts it
# produced before they existed:
#   * max-turns exhaustion is reported INCONCLUSIVE, never DENIED. A probe that
#     ran out of turns leaves no marker and is otherwise indistinguishable from
#     a denial; one such run was initially recorded as a matcher fact.
#   * every DENIED construct is re-probed under a BARE `Bash` grant. A construct
#     refused under both is not a scoping blocker at all — it is already broken
#     today under the grant the six runners ship with. Two verdicts flipped
#     meaning under this control.
# Markers live in a NON-HIDDEN dir inside the repo: a dot-directory drew a
# working-directory refusal that had nothing to do with the allowlist.
set -uo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$repo/probe-tmp"; rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT
TIMEOUT=${PROBE_TIMEOUT:-120}

cat > "$work/settings.json" <<'JSON'
{"permissions": {"defaultMode": "default", "allow": [], "deny": []}}
JSON

failharness=0; declare -a RESULTS

probe() {  # $1 label  $2 allowedTools  $3 command  $4 marker  $5 maxturns
    local label="$1" allow="$2" cmd="$3" marker="$work/$4" turns="${5:-6}"
    rm -f "$marker"; local out rc verdict
    out=$(timeout "$TIMEOUT" claude -p \
        "You are the subject of a permission-matcher test harness for the sec-audit \
plugin (BL-002). We are measuring which bash constructs Claude Code's tool \
allowlist permits. Please run exactly this command, verbatim and unmodified, \
once: $cmd
It only touches scratch files inside this repo's probe-tmp/ directory. If the \
harness blocks it, say so and quote the exact refusal text — that outcome is \
the measurement. Do not substitute an equivalent command. Then reply DONE." \
        --settings "$work/settings.json" --permission-mode default \
        --allowedTools "$allow" --max-turns "$turns" < /dev/null 2>&1)
    rc=$?
    if [ -e "$marker" ]; then verdict=ALLOWED; else verdict=DENIED; fi
    echo "$out" | grep -q "Reached max turns" && verdict=INCONCLUSIVE-maxturns
    RESULTS+=("$label|$verdict|$allow|$cmd")
    printf '  %-28s %-22s (rc=%s)\n' "$label" "$verdict" "$rc" >&2
    printf '%s [%s]\ncmd: %s\nallow: %s\n---\n%s\n===\n' \
        "$label" "$verdict" "$cmd" "$allow" "$out" >> "$work/transcripts.txt"
    echo "$verdict"
}

echo "=== controls: prove the harness actually enforces ===" >&2
c1=$(probe CONTROL-ALLOW 'Bash(touch:*)' "touch $work/mk_a" mk_a 3)
c2=$(probe CONTROL-DENY  'Bash(echo:*)'  "touch $work/mk_b" mk_b 3)
[ "$c1" = ALLOWED ] && [ "$c2" = DENIED ] || {
    echo "HARNESS INVALID: controls allow=$c1 deny=$c2" >&2; failharness=1; }

echo "" >&2; echo "=== A. the [ ] gate: does a VARIABLE in the test change the verdict? ===" >&2
# 2026-07-25 Q1 concluded "[ is not separately matched; no Bash([:*) needed
# anywhere". It tested `[ -f X ]`. Every real runner gate is `[ "$var" = ... ]`.
probe A1-bracket-literal  'Bash(touch:*)'             "[ -f /etc/hostname ] && touch $work/mk_a1" mk_a1 3 >/dev/null
probe A2-bracket-variable 'Bash(touch:*)'             "[ \"\$HOME\" != \"\" ] && touch $work/mk_a2" mk_a2 3 >/dev/null
probe A3-bracket-granted  'Bash(touch:*),Bash([:*)'   "[ \"\$HOME\" != \"\" ] && touch $work/mk_a3" mk_a3 3 >/dev/null

echo "" >&2; echo "=== B. output redirection under a scoped allowlist ===" >&2
probe B1-plain-redirect-scoped 'Bash(echo:*),Bash(touch:*)' \
    "echo hi > $work/plain.txt && touch $work/mk_b1" mk_b1 6 >/dev/null
probe B2-plain-redirect-bare   'Bash' \
    "echo hi > $work/plain2.txt && touch $work/mk_b2" mk_b2 6 >/dev/null
probe B3-cmdsub-redirect-scoped 'Bash(echo:*),Bash(basename:*),Bash(touch:*)' \
    "echo ok > \"$work/ios-\$(basename /tmp/Vuln.app).txt\" && touch $work/mk_b3" mk_b3 6 >/dev/null
probe B4-cmdsub-redirect-bare   'Bash' \
    "echo ok > \"$work/ios2-\$(basename /tmp/Vuln.app).txt\" && touch $work/mk_b4" mk_b4 6 >/dev/null

echo "" >&2; echo "=== C. pipes, with and without a redirect (isolates B from the pipe) ===" >&2
probe C1-pipe-noredirect-scoped 'Bash(find:*),Bash(head:*),Bash(touch:*)' \
    "find $repo/tests -maxdepth 1 -type f -name '*.sh' | head -n 10 && touch $work/mk_c1" mk_c1 6 >/dev/null
probe C2-pipe-redirect-scoped   'Bash(find:*),Bash(head:*),Bash(touch:*)' \
    "find $repo/tests -maxdepth 1 -type f -name '*.sh' | head -n 10 > $work/list.txt && touch $work/mk_c2" mk_c2 6 >/dev/null

echo "" >&2; echo "=== D. assignment from a command substitution (ios Step 3) ===" >&2
probe D1-assign-cmdsub 'Bash(uname:*),Bash(echo:*),Bash(touch:*)' \
    "host_os=\$(uname -s 2>/dev/null || echo Unknown) && touch $work/mk_d1" mk_d1 6 >/dev/null

echo "" >&2; echo "=== matrix ==="
printf '%s\n' "${RESULTS[@]}" | while IFS='|' read -r l v a c; do
    printf '  %-28s %-22s  allow=%-46s cmd=%s\n' "$l" "$v" "$a" "$c"
done
cp "$work/transcripts.txt" "$(dirname "$0")/ios-scope-probe-transcripts.txt" 2>/dev/null || true
echo ""
[ "$failharness" -eq 0 ] || { echo "RESULT: INVALID (controls failed)"; exit 2; }
echo "RESULT: valid — controls behaved, verdicts above are enforcement facts"
