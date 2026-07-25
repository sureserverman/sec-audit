#!/usr/bin/env bash
# matcher-probe.sh — determine, under REAL permission enforcement, how Claude
# Code's Bash matcher treats three constructs the sec-audit runners rely on.
#
# BL-002 was deferred precisely because these could not be answered from docs or
# by reading the matcher; scoping the six host-OS runners blind risks silently
# breaking a lane in a security tool. This harness answers them mechanically.
#
# Method: run `claude -p` headless with a NARROW allowlist and ask it to run one
# exact command. Each probe's command touches a unique marker file on success, so
# the outcome is read from the filesystem — a side effect — not from the model's
# prose, which could claim anything.
#
# WHY THE SETTINGS OVERRIDE (learned the hard way, 2026-07-25):
# the first run of this harness reported CONTROL-DENY as ALLOWED. Cause: the
# user's ~/.claude/settings.json sets `permissions.defaultMode: "auto"`, in which
# a safety classifier — not the allowlist — decides each command. A `touch` was
# judged safe and ran despite an allowlist of only Bash(echo:*). Every probe
# verdict in that run was meaningless. So this harness writes its OWN settings
# file pinning defaultMode to "default" and passes --permission-mode default; in
# headless -p a non-allowed tool cannot prompt, so it is denied. That is the
# strict enforcement BL-002 needs to observe.
#
# Two controls bracket every run:
#   CONTROL-ALLOW  a command squarely inside the allowlist  -> marker MUST appear
#   CONTROL-DENY   a command squarely outside it            -> marker MUST NOT
# If either control misbehaves the harness is not enforcing and every other
# result is meaningless — the script says so and exits non-zero rather than
# reporting findings it cannot stand behind.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# Markers MUST live inside the repo: this environment's sandbox restricts writes
# to the project dir, so a /tmp marker is blocked by the SANDBOX and looks
# identical to a matcher denial. That confound invalidated the first two runs.
work="$here/.probe-tmp"; rm -rf "$work"; mkdir -p "$work"; trap 'rm -rf "$work"' EXIT
TIMEOUT=${PROBE_TIMEOUT:-120}

# Strict-enforcement settings: no auto classifier, no inherited allowances.
cat > "$work/settings.json" <<'JSON'
{"permissions": {"defaultMode": "default", "allow": [], "deny": []}}
JSON

failharness=0
declare -a RESULTS

probe() {  # $1 label  $2 allowedTools  $3 command  $4 marker  -> echoes verdict
    local label="$1" allow="$2" cmd="$3" marker="$work/$4"
    rm -f "$marker"
    local out rc verdict
    # Honest, contextual prompt. An earlier version demanded an unexplained
    # `touch` of a file named *_deny and the model correctly refused it as an
    # unverifiable sentinel — a REFUSAL, not a matcher denial, which would have
    # been recorded as a fake enforcement fact.
    out=$(timeout "$TIMEOUT" claude -p \
        "You are the subject of a permission-matcher test harness for the sec-audit \
plugin (BL-002). We are measuring which bash constructs Claude Code's tool \
allowlist permits. Please run exactly this command, verbatim and unmodified, \
once: $cmd
It only touches a scratch file inside this repo's .probe-tmp/ directory. If the \
harness blocks it, just say so — that outcome is the measurement. Do not \
substitute an equivalent command. Then reply DONE." \
        --settings "$work/settings.json" \
        --permission-mode default \
        --allowedTools "$allow" --max-turns 3 2>&1)
    rc=$?
    if [ -e "$marker" ]; then verdict=ALLOWED; else verdict=DENIED; fi
    RESULTS+=("$label|$verdict|$allow|$cmd")
    # progress to STDERR so command substitution captures only the verdict
    printf '  %-16s %-8s (rc=%s)\n' "$label" "$verdict" "$rc" >&2
    printf '%s [%s]\n---\n%s\n===\n' "$label" "$verdict" "$out" >> "$work/transcripts.txt"
    echo "$verdict"
}

echo "=== controls: prove the harness actually enforces ===" >&2
c1=$(probe CONTROL-ALLOW 'Bash(touch:*)' "touch $work/mk_a" mk_a)
c2=$(probe CONTROL-DENY  'Bash(echo:*)'  "touch $work/mk_b"  mk_b)
if [ "$c1" != ALLOWED ] || [ "$c2" != DENIED ]; then
    echo "" >&2
    echo "HARNESS INVALID: controls returned allow=$c1 deny=$c2 (expected ALLOWED/DENIED)." >&2
    echo "Enforcement is not behaving as assumed; no probe result below can be trusted." >&2
    failharness=1
fi

echo "" >&2
echo "=== Q1: is [ a gated command? ===" >&2
# linux/netcfg/ai-tools runners gate work behind `[ … ] && …`. If `[` is itself
# matched, every such gate needs Bash([:*) in the allowlist.
probe Q1-bracket 'Bash(touch:*)' "[ -f /etc/hostname ] && touch $work/mk_1" mk_1 >/dev/null

echo "" >&2
echo "=== Q2: is the inner command of a process substitution gated? ===" >&2
# macos-runner uses `< <(cat …)`. If the inner `cat` is matched it needs Bash(cat:*).
probe Q2-procsub 'Bash(diff:*),Bash(touch:*)' \
     "diff <(cat /etc/hostname) /etc/hostname >/dev/null && touch $work/mk_2" mk_2 >/dev/null
# control for Q2: same shape WITH cat granted — isolates the process-sub variable
probe Q2-procsub-catok 'Bash(diff:*),Bash(touch:*),Bash(cat:*)' \
     "diff <(cat /etc/hostname) /etc/hostname >/dev/null && touch $work/mk_2b" mk_2b >/dev/null

echo "" >&2
echo "=== Q3: can a variable command name ever match a rule? ===" >&2
# ai-tools-runner invokes mcp-scan as "$mcp_scan_bin". No Bash(...) rule can name
# a variable, so either enforcement blocks it or it slips through unmatched.
probe Q3-varcmd 'Bash(touch:*)' "cmd=touch; \"\$cmd\" $work/mk_3" mk_3 >/dev/null
# control for Q3: the same command spelled literally MUST be allowed
probe Q3-literal 'Bash(touch:*)' "touch $work/mk_3b" mk_3b >/dev/null

echo "" >&2
echo "=== matrix ==="
printf '%s\n' "${RESULTS[@]}" | while IFS='|' read -r l v a c; do
    printf '  %-20s %-8s  allow=%-40s cmd=%s\n' "$l" "$v" "$a" "$c"
done
cp "$work/transcripts.txt" "$here/matcher-probe-transcripts.txt" 2>/dev/null || true
echo ""
echo "transcripts: $here/matcher-probe-transcripts.txt"
[ "$failharness" -eq 0 ] || { echo "RESULT: INVALID (controls failed)"; exit 2; }
echo "RESULT: valid — controls behaved, verdicts above are enforcement facts"
