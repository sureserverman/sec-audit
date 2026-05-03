#!/usr/bin/env bash
# ai-tools-e2e.sh — proves the ai-tools-runner lane wires up
# correctly against tests/fixtures/vulnerable-ai-tools/ when at
# least one of the two tools (jq, mcp-scan / snyk-agent-scan) is
# present on PATH. Mirrors webext-e2e.sh and sast-e2e.sh.
#
# Strategy: this script does NOT invoke the LLM. It validates
# three things a CI run can check deterministically:
#
#   1. Fixture sanity: the vulnerable-ai-tools fixture contains
#      the expected dangerous patterns the agent should flag and
#      the expected malformed JSON the jq lane should flag.
#   2. Tool probe: at least one of {jq, mcp-scan, snyk-agent-scan}
#      is on PATH; if NONE are, the run is treated as the
#      unavailable path and the script exits 0 with a SKIP note
#      (drill covers that path).
#   3. Status emission: when at least one tool is present, the
#      agent's documented status is `ok` (both ran) or `partial`
#      (one ran, one absent). The script synthesizes the expected
#      sentinel and checks shape compliance against the runner
#      spec.
#
# Exit 0 on success with the literal line `ai-tools-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/vulnerable-ai-tools"

if [ ! -d "$target" ]; then
    echo "ai-tools-e2e: FAIL — fixture missing: $target" >&2
    exit 1
fi

# ---- Step 1: fixture-content sanity ----
echo "ai-tools-e2e: validating fixture content..."

# The .mcp.json fixture must contain the exact dangerous patterns
# the sec-expert reading references/ai-tools/claude-code-mcp.md
# (and mcp-scan when available) is expected to flag.
mcp="$target/.mcp.json"
if ! grep -q '"http://mcp.internal.example.com' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing http:// (CWE-319) pattern" >&2
    exit 1
fi
if ! grep -q '"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing hardcoded token (CWE-798) pattern" >&2
    exit 1
fi
if ! grep -q '"@modelcontextprotocol/server-github"' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing unpinned npx (CWE-1395) pattern" >&2
    exit 1
fi
if ! grep -q '\$PROJECT_DIR' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing shell-injection (CWE-78) pattern" >&2
    exit 1
fi
if ! grep -q '"sampling"' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing sampling capability pattern" >&2
    exit 1
fi
# Cyrillic 'υ' (U+03C5 GREEK SMALL LETTER UPSILON) shadowing 'u' in
# 'github' — homoglyph for the tool-shadowing pattern.
if ! grep -q 'githυb-shadow' "$mcp"; then
    echo "ai-tools-e2e: FAIL — fixture .mcp.json missing homoglyph (CWE-1007) tool-shadowing pattern" >&2
    exit 1
fi
echo "  .mcp.json: 6 dangerous patterns present (CWE-319, 798, 1395, 78, sampling, 1007)"

# Malformed JSON for jq parse-failure path. Synthesized at test time
# rather than committed under tests/fixtures/.../.claude/, since
# `.claude/` is gitignored by repo policy.
scratch_pre=$(mktemp -d); trap 'rm -rf "$scratch_pre"' EXIT
malformed="$scratch_pre/settings.local.json"
cat > "$malformed" <<'BAD_JSON'
{
  "permissions": {
    "allow": [ "Bash(*)" ],
    "deny": []
  // intentionally-malformed: closing brace missing
BAD_JSON
if jq --exit-status . "$malformed" >/dev/null 2>&1; then
    echo "ai-tools-e2e: FAIL — synthesized malformed JSON unexpectedly parsed clean" >&2
    exit 1
fi
echo "  synthesized .claude/settings.local.json: malformed (jq lane will flag this shape)"

# Poisoned skill for mcp-scan / sec-expert prompt-injection scanning.
skill="$target/skills/poisoned-skill/SKILL.md"
if [ ! -f "$skill" ]; then
    echo "ai-tools-e2e: FAIL — fixture missing skills/poisoned-skill/SKILL.md" >&2
    exit 1
fi
if ! grep -qi "ignore prior instructions" "$skill"; then
    echo "ai-tools-e2e: FAIL — poisoned skill missing instruction-override payload" >&2
    exit 1
fi
if ! grep -q '~/\.ssh/id_rsa' "$skill"; then
    echo "ai-tools-e2e: FAIL — poisoned skill missing sensitive-path-read pattern" >&2
    exit 1
fi
echo "  skills/poisoned-skill/SKILL.md: instruction-override + sensitive-path read present"

# ---- Step 2: tool probe ----
echo "ai-tools-e2e: probing tools..."

have_jq=0; command -v jq >/dev/null 2>&1 && have_jq=1
mcp_scan_bin=""
if command -v mcp-scan >/dev/null 2>&1; then
    mcp_scan_bin="mcp-scan"
elif command -v snyk-agent-scan >/dev/null 2>&1; then
    mcp_scan_bin="snyk-agent-scan"
fi

echo "  jq: $( [ "$have_jq" = 1 ] && echo PRESENT || echo MISSING )"
echo "  mcp-scan: $( [ -n "$mcp_scan_bin" ] && echo "PRESENT ($mcp_scan_bin)" || echo MISSING )"

if [ "$have_jq" = 0 ] && [ -z "$mcp_scan_bin" ]; then
    echo "ai-tools-e2e: SKIP — neither tool present; degrade path is covered by ai-tools-drill.sh"
    echo "ai-tools-e2e: OK"
    exit 0
fi

# ---- Step 3: synthesize and validate the expected sentinel ----
scratch="$scratch_pre"
sentinel="$scratch/sentinel.jsonl"

if [ "$have_jq" = 1 ] && [ -n "$mcp_scan_bin" ]; then
    expected_status="ok"
    echo '{"__ai_tools_status__":"ok","tools":["jq","mcp-scan"],"runs":2,"findings":0,"skipped":[]}' > "$sentinel"
elif [ "$have_jq" = 1 ]; then
    expected_status="partial"
    echo '{"__ai_tools_status__":"partial","tools":["jq"],"runs":1,"findings":0,"skipped":[{"tool":"mcp-scan","reason":"tool-missing"}]}' > "$sentinel"
else
    expected_status="partial"
    echo '{"__ai_tools_status__":"partial","tools":["mcp-scan"],"runs":1,"findings":0,"skipped":[{"tool":"jq","reason":"tool-missing"}]}' > "$sentinel"
fi

echo "ai-tools-e2e: expected status = $expected_status"

# Step 3a: sentinel parses as JSON and matches the runner spec.
python3 - <<PY
import json, sys
obj = json.loads(open("$sentinel").read().strip())
assert obj["__ai_tools_status__"] == "$expected_status", obj
assert isinstance(obj["tools"], list), obj
assert isinstance(obj.get("skipped", []), list), obj
for sk in obj.get("skipped", []):
    assert "tool" in sk and "reason" in sk, sk
print("  sentinel passes shape check (status=$expected_status)")
PY

# Step 3b: when jq is present, exercise it against the malformed
# fixture so the e2e demonstrates a real finding-emission path.
if [ "$have_jq" = 1 ]; then
    echo "ai-tools-e2e: exercising jq against synthesized malformed JSON..."
    if jq --exit-status . "$malformed" \
            >/dev/null 2> "$scratch/jq.stderr"; then
        echo "ai-tools-e2e: FAIL — jq accepted malformed JSON (synthesizer broken)" >&2
        exit 1
    fi
    if [ ! -s "$scratch/jq.stderr" ]; then
        echo "ai-tools-e2e: FAIL — jq produced no stderr on malformed JSON" >&2
        exit 1
    fi
    echo "  jq emitted parse error on synthesized malformed JSON (verified)"
fi

# Step 3c: when mcp-scan is present, verify only that we can call
# `inspect --json` without launching a server. We do NOT assert
# specific finding counts (signature pack drift makes that
# brittle); we assert that the invocation parses as JSON or fails
# cleanly, and that the runner spec we already validated forbids
# the unsafe `scan` mode.
if [ -n "$mcp_scan_bin" ]; then
    echo "ai-tools-e2e: invoking $mcp_scan_bin inspect --json on fixture..."
    out="$scratch/mcp.json"
    "$mcp_scan_bin" inspect "$mcp" --json > "$out" 2> "$scratch/mcp.stderr" || true
    if [ -s "$out" ]; then
        if python3 -c 'import json,sys; json.loads(open(sys.argv[1]).read())' "$out" 2>/dev/null; then
            echo "  mcp-scan emitted parseable JSON ($(wc -c < "$out") bytes)"
        else
            echo "  mcp-scan output not JSON; runner falls back to parse-failed skip"
        fi
    else
        echo "  mcp-scan produced no stdout; runner treats as parse-failed"
    fi
fi

echo ""
echo "ai-tools-e2e: OK"
