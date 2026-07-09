#!/usr/bin/env bash
# c-cpp-drill.sh — v1.26.0 degrade drill for the c-cpp lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false uname; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ] && ln -s "$resolved" "$stub_bin/$cmd"
done
scrubbed_path="$stub_bin"

echo "c-cpp-drill: testing PATH scrub..."
for tool in cppcheck flawfinder; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "c-cpp-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides cppcheck/flawfinder"

echo "c-cpp-drill: testing c-cpp-runner spec..."
grep -q '"__c_cpp_status__": "unavailable"' "$plugin_root/agents/c-cpp-runner.md" || { echo "c-cpp-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in cppcheck flawfinder; do
    grep -q "command -v $tool" "$plugin_root/agents/c-cpp-runner.md" || { echo "c-cpp-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-c-source; do
    grep -q "$reason" "$plugin_root/agents/c-cpp-runner.md" || { echo "c-cpp-drill: FAIL — missing $reason" >&2; exit 1; }
done

# Live degrade path: PATH scrubbed to python3-only, the engine's command -v
# probes both fail, so the lane emits the unavailable sentinel and nothing else.
empty="$scratch/empty"; mkdir -p "$empty"
stub2="$scratch/stub2"; mkdir -p "$stub2"; ln -sf "$(command -v python3)" "$stub2/python3"
last=$(PATH="$stub2" python3 "$plugin_root/scripts/secaudit/runner.py" c-cpp "$empty" 2>/dev/null | tail -n1)
echo "$last" | jq -e '.__c_cpp_status__ == "unavailable" and (.tools == [])' >/dev/null \
    || { echo "c-cpp-drill: FAIL — live degrade sentinel wrong: $last" >&2; exit 1; }
echo "  live scrubbed-PATH run -> unavailable sentinel"

offline_out="$scratch/c-cpp-offline.jsonl"
echo '{"__c_cpp_status__": "unavailable", "tools": [], "skipped": [{"tool": "cppcheck", "reason": "tool-missing"}, {"tool": "flawfinder", "reason": "tool-missing"}]}' > "$offline_out"
[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__c_cpp_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "c-cpp"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

# Target-shape clean-skip vocabulary parseable.
clean_skip='{"__c_cpp_status__": "partial", "tools": ["cppcheck"], "skipped": [{"tool": "flawfinder", "reason": "no-c-source"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "tool-missing" or .reason == "no-c-source")' >/dev/null \
    || { echo "c-cpp-drill: FAIL — target-shape skip-reason vocabulary not parseable" >&2; exit 1; }

echo ""
echo "c-cpp-drill: OK"
