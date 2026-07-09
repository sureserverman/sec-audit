#!/usr/bin/env bash
# php-drill.sh — v1.27.0 degrade drill for the php lane.

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

echo "php-drill: testing PATH scrub..."
found=$(PATH="$scrubbed_path" command -v phpcs 2>/dev/null || true)
[ -z "$found" ] || { echo "php-drill: FAIL — phpcs leaked" >&2; exit 1; }
echo "  scrubbed PATH hides phpcs"

echo "php-drill: testing php-runner spec..."
grep -q '"__php_status__": "unavailable"' "$plugin_root/agents/php-runner.md" || { echo "php-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
grep -q "command -v phpcs" "$plugin_root/agents/php-runner.md" || { echo "php-drill: FAIL — missing command -v phpcs" >&2; exit 1; }
for reason in tool-missing no-php-source; do
    grep -q "$reason" "$plugin_root/agents/php-runner.md" || { echo "php-drill: FAIL — missing $reason" >&2; exit 1; }
done

# Live degrade path: PATH scrubbed to python3-only, the engine's command -v probe
# fails, so the lane emits the unavailable sentinel and nothing else.
empty="$scratch/empty"; mkdir -p "$empty"
stub2="$scratch/stub2"; mkdir -p "$stub2"; ln -sf "$(command -v python3)" "$stub2/python3"
last=$(PATH="$stub2" python3 "$plugin_root/scripts/secaudit/runner.py" php "$empty" 2>/dev/null | tail -n1)
echo "$last" | jq -e '.__php_status__ == "unavailable" and (.tools == [])' >/dev/null \
    || { echo "php-drill: FAIL — live degrade sentinel wrong: $last" >&2; exit 1; }
echo "  live scrubbed-PATH run -> unavailable sentinel"

offline_out="$scratch/php-offline.jsonl"
echo '{"__php_status__": "unavailable", "tools": [], "skipped": [{"tool": "phpcs", "reason": "tool-missing"}]}' > "$offline_out"
[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__php_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "php"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

# Target-shape clean-skip vocabulary parseable.
clean_skip='{"__php_status__": "unavailable", "tools": [], "skipped": [{"tool": "phpcs", "reason": "no-php-source"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "tool-missing" or .reason == "no-php-source")' >/dev/null \
    || { echo "php-drill: FAIL — target-shape skip-reason vocabulary not parseable" >&2; exit 1; }

echo ""
echo "php-drill: OK"
