#!/usr/bin/env bash
# k8s-drill.sh — v1.1.0 degrade drill for the K8s lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-k8s"
mode="synthetic"
[ "${1:-}" = "--live" ] && mode="live"

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false xargs uname; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ] && ln -s "$resolved" "$stub_bin/$cmd"
done
scrubbed_path="$stub_bin"

echo "k8s-drill: testing PATH scrub..."
for tool in kube-score kubesec; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "k8s-drill: FAIL — $tool leaked at $found" >&2; exit 1; }
done
echo "  scrubbed PATH hides kube-score/kubesec"

echo "k8s-drill: testing k8s-runner spec..."
grep -q '"__k8s_status__": "unavailable"' "$plugin_root/agents/k8s-runner.md" || { echo "k8s-drill: FAIL — missing sentinel spec" >&2; exit 1; }
for tool in kube-score kubesec; do
    grep -q "command -v $tool" "$plugin_root/agents/k8s-runner.md" || { echo "k8s-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
grep -q "tool-missing" "$plugin_root/agents/k8s-runner.md" || { echo "k8s-drill: FAIL — missing tool-missing skip reason" >&2; exit 1; }

offline_out="$scratch/k8s-offline.jsonl"
echo '{"__k8s_status__": "unavailable", "tools": [], "skipped": [{"tool": "kube-score", "reason": "tool-missing"}, {"tool": "kubesec", "reason": "tool-missing"}]}' > "$offline_out"

total=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total" = "1" ] || { echo "k8s-drill: FAIL — expected 1 line" >&2; exit 1; }
[ "$(grep -c '"__k8s_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "k8s"' "$offline_out")" = "0" ] || exit 1
echo "  unavailable output shape OK"

jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null \
    || { echo "k8s-drill: FAIL — skipped entries malformed" >&2; exit 1; }
echo "  structured skipped entries OK"

if [ "$mode" = "live" ]; then
    echo "k8s-drill: --live mode skipped (claude CLI presumed absent in CI)"
fi

echo ""
echo "k8s-drill: OK"
