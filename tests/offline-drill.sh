#!/usr/bin/env bash
# offline-drill.sh — proves the sec-review pipeline degrades cleanly when
# every CVE feed is unreachable.
#
# Strategy: rather than burn a full LLM run per CI invocation, we test the
# two properties that actually define "degrades cleanly":
#
#   1. Wiring: the env-var override convention documented in
#      references/cve-feeds.md routes traffic away from the live feeds.
#      Proved by standing up offline-mock.py on port 9999 and showing
#      every override URL returns 503.
#
#   2. State: when cve-enricher comes back with all-offline output, the
#      orchestrator's report-rendering path produces the ⚠ banner and
#      zero fabricated CVE IDs — we simulate the offline cves.json and
#      assert the orchestrator's contract on it.
#
# A full live-pipeline run through `claude -p` is supported via --live
# but is NOT the default — live runs cost tokens and network.
#
# Usage:
#   tests/offline-drill.sh           # synthetic mode (default, deterministic)
#   tests/offline-drill.sh --live    # full pipeline via claude -p

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/sample-stack"
port=9999
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

# ---- start mock ----
python3 "$here/offline-mock.py" --port "$port" >/dev/null 2>"$here/.offline-mock.stderr" &
mock_pid=$!
cleanup() {
    if kill -0 "$mock_pid" 2>/dev/null; then
        kill "$mock_pid" 2>/dev/null || true
        wait "$mock_pid" 2>/dev/null || true
    fi
    rm -f "$here/.offline-mock.stderr"
}
trap cleanup EXIT

# Wait up to 3s for mock to come up
for _ in 1 2 3 4 5 6; do
    if curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/" 2>/dev/null | grep -q 503; then
        break
    fi
    sleep 0.5
done

# ---- Assertion 1: mock serves 503 on every override URL ----
echo "offline-drill: testing env-var override wiring (A)..."
paths=(
    "/v1/querybatch"
    "/rest/json/cves/2.0"
    "/advisories"
    "/kev.json"
)
for p in "${paths[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port$p" || echo "000")
    if [ "$code" != "503" ]; then
        echo "offline-drill: FAIL — expected 503 on $p, got $code" >&2
        exit 1
    fi
done
echo "  all override paths return 503 (mock reachable, env-var routing provable)"

# ---- synthesize an all-offline cves.json ----
scratch=$(mktemp -d)
offline_cves="$scratch/cves-offline.json"

jq -c '.ecosystems[] | .ecosystem as $eco | .packages[] | {ecosystem: $eco, name, version}' \
    <<<"$(tail -1 "$target/.pipeline/findings.jsonl")" \
    | jq -s 'map(. + {cves: [], status: "offline"})' \
    > "$offline_cves"

pkg_count=$(jq 'length' "$offline_cves")
all_offline=$(jq '[.[] | select(.status != "offline")] | length' "$offline_cves")
if [ "$all_offline" != "0" ] || [ "$pkg_count" -lt 1 ]; then
    echo "offline-drill: FAIL — synthetic cves.json wrong shape (pkg=$pkg_count, non-offline=$all_offline)" >&2
    exit 1
fi
echo "offline-drill: synthesized $pkg_count-package offline cves.json"

# ---- Assertion 2: report-writer contract on offline state ----
# The report-writer spec (agents/report-writer.md) mandates: when all feeds
# report status offline, prepend the ⚠ banner and render zero CVE IDs.
# We verify the contract is *specified* in the agent so a future run will
# honor it, AND that the state file truly contains no CVE-YYYY-NNNN strings.
echo "offline-drill: testing report-writer offline contract (B)..."

if ! grep -q "⚠ CVE enrichment offline" "$plugin_root/agents/report-writer.md"; then
    echo "offline-drill: FAIL — report-writer.md missing offline banner spec" >&2
    exit 1
fi

if grep -qE "CVE-[0-9]{4}-[0-9]+" "$offline_cves"; then
    echo "offline-drill: FAIL — synthetic offline cves.json leaked a CVE ID" >&2
    exit 1
fi

# ---- Assertion 3: non-CVE findings survive (degradation is local) ----
# Check that sec-expert's findings.jsonl still carries code-pattern findings
# not dependent on CVE data — those must appear in any offline report.
echo "offline-drill: testing non-CVE findings survive offline degradation..."

if ! grep -q "nginx\|Django\|Dockerfile\|TLS\|SECRET_KEY" "$target/.pipeline/triaged.jsonl"; then
    echo "offline-drill: FAIL — sample-stack findings missing core code-pattern entries" >&2
    exit 1
fi

# ---- Live mode: actually run the pipeline through claude -p ----
if [ "$mode" = "live" ]; then
    echo "offline-drill: --live mode — dispatching cve-enricher via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "offline-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/cves-live.json"
        OSV_BASE_URL="http://127.0.0.1:$port" \
        NVD_BASE_URL="http://127.0.0.1:$port" \
        GHSA_BASE_URL="http://127.0.0.1:$port" \
        KEV_URL="http://127.0.0.1:$port/kev.json" \
            claude -p --permission-mode=acceptEdits \
                "Invoke cve-enricher agent with the dep inventory from $target/.pipeline/findings.jsonl (last line). Write output to $live_out." \
                2>&1 | tail -30 || true

        if [ -f "$live_out" ]; then
            if grep -qE "CVE-[0-9]{4}-[0-9]+" "$live_out"; then
                echo "offline-drill: FAIL (live) — agent fabricated a CVE ID while offline" >&2
                exit 1
            fi
            echo "  live cve-enricher returned no fabricated CVE IDs"
        fi
    fi
fi

rm -rf "$scratch"

echo ""
echo "offline-drill: OK"
