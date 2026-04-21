#!/usr/bin/env bash
# measure-pipeline.sh — convert a per-agent tokens JSON into a cost figure.
#
# Usage:
#   measure-pipeline.sh <tokens.json>          # human-readable table
#   measure-pipeline.sh --json <tokens.json>   # machine-readable JSON
#
# Input shape (array of objects):
#   [{"agent":"sec-expert","model":"sonnet","total_tokens":34792, ...}, ...]
#
# Rates come from tests/model-costs.json (blended_per_mtok per model).
# Runtime only exposes total_tokens, so we cost at the blended rate — this is
# the honest number given the available signal. When per-call input/output
# becomes visible, swap to the input_per_mtok + output_per_mtok fields.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
costs="$here/model-costs.json"

json_mode=0
if [ "${1:-}" = "--json" ]; then
    json_mode=1
    shift
fi

tokens_file="${1:-}"
if [ -z "$tokens_file" ] || [ ! -f "$tokens_file" ]; then
    echo "usage: $0 [--json] <tokens.json>" >&2
    exit 2
fi

json=$(jq --slurpfile c "$costs" '
    def rate($m): ($c[0][$m].blended_per_mtok // error("unknown model: "+$m));
    {
        per_agent: (map({
            agent: .agent,
            model: .model,
            tokens: .total_tokens,
            cost_usd: (.total_tokens / 1000000 * rate(.model) | . * 10000 | round / 10000)
        })),
        total_usd: (map(.total_tokens / 1000000 * rate(.model)) | add | . * 10000 | round / 10000),
        total_tokens: (map(.total_tokens) | add)
    }' "$tokens_file")

if [ "$json_mode" -eq 1 ]; then
    echo "$json"
    exit 0
fi

echo "Per-agent cost (blended rate — runtime exposes only total_tokens)"
echo
printf "%-20s %-8s %10s %10s\n" "agent" "model" "tokens" "cost USD"
printf "%-20s %-8s %10s %10s\n" "--------------------" "--------" "----------" "----------"
echo "$json" | jq -r '.per_agent[] | [.agent, .model, (.tokens|tostring), (.cost_usd|tostring)] | @tsv' \
    | while IFS=$'\t' read -r a m t c; do
        printf "%-20s %-8s %10s %10s\n" "$a" "$m" "$t" "\$$c"
      done
printf "%-20s %-8s %10s %10s\n" "--------------------" "--------" "----------" "----------"
printf "%-20s %-8s %10s %10s\n" "TOTAL" "" "$(echo "$json" | jq -r .total_tokens)" "\$$(echo "$json" | jq -r .total_usd)"
