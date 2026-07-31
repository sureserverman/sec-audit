#!/usr/bin/env bash
# supply-chain-guarddog-map.sh — pins the guarddog field mapping against the
# shape guarddog actually emits.
#
# Why this exists: supply-chain-e2e.sh reads a PRE-RECORDED
# `.pipeline/supply-chain.jsonl`, so it validates the output contract but never
# runs guarddog. That let the npm mapping drift out of sync with guarddog's real
# output — the lane reported `ok` with zero findings while guarddog itself was
# reporting issues. A silent false negative in a malicious-package detector is
# the worst failure this lane has, so the mapping gets its own test.
#
# Two properties, both of which failed before v1.36.2:
#   1. guarddog's rule-keyed `result.results` object maps to findings at all
#      (it is a dict of rule -> hits, not an array; `flatten` had to learn it).
#   2. Only reputation rules become findings. `threat-*` and `capability-*` fire
#      on ordinary packages — lodash and requests each tripped 43 `threat-*`
#      rules — so emitting them buries real signal under HIGH-severity noise.
#
# Exit 0 with the literal line `supply-chain-guarddog-map: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

python3 - "$plugin_root" <<'PY'
import json, sys, os
plugin_root = sys.argv[1]
sys.path.insert(0, os.path.join(plugin_root, "scripts"))
from secaudit import runner

lane = json.load(open(os.path.join(
    plugin_root, "scripts/secaudit/lanes/supply-chain.json")))

# Verbatim shape from `guarddog <eco> verify --output-format json`.
payload = [
  {"dependency": "python-sqlite", "version": "0.1.0", "result": {
      "issues": 2, "errors": {}, "results": {
        "typosquatting": [{"message": "Package name resembles 'pysqlite3'"}],
        "capability-network-outbound": [{"message": "makes outbound calls"}],
        "threat-network-reverse-shell": [{"message": "looks like a reverse shell"}],
        "metadata_mismatch": [{"message": "repo URL does not match"}],
        "deceptive_author": None}}},
  {"dependency": "requests", "version": "2.32.3", "result": {
      "issues": 3, "errors": {}, "results": {
        "typosquatting": None,
        "capability-filesystem-delete": [{"message": "deletes files"}],
        "threat-runtime-system-info": [{"message": "reads system info"}]}}},
]

def collect(tool):
    out = []
    for block in runner._blocks(tool):
        fp = block.get("findings_path")
        base = (runner._get(payload, fp) or []) if fp else payload
        for leaf, parent in runner._flatten(base, block.get("flatten")):
            ctx = leaf if parent is None else {**leaf, "_parent": parent}
            if not runner._passes_filter(block.get("filter"), ctx):
                continue
            out.append(runner.map_item(lane, tool, block, ctx))
    return out

names = [t["name"] for t in lane["tools"] if t["name"].startswith("guarddog-")]
assert sorted(names) == ["guarddog-go", "guarddog-npm", "guarddog-pypi"], names
print("  ecosystems wired: %s" % ", ".join(sorted(names)))

for name in names:
    tool = [t for t in lane["tools"] if t["name"] == name][0]
    found = collect(tool)
    ids = sorted(f["id"] for f in found)
    assert ids == ["metadata_mismatch", "typosquatting"], f"{name}: {ids}"
    assert all(not f["id"].startswith(("threat-", "capability-")) for f in found), \
        f"{name}: threat/capability noise leaked into findings"
    byid = {f["id"]: f for f in found}
    assert byid["typosquatting"]["severity"] == "HIGH", name
    assert byid["metadata_mismatch"]["severity"] == "MEDIUM", name
    assert byid["typosquatting"]["file"] == "python-sqlite@0.1.0", \
        f"{name}: package@version lost: {byid['typosquatting']['file']}"
    print("  %-14s 2 reputation findings, 0 noise, package@version intact" % name)

print("  a rule whose value is null (deceptive_author) yields no finding")
PY

echo "supply-chain-guarddog-map: OK"
