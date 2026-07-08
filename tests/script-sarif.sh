#!/usr/bin/env bash
# script-sarif.sh — verifies sarif.py emits valid GitHub-compatible SARIF 2.1.0
# from sec-audit scored findings. Uses the committed sample-stack triaged
# findings, scored through score.py (the real pipeline order), plus a synthetic
# line-0 finding to exercise region omission.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

triaged="tests/fixtures/sample-stack/.pipeline/triaged.jsonl"
[ -f "$triaged" ] || { echo "script-sarif: FAIL — missing $triaged" >&2; exit 1; }

# Build a scored findings array: triaged findings (strip any sentinel lines) +
# one synthetic line-0 finding (a DAST-style URI finding) to test region omit.
python3 - "$triaged" > "$scratch/findings.json" <<'PY'
import json, sys
rows = []
for l in open(sys.argv[1]):
    l = l.strip()
    if not l:
        continue
    o = json.loads(l)
    # drop pipeline sentinels: id-based (__dep_inventory__) and key-based (__*_status__)
    if o.get("id", "").startswith("__") or any(k.startswith("__") and k.endswith("_status__") for k in o):
        continue
    rows.append(o)
rows.append({"id": "dast-xcontenttype", "severity": "LOW", "cwe": "CWE-693",
             "title": "Missing X-Content-Type-Options header", "file": "https://app/",
             "line": 0, "evidence": "response lacked header", "origin": "dast",
             "tool": "zap-baseline"})
# A finding with NO title whose evidence carries a plaintext secret — message.text
# must fall back to the id, never the raw evidence.
rows.append({"id": "notitle-secret", "severity": "HIGH", "cwe": "CWE-798",
             "evidence": "api_key = 'SARIF_CANARY_PLAINTEXT'", "file": "x.py",
             "line": 5, "origin": "webapp", "tool": "bearer"})
json.dump(rows, sys.stdout)
PY

# Real pipeline order: score.py then sarif.py.
python3 scripts/secaudit/score.py < "$scratch/findings.json" \
    | python3 scripts/secaudit/sarif.py > "$scratch/out.sarif"

python3 - "$scratch/out.sarif" "$scratch/findings.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
findings = json.load(open(sys.argv[2]))

assert s["version"] == "2.1.0", s.get("version")
assert "$schema" in s and s["$schema"], "missing $schema"
assert isinstance(s["runs"], list) and len(s["runs"]) == 1, "expected exactly one run"
run = s["runs"][0]
assert run["tool"]["driver"]["name"] == "sec-audit", run["tool"]["driver"]["name"]

results = run["results"]
assert len(results) == len(findings), f"results {len(results)} != findings {len(findings)}"

# score.py sorts findings by score desc, so match results to findings by id
# (not position). Fixture ids are unique.
assert len({f["id"] for f in findings}) == len(findings), "fixture finding ids must be unique"
fmap = {f["id"]: f for f in findings}

LEVELS = {"error", "warning", "note", "none"}
sev_to_level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
by_rule = {}
for r in results:
    f = fmap[r["ruleId"]]
    assert r["level"] in LEVELS, r["level"]
    assert r["level"] == sev_to_level[f["severity"].upper()], (f["id"], r["level"], f["severity"])
    assert r["message"]["text"], "empty message"
    phys = r["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == (f.get("file") or "unknown"), (r["ruleId"], phys)
    # line 0 / missing -> region omitted; line > 0 -> region.startLine present
    line = f.get("line")
    if isinstance(line, int) and line > 0:
        assert phys["region"]["startLine"] == line, phys
    else:
        assert "region" not in phys, f"line-0 finding {f['id']} must omit region"
    by_rule[f["id"]] = f

# rules[] deduped by id; security-severity derived (cvss or score/10, 0-10)
rules = {rr["id"]: rr for rr in run["tool"]["driver"]["rules"]}
assert set(rules) == set(by_rule), "rules must cover exactly the finding ids"
for rid, rr in rules.items():
    ss = rr.get("properties", {}).get("security-severity")
    if ss is not None:
        v = float(ss)
        assert 0.0 <= v <= 10.0, (rid, v)

# Secret-leak safety: a no-title finding's message is its id, and the plaintext
# canary in its evidence NEVER reaches the SARIF output.
nt = [r for r in results if r["ruleId"] == "notitle-secret"]
assert nt and nt[0]["message"]["text"] == "notitle-secret", nt
raw = open(sys.argv[1]).read()
assert "SARIF_CANARY_PLAINTEXT" not in raw, "plaintext secret from evidence leaked into SARIF"

# No pipeline sentinel ever becomes a result.
assert not any(r["ruleId"].startswith("__") for r in results), "sentinel ruleId leaked into SARIF"

print(f"  SARIF 2.1.0: {len(results)} results, {len(rules)} rules, levels + regions + security-severity + no-leak OK")
PY

# e2e cross-check with jq (independent of the python asserts): the SARIF parses
# and its result count equals the input finding count.
jq -e . "$scratch/out.sarif" >/dev/null || { echo "script-sarif: FAIL — output is not valid JSON" >&2; exit 1; }
sarif_n=$(jq '.runs[0].results | length' "$scratch/out.sarif")
find_n=$(jq 'length' "$scratch/findings.json")
[ "$sarif_n" = "$find_n" ] || { echo "script-sarif: FAIL — results $sarif_n != findings $find_n" >&2; exit 1; }
echo "  jq e2e: valid JSON, results ($sarif_n) == findings ($find_n)"

echo "=== edge cases ==="
# empty array -> valid 0-result SARIF, exit 0
echo '[]' | python3 scripts/secaudit/sarif.py > "$scratch/empty.sarif"
python3 - "$scratch/empty.sarif" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["version"] == "2.1.0" and s["runs"][0]["results"] == [], s
print("  empty array -> valid 0-result SARIF OK")
PY

# malformed JSON stdin -> fail loudly (exit 1), no false-clean SARIF
if printf 'not json' | python3 scripts/secaudit/sarif.py >/dev/null 2>&1; then
    echo "script-sarif: FAIL — malformed stdin did not exit non-zero" >&2; exit 1
fi
echo "  malformed stdin -> exit 1 OK"

# non-list JSON stdin -> fail loudly (exit 1)
if printf '{"not":"a list"}' | python3 scripts/secaudit/sarif.py >/dev/null 2>&1; then
    echo "script-sarif: FAIL — non-list stdin did not exit non-zero" >&2; exit 1
fi
echo "  non-list stdin -> exit 1 OK"

# sentinel entries (__dep_inventory__, __*_status__) are dropped, not emitted
echo '[{"id":"__dep_inventory__","x":1},{"__secrets_status__":"ok","tools":[]},{"id":"real","severity":"LOW","title":"t","file":"a","line":1}]' \
    | python3 scripts/secaudit/sarif.py > "$scratch/sent.sarif"
python3 - "$scratch/sent.sarif" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
ids = [r["ruleId"] for r in s["runs"][0]["results"]]
assert ids == ["real"], ids
print("  sentinel entries dropped (only real finding emitted) OK")
PY

# true dedup: two findings share one id -> 2 results, 1 rule
echo '[{"id":"dup","severity":"HIGH","title":"a","file":"x","line":1},{"id":"dup","severity":"HIGH","title":"b","file":"y","line":2}]' \
    | python3 scripts/secaudit/sarif.py > "$scratch/dup.sarif"
python3 - "$scratch/dup.sarif" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
run = s["runs"][0]
assert len(run["results"]) == 2 and len(run["tool"]["driver"]["rules"]) == 1, \
    (len(run["results"]), len(run["tool"]["driver"]["rules"]))
print("  same-id dedup: 2 results, 1 rule OK")
PY

echo ""
echo "script-sarif: OK"
