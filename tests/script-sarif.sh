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
    if any(k.startswith("__") and k.endswith("_status__") for k in o):
        continue
    rows.append(o)
rows.append({"id": "dast-xcontenttype", "severity": "LOW", "cwe": "CWE-693",
             "title": "Missing X-Content-Type-Options header", "file": "https://app/",
             "line": 0, "evidence": "response lacked header", "origin": "dast",
             "tool": "zap-baseline"})
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

# No raw-secret leakage: the synthetic evidence strings never surface verbatim
# beyond the redacted forms (smoke check — no plaintext canary token in output).
raw = open(sys.argv[1]).read()
assert "CANARY_RAW_SECRET" not in raw, "raw secret canary leaked into SARIF"

print(f"  SARIF 2.1.0: {len(results)} results, {len(rules)} rules, levels + regions + security-severity OK")
PY

echo ""
echo "script-sarif: OK"
