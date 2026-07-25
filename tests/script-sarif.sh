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

# sentinel entries are dropped in ALL shapes: id-based __dep_inventory__,
# key-based {__dep_inventory__:...} (contract-check accepts both), and __*_status__
echo '[{"id":"__dep_inventory__","x":1},{"__dep_inventory__":{"ecosystems":[]}},{"__secrets_status__":"ok","tools":[]},{"id":"real","severity":"LOW","title":"t","file":"a","line":1}]' \
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

echo "=== ACCEPTED is suppressed in BOTH modes (BL-004) ==="
# An accepted risk must not come back as a code-scanning alert in either mode —
# in `all` because someone explicitly accepted it, in `new` because it is not new.
cat > "$scratch/acc-findings.json" <<'JSON'
[{"id":"f-accepted","severity":"CRITICAL","title":"accepted risk","file":"a.py","line":1,
  "status":"ACCEPTED","suppressed_status":"CARRIED"},
 {"id":"f-live","severity":"HIGH","title":"live","file":"b.py","line":2,"status":"NEW"},
 {"id":"f-carried","severity":"HIGH","title":"carried","file":"c.py","line":3,"status":"CARRIED"}]
JSON
for m in all new; do
  python3 scripts/secaudit/sarif.py --mode=$m < "$scratch/acc-findings.json" > "$scratch/acc-$m.sarif"
  python3 - "$scratch/acc-$m.sarif" "$m" <<'PY'
import json, sys
run = json.load(open(sys.argv[1]))["runs"][0]
ids = sorted(r["ruleId"] for r in run["results"])
assert "f-accepted" not in ids, (sys.argv[2], ids)
assert "f-accepted" not in [r["id"] for r in run["tool"]["driver"]["rules"]], ids
expect = ["f-carried", "f-live"] if sys.argv[2] == "all" else ["f-live"]
assert ids == expect, (sys.argv[2], ids, expect)
print(f"  --mode={sys.argv[2]}: ACCEPTED absent from results AND rules OK")
PY
done

# Tripwire: every status deltas.py can emit must be accounted for in exactly one
# of SUPPRESSED / NOT_INTRODUCED / (introduced). A status added to deltas.py
# without updating sarif.py fails HERE rather than silently leaking or hiding.
python3 - <<'PY'
import re, sys
sys.path.insert(0, "scripts")
from secaudit.sarif import SUPPRESSED, NOT_INTRODUCED
src = open("scripts/secaudit/deltas.py").read()
emitted = set(re.findall(r'"status":\s*"([A-Z]+)"', src))
emitted |= set(re.findall(r'g\["status"\]\s*=\s*"([A-Z]+)"', src))
emitted |= {"NEW", "REVERIFIED", "CARRIED", "FIXED", "REGRESSED", "ACCEPTED"}
known = SUPPRESSED | NOT_INTRODUCED | {"NEW", "REGRESSED"}
unaccounted = emitted - known
assert not unaccounted, (
    f"deltas.py can emit status {sorted(unaccounted)} that sarif.py does not "
    f"classify — it would be treated as introduced by default. Add it to "
    f"SUPPRESSED or NOT_INTRODUCED deliberately.")
assert not (SUPPRESSED & NOT_INTRODUCED), "a status cannot be in both sets"
print(f"  tripwire: all {len(emitted)} deltas statuses accounted for OK")
PY

echo "=== --mode=new: emit only what this run introduced (BL-007) ==="
# deltas.py stamps `status` upstream of score.py, which preserves every key, so
# sarif.py sees the delta class on its stdin. Fixture covers each status plus an
# unclassified finding (no `status` key at all).
cat > "$scratch/delta-findings.json" <<'JSON'
[{"id":"f-new","severity":"HIGH","title":"new one","file":"a.py","line":1,"status":"NEW"},
 {"id":"f-regressed","severity":"CRITICAL","title":"regressed one","file":"b.py","line":2,"status":"REGRESSED"},
 {"id":"f-carried","severity":"HIGH","title":"carried one","file":"c.py","line":3,"status":"CARRIED"},
 {"id":"f-reverified","severity":"MEDIUM","title":"reverified one","file":"d.py","line":4,"status":"REVERIFIED"},
 {"id":"f-fixed","severity":"LOW","title":"fixed one","file":"e.py","line":5,"status":"FIXED"},
 {"id":"f-nostatus","severity":"LOW","title":"unclassified","file":"f.py","line":6}]
JSON

python3 scripts/secaudit/sarif.py < "$scratch/delta-findings.json" > "$scratch/d-default.sarif"
python3 scripts/secaudit/sarif.py --mode=all < "$scratch/delta-findings.json" > "$scratch/d-all.sarif"
python3 scripts/secaudit/sarif.py --mode=new < "$scratch/delta-findings.json" > "$scratch/d-new.sarif"
# space-separated form must parse identically to the = form
python3 scripts/secaudit/sarif.py --mode new < "$scratch/delta-findings.json" > "$scratch/d-new2.sarif"

# Back-compat: no flag == --mode=all, byte for byte. Existing CI consumers that
# invoke sarif.py with no argv must see exactly the pre-BL-007 output.
cmp -s "$scratch/d-default.sarif" "$scratch/d-all.sarif" \
    || { echo "script-sarif: FAIL — default mode differs from --mode=all" >&2; exit 1; }
cmp -s "$scratch/d-new.sarif" "$scratch/d-new2.sarif" \
    || { echo "script-sarif: FAIL — --mode=new differs from '--mode new'" >&2; exit 1; }
# The same back-compat check on the REAL scored pipeline fixture used above.
python3 scripts/secaudit/score.py < "$scratch/findings.json" \
    | python3 scripts/secaudit/sarif.py --mode=all > "$scratch/out-all.sarif"
cmp -s "$scratch/out.sarif" "$scratch/out-all.sarif" \
    || { echo "script-sarif: FAIL — pipeline default output changed under --mode=all" >&2; exit 1; }
echo "  default == --mode=all (byte-identical, both fixtures) OK"

python3 - "$scratch/d-all.sarif" "$scratch/d-new.sarif" <<'PY'
import json, sys
allr = json.load(open(sys.argv[1]))["runs"][0]
newr = json.load(open(sys.argv[2]))["runs"][0]

all_ids = [r["ruleId"] for r in allr["results"]]
assert sorted(all_ids) == ["f-carried", "f-fixed", "f-new", "f-nostatus",
                           "f-regressed", "f-reverified"], all_ids

new_ids = sorted(r["ruleId"] for r in newr["results"])
# NEW + REGRESSED are introduced; a finding with no status fails OPEN (never
# silently dropped). CARRIED/REVERIFIED/FIXED are the project's backlog, not
# what this run/PR added — they must not fail a PR check.
assert new_ids == ["f-new", "f-nostatus", "f-regressed"], new_ids

# Filtered findings must not leak in via rules[] either — a rule with no result
# would still show up as a scanned rule in GitHub's ingest.
rule_ids = sorted(r["id"] for r in newr["tool"]["driver"]["rules"])
assert rule_ids == new_ids, (rule_ids, new_ids)
print(f"  --mode=new: {len(new_ids)} of {len(all_ids)} results (NEW+REGRESSED+unclassified), rules match OK")
PY

# unknown mode -> exit 2 with usage on stderr (deltas.py convention)
set +e
printf '[]' | python3 scripts/secaudit/sarif.py --mode=bogus >"$scratch/bogus.out" 2>"$scratch/bogus.err"
rc=$?
set -e
[ "$rc" = "2" ] || { echo "script-sarif: FAIL — unknown mode exit $rc, expected 2" >&2; exit 1; }
grep -q 'usage: sarif.py' "$scratch/bogus.err" \
    || { echo "script-sarif: FAIL — unknown mode printed no usage on stderr" >&2; exit 1; }
# unknown flag likewise
set +e
printf '[]' | python3 scripts/secaudit/sarif.py --nope=1 >/dev/null 2>&1
rc=$?
set -e
[ "$rc" = "2" ] || { echo "script-sarif: FAIL — unknown flag exit $rc, expected 2" >&2; exit 1; }
echo "  unknown mode/flag -> exit 2 + usage OK"

# Malformed stdin must STILL fail loudly under --mode=new: a broken pipe must
# never become an empty "nothing new" PR check that passes.
if printf 'not json' | python3 scripts/secaudit/sarif.py --mode=new >/dev/null 2>&1; then
    echo "script-sarif: FAIL — malformed stdin passed under --mode=new" >&2; exit 1
fi
echo "  malformed stdin under --mode=new -> exit 1 OK"

# v1.29: the SARIF log is written beside the markdown report INSIDE the state
# home (§6.5), never into the audited tree. sarif.py itself writes to stdout, so
# the contract lives in the documented redirect target — assert the skill's §6.5
# names <state_home>/reports/ and that no in-target path survives anywhere.
echo "=== §6.5 SARIF output path derives from the state home ==="
grep -q 'state_home>/reports/sec-audit-YYYYMMDD-HHMM.sarif' skills/sec-audit/SKILL.md \
    || { echo "FAIL: SKILL.md §6.5 does not write the SARIF into <state_home>/reports/"; exit 1; }
grep -nE '(<target_path>|<target>)/sec-audit-report-YYYYMMDD-HHMM\.sarif' \
    skills/sec-audit/SKILL.md commands/sec-audit.md \
    && { echo "FAIL: an in-target SARIF path survives"; exit 1; }
# The pairing rule (same UTC timestamp as the markdown report) must survive the move.
grep -q 'same' <(sed -n '/6.5 Optional SARIF/,/^## /p' skills/sec-audit/SKILL.md) \
    || { echo "FAIL: §6.5 lost the same-timestamp pairing rule"; exit 1; }
echo "  SARIF path: <state_home>/reports/, timestamp-paired OK"

echo ""
echo "script-sarif: OK"
