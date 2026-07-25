#!/usr/bin/env bash
# script-accepted.sh — verifies accepted.py, the accepted-risk register (BL-004).
#
# The invariants this defends, in priority order:
#   (1) A corrupt/unreadable register NEVER fails the audit and NEVER vanishes
#       silently — it degrades to zero acceptances plus a loud warning.
#   (2) Expiry is mandatory: an entry without `expires` is rejected, and the
#       finding keeps full severity. No permanent blind spots.
#   (3) A CRITICAL acceptance is capped at 30 days from the date it was made,
#       regardless of what `expires` claims — clamped down, never honoured.
#   (4) Fingerprint matching is exact on `v1:<64 hex>`; no prefix/substring.
#   (5) Acceptance never DROPS a finding — it rewrites status and preserves the
#       original in suppressed_status.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
ac="scripts/secaudit/accepted.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
NOW=2026-07-25

fp() { python3 -c "
import sys; sys.path.insert(0,'scripts')
from secaudit.fingerprint import fingerprint
import json; print(fingerprint(json.loads(sys.argv[1])))" "$1"; }

F_HIGH='{"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":10,"cwe":"CWE-89","evidence":"execute(q)","severity":"HIGH","title":"SQLi","status":"CARRIED"}'
F_CRIT='{"origin":"python","tool":"ruff","rule_id":"S105","file":"src/cfg.py","line":7,"cwe":"CWE-798","evidence":"pw=x","severity":"CRITICAL","title":"Hardcoded pw","status":"NEW"}'
FP_HIGH=$(fp "$F_HIGH"); FP_CRIT=$(fp "$F_CRIT")
printf '%s\n%s\n' "$F_HIGH" "$F_CRIT" > "$scratch/findings.jsonl"
# fingerprints must carry into the findings for matching (deltas.py stamps them)
python3 - "$scratch/findings.jsonl" "$FP_HIGH" "$FP_CRIT" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
rows[0]["fingerprint"] = sys.argv[2]; rows[1]["fingerprint"] = sys.argv[3]
open(sys.argv[1], "w").write("\n".join(json.dumps(r) for r in rows) + "\n")
PY

run() { python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/findings.jsonl" --now "$NOW"; }

echo "=== (1) a valid register accepts exactly its fingerprint ==="
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "compensating control at the proxy",
  "accepted": "2026-07-20", "expires": "2026-09-01", "accepted_by": "alice"}]}
JSON
out=$(run)
python3 - "$FP_HIGH" "$FP_CRIT" <<PY
import json, sys
d = json.loads('''$out''')
fs = {f["fingerprint"]: f for f in d["findings"]}
a, u = fs[sys.argv[1]], fs[sys.argv[2]]
assert a["status"] == "ACCEPTED", a["status"]
assert a["suppressed_status"] == "CARRIED", a  # original preserved, not lost
assert a["accepted_reason"].startswith("compensating"), a
assert a["accepted_expires"] == "2026-09-01", a
assert a["accepted_by"] == "alice", a
assert u["status"] == "NEW", u              # untouched finding unchanged
assert d["info"]["accepted"] == 1 and not d["warnings"], d
assert len(d["findings"]) == 2, "acceptance must never drop a finding"
print("  valid entry -> ACCEPTED, suppressed_status preserved, sibling untouched OK")
PY

echo "=== (2) expiry is mandatory ==="
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "no expiry given", "accepted": "2026-07-20"}]}
JSON
out=$(run)
python3 - "$FP_HIGH" <<PY
import json, sys
d = json.loads('''$out''')
assert d["entries"] == 0, d
assert any("expires" in w and "mandatory" in w for w in d["warnings"]), d["warnings"]
f = {x["fingerprint"]: x for x in d["findings"]}[sys.argv[1]]
assert f["status"] == "CARRIED" and "accepted_reason" not in f, f
print("  missing expires -> entry rejected loudly, finding keeps full severity OK")
PY

echo "=== (3) an already-expired entry does not suppress ==="
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "lapsed", "accepted": "2026-01-01",
  "expires": "2026-06-01"}]}
JSON
out=$(run)
python3 - "$FP_HIGH" <<PY
import json, sys
d = json.loads('''$out''')
assert d["entries"] == 0, d
assert len(d["expired"]) == 1 and d["expired"][0]["expired_on"] == "2026-06-01", d
f = {x["fingerprint"]: x for x in d["findings"]}[sys.argv[1]]
assert f["status"] == "CARRIED", f
print("  expired entry -> reported in the expired list, finding live again OK")
PY

echo "=== (4) CRITICAL acceptance is clamped to 30 days ==="
# expires claims a year; accepted 2026-07-20 => enforced 2026-08-19
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_CRIT", "reason": "risk accepted pending vendor fix",
  "accepted": "2026-07-20", "expires": "2027-07-20"}]}
JSON
out=$(run)
python3 - "$FP_CRIT" <<PY
import json, sys
d = json.loads('''$out''')
f = {x["fingerprint"]: x for x in d["findings"]}[sys.argv[1]]
assert f["status"] == "ACCEPTED", f
assert f["accepted_expires"] == "2026-08-19", f["accepted_expires"]
assert f["accepted_clamped_from"] == "2027-07-20", f
c = d["info"]["clamped"]
assert len(c) == 1 and c[0]["enforced"] == "2026-08-19", c
print("  CRITICAL clamp: min(expires, accepted+30d) = 2026-08-19, clamp reported OK")
PY
# ... and past the clamp the CRITICAL comes back at full severity even though
# the file still claims a 2027 expiry — the footgun this rule exists to prevent.
out=$(python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/findings.jsonl" --now 2026-09-01)
python3 - "$FP_CRIT" <<PY
import json, sys
d = json.loads('''$out''')
f = {x["fingerprint"]: x for x in d["findings"]}[sys.argv[1]]
assert f["status"] == "NEW", f["status"]
l = d["info"]["lapsed"]
assert len(l) == 1 and l[0]["clamped"] and l[0]["enforced_expiry"] == "2026-08-19", l
print("  past the clamp: CRITICAL live again + lapsed list explains why OK")
PY
# a HIGH with the same dates is NOT clamped — the cap is CRITICAL-only
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "long but allowed", "accepted": "2026-07-20",
  "expires": "2027-07-20"}]}
JSON
python3 - "$FP_HIGH" <<PY
import json, sys, subprocess
d = json.loads(subprocess.run(["python3","$ac","--register","$scratch/reg.json",
    "--findings","$scratch/findings.jsonl","--now","$NOW"],
    capture_output=True, text=True, check=True).stdout)
f = {x["fingerprint"]: x for x in d["findings"]}[sys.argv[1]]
assert f["accepted_expires"] == "2027-07-20" and "accepted_clamped_from" not in f, f
assert not d["info"]["clamped"], d["info"]
print("  non-CRITICAL severity is not clamped OK")
PY

echo "=== (5) a malformed register is ignored loudly, exit 0 ==="
printf 'not json at all' > "$scratch/reg.json"
set +e; out=$(run); rc=$?; set -e
[ "$rc" = "0" ] || { echo "script-accepted: FAIL — malformed register exited $rc, must not fail the audit" >&2; exit 1; }
python3 - <<PY
import json
d = json.loads('''$out''')
assert d["entries"] == 0, d
assert len(d["warnings"]) == 1, d["warnings"]
w = d["warnings"][0]
assert "unreadable" in w and "full severity" in w, w
assert all(f["status"] != "ACCEPTED" for f in d["findings"]), d
print("  malformed register -> 1 loud warning, 0 acceptances, exit 0 OK")
PY
# a register that is valid JSON but the wrong shape is equally non-fatal
for body in '[]' '{"schema": 99, "accepted": []}' '{"schema": 1}'; do
    printf '%s' "$body" > "$scratch/reg.json"
    set +e; out=$(run); rc=$?; set -e
    [ "$rc" = "0" ] || { echo "script-accepted: FAIL — shape '$body' exited $rc" >&2; exit 1; }
    echo "$out" | python3 -c "
import json,sys
d=json.load(sys.stdin); assert d['entries']==0 and d['warnings'], d" \
      || { echo "script-accepted: FAIL — shape '$body' not warned about" >&2; exit 1; }
done
echo "  wrong-shape / unsupported-schema registers -> warned, non-fatal OK"

echo "=== (6) fingerprint matching is exact ==="
short=${FP_HIGH:0:20}
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$short", "reason": "truncated fp", "accepted": "2026-07-20",
  "expires": "2026-09-01"},
 {"fingerprint": "v1:${FP_HIGH:3:63}f", "reason": "one char off",
  "accepted": "2026-07-20", "expires": "2026-09-01"},
 {"fingerprint": "V1:ABCDEF", "reason": "wrong case/shape",
  "accepted": "2026-07-20", "expires": "2026-09-01"}]}
JSON
out=$(run)
python3 - <<PY
import json
d = json.loads('''$out''')
assert d["info"]["accepted"] == 0, d["info"]
assert all(f["status"] != "ACCEPTED" for f in d["findings"]), d
# the truncated and mis-cased ones are rejected as malformed fingerprints;
# the one-char-off one is well-formed but simply never matches
assert sum("not a v1 fingerprint" in w for w in d["warnings"]) == 2, d["warnings"]
assert d["entries"] == 1, d["entries"]
print("  truncated / mis-cased fingerprints rejected; near-miss never matches OK")
PY

echo "=== (7) type confusion never crashes the audit (regression, Tier-1 Criticals) ==="
# A hand-edited register WILL eventually contain an unquoted fingerprint or a
# list where a string belongs. Any of these raising would abort the whole audit
# — the one thing this module promises never to do.
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": 12345, "reason": "unquoted fp", "accepted": "2026-07-20", "expires": "2026-09-01"},
 {"fingerprint": ["$FP_HIGH"], "reason": "list fp", "accepted": "2026-07-20", "expires": "2026-09-01"},
 {"fingerprint": "$FP_HIGH", "reason": {"why": "obj"}, "accepted": "2026-07-20", "expires": "2026-09-01"},
 {"fingerprint": "$FP_HIGH", "reason": "num expiry", "accepted": "2026-07-20", "expires": 20260901},
 {"fingerprint": null, "reason": "null fp", "accepted": "2026-07-20", "expires": "2026-09-01"},
 {"fingerprint": true, "reason": "bool fp", "accepted": "2026-07-20", "expires": "2026-09-01"}]}
JSON
set +e; out=$(run); rc=$?; set -e
[ "$rc" = "0" ] || { echo "script-accepted: FAIL — type-confused register exited $rc (must degrade, not crash)" >&2; exit 1; }
python3 - <<PY
import json
d = json.loads('''$out''')
assert d["entries"] == 0, d["entries"]
assert len(d["warnings"]) == 6, d["warnings"]
assert sum("must be a quoted string" in w for w in d["warnings"]) >= 4, d["warnings"]
assert all(f["status"] != "ACCEPTED" for f in d["findings"]), d
print("  6 type-confused entries -> 6 warnings, 0 acceptances, exit 0 OK")
PY
# ... and a non-string severity on the FINDINGS side must not crash either,
# nor buy an uncapped suppression.
python3 - <<'PY'
import sys; sys.path.insert(0, "scripts")
from secaudit.accepted import effective_expiry
from datetime import date
e = {"accepted": "2026-07-01", "expires": "2027-07-01"}
for sev in (["CRITICAL"], {"s": 1}, 7, None, "", "WEIRD"):
    exp, clamped = effective_expiry(e, sev)
    assert clamped and exp == date(2026, 7, 31), (sev, exp, clamped)
# only a recognised non-critical severity skips the cap
for sev in ("HIGH", "medium", "Low", "INFO"):
    exp, clamped = effective_expiry(e, sev)
    assert not clamped and exp == date(2027, 7, 1), (sev, exp, clamped)
print("  unknown/non-string severity -> CAPPED (fails toward showing the finding) OK")
PY

echo "=== (8) duplicate fingerprints: later entry wins, loudly ==="
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "first", "accepted": "2026-07-20", "expires": "2026-08-01"},
 {"fingerprint": "$FP_HIGH", "reason": "second", "accepted": "2026-07-20", "expires": "2026-09-01"}]}
JSON
run | python3 -c "
import json,sys
d=json.load(sys.stdin)
f={x['fingerprint']:x for x in d['findings']}['$FP_HIGH']
assert f['accepted_reason']=='second' and f['accepted_expires']=='2026-09-01', f
assert sum('duplicate fingerprint' in w for w in d['warnings'])==1, d['warnings']
assert d['entries']==1, d['entries']
print('  duplicate fingerprint -> later entry wins + exactly 1 warning OK')"

echo "=== (9) expiry boundaries are inclusive ==="
# expires == today is still accepted; the day after is not.
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "boundary", "accepted": "2026-07-01",
  "expires": "2026-07-25"}]}
JSON
python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/findings.jsonl" --now 2026-07-25 \
 | python3 -c "
import json,sys
f={x['fingerprint']:x for x in json.load(sys.stdin)['findings']}['$FP_HIGH']
assert f['status']=='ACCEPTED', f['status']
print('  expires == today -> still ACCEPTED (inclusive) OK')"
python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/findings.jsonl" --now 2026-07-26 \
 | python3 -c "
import json,sys
d=json.load(sys.stdin)
f={x['fingerprint']:x for x in d['findings']}['$FP_HIGH']
assert f['status']=='CARRIED' and len(d['expired'])==1, d
print('  expires == yesterday -> lapsed OK')"
# clamp boundary: CRITICAL accepted 2026-07-20 is ACCEPTED on 08-19, live on 08-20
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_CRIT", "reason": "clamp boundary", "accepted": "2026-07-20",
  "expires": "2027-01-01"}]}
JSON
for pair in "2026-08-19 ACCEPTED" "2026-08-20 NEW"; do
  set -- $pair
  python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/findings.jsonl" --now "$1" \
   | python3 -c "
import json,sys
f={x['fingerprint']:x for x in json.load(sys.stdin)['findings']}['$FP_CRIT']
assert f['status']=='$2', (f['status'], '$1')
print('  clamp boundary $1 -> $2 OK')"
done

echo "=== edge cases ==="
# missing register file is normal (most projects have none) -> silent, no warning
rm -f "$scratch/none.json"
python3 "$ac" --register "$scratch/none.json" --now "$NOW" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['entries']==0 and not d['warnings'], d
print('  absent register -> silent, no warning OK')"
# expires before accepted is nonsense -> rejected
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "backwards", "accepted": "2026-07-20",
  "expires": "2026-07-01"}]}
JSON
run | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['entries']==0 and any('precedes' in w for w in d['warnings']), d
print('  expires-before-accepted -> rejected OK')"
# a non-date expires is rejected rather than silently treated as forever
cat > "$scratch/reg.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "bad date", "accepted": "2026-07-20",
  "expires": "never"}]}
JSON
run | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['entries']==0 and any('ISO date' in w for w in d['warnings']), d
print('  non-ISO expires -> rejected, never treated as no-expiry OK')"
# no --register -> usage, exit 2
set +e; python3 "$ac" >/dev/null 2>"$scratch/u.err"; rc=$?; set -e
[ "$rc" = "2" ] || { echo "script-accepted: FAIL — missing --register exited $rc, expected 2" >&2; exit 1; }
grep -q 'usage: accepted.py' "$scratch/u.err" || { echo "script-accepted: FAIL — no usage on stderr" >&2; exit 1; }
echo "  missing --register -> exit 2 + usage OK"
# an unparseable --now must NOT silently fall back to the wall clock: that would
# make a caller's typo look like a passing deterministic run.
set +e; python3 "$ac" --register "$scratch/reg.json" --now 07/25/2026 >/dev/null 2>"$scratch/n.err"; rc=$?; set -e
[ "$rc" = "2" ] || { echo "script-accepted: FAIL — bad --now exited $rc, expected 2" >&2; exit 1; }
grep -q 'not an ISO date' "$scratch/n.err" || { echo "script-accepted: FAIL — bad --now not diagnosed" >&2; exit 1; }
echo "  unparseable --now -> exit 2, never a silent wall-clock fallback OK"
# a broken --findings file fails with a diagnostic, not a traceback, and never
# degrades to "zero findings" (which would report zero acceptances silently).
set +e; python3 "$ac" --register "$scratch/reg.json" --findings /nonexistent.jsonl >/dev/null 2>"$scratch/f.err"; rc=$?; set -e
[ "$rc" != "0" ] || { echo "script-accepted: FAIL — missing findings file exited 0" >&2; exit 1; }
grep -q 'cannot read findings file' "$scratch/f.err" || { echo "script-accepted: FAIL — no diagnostic for missing findings" >&2; exit 1; }
grep -q 'Traceback' "$scratch/f.err" && { echo "script-accepted: FAIL — traceback leaked for missing findings" >&2; exit 1; }
printf '{"a":1}\nnot json\n' > "$scratch/bad.jsonl"
set +e; python3 "$ac" --register "$scratch/reg.json" --findings "$scratch/bad.jsonl" >/dev/null 2>"$scratch/f2.err"; rc=$?; set -e
[ "$rc" != "0" ] || { echo "script-accepted: FAIL — malformed findings line exited 0" >&2; exit 1; }
grep -q 'bad.jsonl:2 is not valid JSON' "$scratch/f2.err" || { echo "script-accepted: FAIL — malformed findings line not located" >&2; exit 1; }
echo "  broken --findings -> located diagnostic, no traceback, never silent OK"

echo ""
echo "script-accepted: OK"
