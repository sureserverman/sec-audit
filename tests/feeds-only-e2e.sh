#!/usr/bin/env bash
# feeds-only-e2e.sh — the feed-only re-audit end to end over the real scripts
# (BL-006), in a sandboxed state home with offline feed replay.
#
#   run 1  full baseline audit                   -> findings + deps persisted
#   run 2  --feeds-only, feeds unchanged         -> QUIET: history line appended,
#                                                   NO new report, findings carried
#   run 3  --feeds-only, a new advisory appears  -> NEW (feed-driven) reported,
#                                                   deps state updated
#   run 4  a normal incremental run afterwards   -> loads the state written by a
#                                                   feed-only run without error
#
# The last run is the point: a cheap scheduled check must not corrupt the state
# that real audits depend on.
#
# Hermetic: statehome + statestore + fingerprint + deltas + cve_enricher replay.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
S=scripts/secaudit
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
export SECAUDIT_PORTFOLIO_ROOT="$scratch/vault/Portfolio"
export SECAUDIT_DEV_ROOT="$scratch/dev"
export SECAUDIT_REGISTRY="$scratch/registry.yaml"
mkdir -p "$SECAUDIT_PORTFOLIO_ROOT" "$scratch/dev/web"

target="$scratch/dev/web/demo"; mkdir -p "$target/src"
cat > "$SECAUDIT_REGISTRY" <<YAML
version: 1
projects:
  - path: $target
    name: demo
    area: web
    enabled: true
YAML
printf 'q = "select 1"\n' > "$target/src/db.py"

home=$(python3 "$S/statehome.py" "$target" | python3 -c "import json,sys; print(json.load(sys.stdin)['home'])")
mkdir -p "$home"

F='{"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":1,"cwe":"CWE-89","evidence":"select 1","severity":"HIGH","title":"SQLi"}'
echo "$F" > "$scratch/fresh.jsonl"
python3 "$S/fingerprint.py" findings "$scratch/fresh.jsonl" > "$scratch/fp.jsonl"
FP=$(python3 -c "
import json,sys
print(json.loads(open('$scratch/fp.jsonl').read().strip())['fingerprint'])")

cat > "$scratch/cs.json" <<'JSON'
{"mode":"incremental","baseline_run":null,
 "files":{"added":["src/db.py"],"modified":[],"deleted":[],"unchanged":0},
 "lanes":{"python":{"rerun":true,"reason":"first audit"}}}
JSON
echo '{"python":"ok"}' > "$scratch/lane.json"

# CVE-enricher output stand-ins: run 1 knows one advisory, run 3 sees a second.
cat > "$scratch/cve1.json" <<'JSON'
[{"ecosystem":"PyPI","name":"django","version":"2.2.0","resolution":"lockfile","status":"ok",
  "cves":[{"id":"CVE-2024-0001","cve":"CVE-2024-0001","cvss":7.5,"epss":0.06,"kev":false}],
  "malicious":[]}]
JSON
cat > "$scratch/cve2.json" <<'JSON'
[{"ecosystem":"PyPI","name":"django","version":"2.2.0","resolution":"lockfile","status":"ok",
  "cves":[{"id":"CVE-2024-0001","cve":"CVE-2024-0001","cvss":7.5,"epss":0.06,"kev":false},
          {"id":"CVE-2026-9999","cve":"CVE-2026-9999","cvss":9.8,"epss":0.8,"kev":true,
           "kev_date_added":"2026-07-24"}],
  "malicious":[]}]
JSON

persist() {  # $1 merged.json  $2 run-id  $3 mode
python3 - "$home" "$1" "$2" "$3" <<'PY'
import json, sys, os
sys.path.insert(0, "scripts")
from secaudit import statestore
home, merged, run_id, mode = sys.argv[1], json.load(open(sys.argv[2])), sys.argv[3], sys.argv[4]
st = statestore.load(home) if os.path.exists(os.path.join(home, statestore.STATE_FILE)) \
     else statestore.skeleton()
st["findings"] = merged["state_findings"]
if "state_deps" in merged:
    st["deps"] = merged["state_deps"]
statestore.save(home, st)
statestore.append_run(home, {"run_id": run_id, "mode": mode,
                             "counts": {"open": merged["deltas"]["total_open"]},
                             "deltas": merged["deltas"]})
PY
}

echo "=== run 1: full baseline ==="
python3 "$S/deltas.py" --state "$home/audit-state.json" --changeset "$scratch/cs.json" \
    --findings "$scratch/fp.jsonl" --lane-status "$scratch/lane.json" \
    --cve-output "$scratch/cve1.json" --run-id 20260701-1200 \
    --now 2026-07-01T12:00:00Z > "$scratch/m1.json"
persist "$scratch/m1.json" 20260701-1200 incremental
python3 -c "
import json
d=json.load(open('$scratch/m1.json'))
assert d['deltas']['new']==1, d['deltas']
assert d['state_deps']['PyPI|django']['advisories']==['CVE-2024-0001'], d['state_deps']
print('  baseline: 1 NEW finding, 1 known advisory persisted OK')"

echo "=== run 2: --feeds-only, nothing moved -> QUIET ==="
python3 "$S/deltas.py" --state "$home/audit-state.json" --feeds-only \
    --cve-output "$scratch/cve1.json" --run-id 20260702-1200 \
    --now 2026-07-02T12:00:00Z > "$scratch/m2.json"
python3 -c "
import json
d=json.load(open('$scratch/m2.json'))
ad=d['advisory_deltas']
assert d['mode']=='feeds', d.get('mode')
assert ad['new']==[] and ad['escalated']==[] and ad['withdrawn']==[], ad
# the code finding is carried, untouched, and nothing was resolved
f=d['findings'][0]
assert f['status']=='CARRIED' and f['fingerprint']=='$FP', f
assert d['deltas']['fixed']==0 and d['deltas']['total_open']==1, d['deltas']
print('  feeds-only quiet run: no advisory movement, finding CARRIED, 0 fixed OK')"
# Quiet-mode contract: a history line IS appended, but no report file is written.
# The reports dir legitimately may not exist yet, and both `ls` and `find` exit
# non-zero on a missing path — which under `set -e` + `pipefail` aborts the whole
# run with no message. Handle absence explicitly rather than swallowing the
# status, so a real failure here still surfaces.
count_reports() {
    [ -d "$home/reports" ] || { echo 0; return 0; }
    find "$home/reports" -type f | wc -l
}
before_reports=$(count_reports)
persist "$scratch/m2.json" 20260702-1200 feeds
after_reports=$(count_reports)
[ "$before_reports" = "$after_reports" ] \
  || { echo "feeds-only-e2e: FAIL — a quiet run wrote a report" >&2; exit 1; }
python3 - "$home" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1] + "/history.jsonl") if l.strip()]
assert len(rows) == 2, len(rows)
assert rows[1]["mode"] == "feeds", rows[1]
print("  quiet run: history line appended (mode=feeds), no report written OK")
PY

echo "=== run 3: --feeds-only, a NEW advisory lands on the unchanged dep ==="
python3 "$S/deltas.py" --state "$home/audit-state.json" --feeds-only \
    --cve-output "$scratch/cve2.json" --run-id 20260703-1200 \
    --now 2026-07-03T12:00:00Z > "$scratch/m3.json"
persist "$scratch/m3.json" 20260703-1200 feeds
python3 -c "
import json
d=json.load(open('$scratch/m3.json'))
ad=d['advisory_deltas']
new=ad['new']
assert len(new)==1 and new[0]['advisory']=='CVE-2026-9999', new
assert new[0]['dep_unchanged'] is True, new       # the whole point of the mode
assert new[0]['package']=='PyPI|django', new
# the code finding is STILL only carried — no scanner ran
assert d['findings'][0]['status']=='CARRIED', d['findings'][0]
assert d['deltas']['fixed']==0, d['deltas']
assert 'CVE-2026-9999' in d['state_deps']['PyPI|django']['advisories'], d['state_deps']
assert d['state_deps']['PyPI|django']['kev']==['CVE-2026-9999'], d['state_deps']
print('  feeds-only: NEW (feed-driven) CVE-2026-9999 on an UNCHANGED dep, KEV recorded OK')"

echo "=== run 4: a normal incremental run still loads the state ==="
# The cheap scheduled check must not corrupt what real audits depend on.
cat > "$scratch/cs4.json" <<'JSON'
{"mode":"incremental","baseline_run":"20260703-1200",
 "files":{"added":[],"modified":[],"deleted":[],"unchanged":1},
 "lanes":{"python":{"rerun":true,"reason":"scheduled"}}}
JSON
python3 "$S/deltas.py" --state "$home/audit-state.json" --changeset "$scratch/cs4.json" \
    --findings "$scratch/fp.jsonl" --lane-status "$scratch/lane.json" \
    --cve-output "$scratch/cve2.json" --run-id 20260704-1200 \
    --now 2026-07-04T12:00:00Z > "$scratch/m4.json"
persist "$scratch/m4.json" 20260704-1200 incremental
python3 -c "
import json
d=json.load(open('$scratch/m4.json'))
f=d['findings'][0]
# the finding first seen in run 1 is re-verified, not re-reported as NEW:
# the feed-only runs preserved its identity and first_seen
assert f['status']=='REVERIFIED', f['status']
assert f['first_seen']=='20260701-1200', f
assert d['deltas']['new']==0, d['deltas']
# and the feed-only runs' advisory knowledge is the baseline now, so no re-announce
assert d['advisory_deltas']['new']==[], d['advisory_deltas']
print('  post-feeds incremental: REVERIFIED, first_seen intact, no advisory re-announce OK')"

python3 - "$home" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
from secaudit import statestore
st = statestore.load(sys.argv[1])          # must not raise
rows = [json.loads(l) for l in open(sys.argv[1] + "/history.jsonl") if l.strip()]
assert [r["mode"] for r in rows] == ["incremental", "feeds", "feeds", "incremental"], \
    [r["mode"] for r in rows]
assert [r["counts"]["open"] for r in rows] == [1, 1, 1, 1], [r["counts"] for r in rows]
print("  state loads cleanly; history distinguishes 2 feed checks from 2 real audits OK")
PY

echo ""
echo "feeds-only-e2e: OK"
