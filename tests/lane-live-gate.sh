#!/usr/bin/env bash
# lane-live-gate.sh — the one gate per lane that EXECUTES the lane.
#
# Why this exists
# ---------------
# Every other per-lane gate reads a file. `<lane>-e2e.sh` asserts over
# `tests/fixtures/<fixture>/.pipeline/<lane>.jsonl`, a recording a human wrote;
# nothing in that path runs the tool, the lane, or the engine. The 2026-08-27
# audit (docs/plans-notes/pipeline-recording-audit.md) found what that costs:
# two lanes had stopped working and the suite stayed green, and three recordings
# assert findings their tools cannot produce.
#
# So this gate runs `runner.py <lane> <fixture>` for EVERY lane and asserts
# invariants of the run itself. It deliberately does NOT assert finding counts
# or ids — that is what rotted the recordings. Tool versions move; the
# invariants below do not.
#
# One script covering all lanes, rather than one file per lane, is deliberate:
# a per-lane file can be forgotten when a lane is added, and an ungated lane is
# exactly the failure this gate exists to prevent. Lanes are discovered from
# scripts/secaudit/lanes/*.json.
#
# Hermeticity
# -----------
# ci-local.sh is otherwise hermetic and says so. This gate is the documented
# exception: it invokes whatever scanners happen to be installed. On CI, where
# none are, every probe misses and each lane still executes end to end — the
# engine, the lane JSON, the bundled wrappers, the sentinel contract — which is
# already more than any recording proved. On a developer host with tools
# present, the stronger assertions below engage automatically.
#
# Set SECAUDIT_LIVE_GATE=0 to skip entirely (exit 0 with a notice).
#
# Exit 0 on success with the literal line `lane-live-gate: OK`.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

if [ "${SECAUDIT_LIVE_GATE:-1}" = "0" ]; then
    echo "lane-live-gate: SKIPPED (SECAUDIT_LIVE_GATE=0)"
    exit 0
fi

PER_LANE_TIMEOUT="${SECAUDIT_LIVE_GATE_TIMEOUT:-300}"
failures=0
checked=0

for lane_json in scripts/secaudit/lanes/*.json; do
    lane="$(basename "$lane_json" .json)"

    # Fixture: the one carrying this lane's recording, else vulnerable-<lane>.
    fixture=""
    for cand in tests/fixtures/*/.pipeline/"$lane".jsonl; do
        [ -e "$cand" ] || continue
        fixture="$(echo "$cand" | cut -d/ -f3)"
        break
    done
    [ -n "$fixture" ] && [ -d "tests/fixtures/$fixture" ] || fixture="vulnerable-$lane"
    if [ ! -d "tests/fixtures/$fixture" ]; then
        echo "lane-live-gate: SKIP $lane (no fixture)" >&2
        continue
    fi

    # Run against a STAGED COPY, never the tree under tests/fixtures/. Two
    # reasons, both learned the hard way: mobsfscan hard-codes `fixtures` (and
    # `spec`) as ignored path segments, so a lane run in place scanned nothing
    # and reported the absence-of-best-practice rules only; and some tools
    # write next to their input (mobsfscan `--output -` left a file named `-`,
    # cargo tools fill `target/`), which would dirty the checkout. The copy
    # drops `.pipeline/` so a recording is never scanned as if it were source.
    stage="$(mktemp -d)"
    cp -a "tests/fixtures/$fixture" "$stage/"
    rm -rf "$stage/$fixture/.pipeline"
    out="$(mktemp)"; err="$(mktemp)"
    timeout "$PER_LANE_TIMEOUT" python3 scripts/secaudit/runner.py \
        "$lane" "$stage/$fixture" >"$out" 2>"$err"
    rc=$?
    rm -rf "$stage"
    if [ "$rc" -ne 0 ]; then
        echo "lane-live-gate: FAIL — $lane exited $rc" >&2
        sed 's/^/  | /' "$err" | tail -n 8 >&2
        failures=$((failures + 1)); rm -f "$out" "$err"; continue
    fi

    # Everything else is structural, so it lives in python where the lane
    # definition can be read alongside the output it produced.
    if ! python3 - "$lane" "$lane_json" "$out" <<'PY'
import json, os, shutil, sys

lane, lane_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.load(open(lane_path))
origin = spec.get("origin", lane)
key = spec["status_key"]
declared = [t["name"] for t in spec["tools"]]
probes = {}
for t in spec["tools"]:
    p = t["probe"]
    probes[t["name"]] = [p] if isinstance(p, str) else list(p)

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
REQUIRED = ("id", "severity", "title", "file", "line", "evidence", "origin", "tool")
errs = []

lines = [l for l in open(out_path).read().splitlines() if l.strip()]
objs = []
for i, l in enumerate(lines, 1):
    try:
        objs.append(json.loads(l))
    except json.JSONDecodeError as e:
        errs.append(f"line {i} is not JSON: {e}")
if errs:
    print(f"{lane}: " + "; ".join(errs), file=sys.stderr)
    sys.exit(1)

sentinels = [o for o in objs if key in o]
if len(sentinels) != 1:
    errs.append(f"expected exactly 1 {key} record, got {len(sentinels)}")
elif objs[-1] is not sentinels[0]:
    errs.append(f"{key} record is not the last line")

findings = [o for o in objs if key not in o]
sent = sentinels[0] if sentinels else {}
status = sent.get(key)
if status not in ("ok", "partial", "unavailable"):
    errs.append(f"status {status!r} outside ok|partial|unavailable")

ran = list(sent.get("tools") or [])
skipped = list(sent.get("skipped") or [])
failed = list(sent.get("failed") or [])

# A failure is never `ok`: reporting a tool the lane could not read as a clean
# scan is the defect the 2026-08-27 audit found in run_live.
if status == "ok" and (skipped or failed):
    errs.append("status ok despite skipped/failed entries")

if status == "unavailable":
    # The documented unavailable shape is `{status, tools: []}` — it carries no
    # per-tool accounting, so the accounting invariant cannot apply here.
    if ran:
        errs.append(f"status unavailable but tools={ran}")
else:
    # THE invariant. A tool must land in exactly one bucket. Silently belonging
    # to none is how the rust lane reported `ok` with two tools failed and
    # absent, and how the android lane reported `unavailable` over a target it
    # had actually scanned.
    seen = {}
    for name in ran:
        seen.setdefault(name, []).append("tools")
    for entry in skipped:
        seen.setdefault(entry.get("tool"), []).append("skipped")
    for entry in failed:
        seen.setdefault(entry.get("tool"), []).append("failed")
    for name in declared:
        where = seen.get(name, [])
        if len(where) != 1:
            errs.append(f"tool {name!r} appears in {where or 'NO bucket'} "
                        f"(must be exactly one of tools/skipped/failed)")
    for name in seen:
        if name not in declared:
            errs.append(f"sentinel names undeclared tool {name!r}")

# A tool whose binary is on PATH must not be reported missing.
missing_reason = {e.get("tool") for e in skipped
                  if e.get("reason") == "tool-missing"}
for name in declared:
    if name in missing_reason and any(shutil.which(b) for b in probes[name]):
        errs.append(f"tool {name!r} reported tool-missing but its binary is on PATH")

# An INSTALLED tool that the lane could not read means the lane is broken —
# that is precisely the android `--output -` defect, which reported a failure
# honestly and was still a lane that scanned nothing. Honest reporting of a
# failure is necessary, not sufficient.
#
# Exceptions are listed here with a reason rather than tolerated silently. A
# lane on this list still runs and is still checked for everything else; only
# this one assertion is waived, and the entry is a debt with a backlog id.
FAILED_ALLOWED = {
    # Empty since 2026-09-02. The one entry it ever held (rust: cargo-audit and
    # cargo-geiger, whose fixture pinned an unresolvable git dependency and
    # whose invocations carried no {target}) was removed when both were fixed.
    # An entry here is a debt with a backlog id, never a convenience.
}
waived = FAILED_ALLOWED.get(lane, set())
for entry in failed:
    name = entry.get("tool")
    if name in waived:
        continue
    if any(shutil.which(b) for b in probes.get(name, [])):
        errs.append(f"tool {name!r} is installed but the lane could not read it "
                    f"({entry.get('reason')}) — the lane is broken, not the host")

for f in findings:
    for k in REQUIRED:
        if k not in f:
            errs.append(f"finding {f.get('id')!r} missing {k!r}")
    if f.get("origin") != origin:
        errs.append(f"finding {f.get('id')!r} origin {f.get('origin')!r} != {origin!r}")
    if f.get("tool") not in declared:
        errs.append(f"finding {f.get('id')!r} tool {f.get('tool')!r} not declared by the lane")
    if f.get("severity") not in SEVERITIES:
        errs.append(f"finding {f.get('id')!r} severity {f.get('severity')!r} invalid")

if errs:
    for e in errs[:10]:
        print(f"{lane}: {e}", file=sys.stderr)
    sys.exit(1)

print(f"  {lane:<14} {status:<12} ran={len(ran)} skipped={len(skipped)} "
      f"failed={len(failed)} findings={len(findings)}")
PY
    then
        echo "lane-live-gate: FAIL — $lane" >&2
        failures=$((failures + 1))
    fi
    checked=$((checked + 1))
    rm -f "$out" "$err"
done

# ---------------------------------------------------------------------------
# Lane scenario: secrets — a secret deleted from HEAD is still found in history.
#
# The fixture under tests/fixtures/ cannot carry this claim: it is a
# subdirectory of this repo and has no history of its own, so trufflehog
# (a git-history scanner) skips it `no-git-history` and the recording says so.
# The claim is worth a gate of its own because it is the one thing the
# working-tree scan structurally cannot see. Runs only where trufflehog and
# git exist; elsewhere it is reported as skipped, never as passed.
# ---------------------------------------------------------------------------
if command -v trufflehog >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
    repo="$(mktemp -d)"
    cp -a tests/fixtures/vulnerable-secrets/. "$repo/"
    rm -rf "$repo/.pipeline"
    G="git -C $repo -c user.email=fixture@example.invalid -c user.name=fixture -c commit.gpgsign=false"
    git -C "$repo" init -q
    $G add -A && $G commit -q --no-verify -m init
    # A URI with an embedded password (trufflehog `Postgres` detector). Not an
    # AWS-shaped key: GitHub push protection blocks that shape in this script
    # as readily as in a fixture, so it could never be pushed.
    printf 'DATABASE_URL=postgres://admin:S3cretPassw0rd-fixture-only@db.example.internal:5432/app\n' > "$repo/deleted_secrets.txt"
    $G add deleted_secrets.txt && $G commit -q --no-verify -m leak
    $G rm -q deleted_secrets.txt && $G commit -q --no-verify -m remove
    out="$(mktemp)"
    if timeout "$PER_LANE_TIMEOUT" python3 scripts/secaudit/runner.py secrets "$repo" >"$out" 2>/dev/null \
       && [ "$(jq -rs 'map(select(.tool=="trufflehog" and .file=="deleted_secrets.txt")) | length' "$out")" -ge 1 ] \
       && [ "$(tail -n 1 "$out" | jq -r '.tools | index("trufflehog") // empty')" != "" ] \
       && ! grep -q 'S3cretPassw0rd' "$out"; then
        echo "  secrets/history   ok           trufflehog found the deleted file's secret; secret value not echoed"
    else
        echo "lane-live-gate: FAIL — secrets git-history scenario" >&2
        tail -n 3 "$out" | cut -c1-200 | sed 's/^/  | /' >&2
        failures=$((failures + 1))
    fi
    rm -rf "$repo" "$out"
else
    echo "  secrets/history   SKIPPED      (trufflehog or git not on PATH)"
fi

# ---------------------------------------------------------------------------
# Lane scenario: dast — the only URL-driven lane. The generic loop above runs
# it with no URL and can only prove the `no-target-url` skip. Here the fixture
# site is served on a loopback port and the lane is given `--url`, so ZAP
# actually scans something. Needs a local zap-baseline.py or a reachable
# docker daemon (the official image is pulled on first use); otherwise
# reported as skipped, never as passed. Takes 1-2 minutes with docker.
# ---------------------------------------------------------------------------
if [ "${SECAUDIT_LIVE_DAST:-1}" != "0" ] && { command -v zap-baseline.py >/dev/null 2>&1 \
     || { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }; }; then
    port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    ( cd tests/fixtures/dast-target/site && exec python3 -m http.server "$port" --bind 127.0.0.1 ) >/dev/null 2>&1 &
    http_pid=$!
    sleep 1
    out="$(mktemp)"
    if timeout 900 python3 scripts/secaudit/runner.py dast tests/fixtures/dast-target \
            --url "http://127.0.0.1:$port" >"$out" 2>/dev/null \
       && [ "$(tail -n 1 "$out" | jq -r '.__dast_status__')" = "ok" ] \
       && [ "$(jq -rs 'map(select(.tool=="zap-baseline" and .origin=="dast")) | length' "$out")" -ge 1 ]; then
        echo "  dast/live-url     ok           zap-baseline scanned the served fixture: $(jq -rs 'map(select(.tool=="zap-baseline")) | length' "$out") findings"
    else
        echo "lane-live-gate: FAIL — dast live-url scenario" >&2
        tail -n 2 "$out" | cut -c1-200 | sed 's/^/  | /' >&2
        failures=$((failures + 1))
    fi
    kill "$http_pid" 2>/dev/null; rm -f "$out"
else
    echo "  dast/live-url     SKIPPED      (no zap-baseline.py and no docker daemon, or SECAUDIT_LIVE_DAST=0)"
fi

echo ""
if [ "$failures" -ne 0 ]; then
    echo "lane-live-gate: FAIL — $failures of $checked lane(s)" >&2
    exit 1
fi
echo "lane-live-gate: OK ($checked lanes executed)"
