#!/usr/bin/env python3
"""Config-driven sec-audit runner engine (replaces per-lane LLM field-mapping).

A lane is a declarative JSON config under scripts/secaudit/lanes/<lane>.json
(the *-tools.md recipe table, machine-readable). The engine probes the lane's
tools, runs them, parses native JSON, maps fields to the sec-audit finding
schema, and emits JSONL + the __<lane>_status__ sentinel — identical contract
to the LLM runner agents, now deterministic.

Modes:
  runner.py <lane> <target>            probe -> run -> map -> emit + sentinel
  runner.py <lane> --map-only <raw> --tool <name>
                                       map a recorded raw tool output (no run;
                                       used by parity tests). Emits findings only.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

LANES = os.path.join(os.path.dirname(__file__), "lanes")


def load_lane(name):
    with open(os.path.join(LANES, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def _get(obj, path):
    """Navigate a dotted path through dicts (and list indices: numeric segment).
    Returns None if any step is missing."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _field(spec, item):
    """Resolve a field spec:
      - str            -> dotted path lookup
      - {"concat":[lit|spec,...], "default":d}  -> string concat (literal strings
        as-is, dict parts resolved; if any dict part is None -> default)
      - {"from":path, "map"/"lookup":{}, "index":i, "int":true, "truncate":N,
         "default":d}
    """
    if isinstance(spec, str):
        return _get(item, spec)
    if not isinstance(spec, dict):
        return spec
    if "concat" in spec:
        parts = []
        for p in spec["concat"]:
            if isinstance(p, str):
                parts.append(p)
            else:
                v = _field(p, item)
                if v is None:
                    return spec.get("default")
                parts.append(str(v))
        return "".join(parts)
    default = spec.get("default")
    val = _get(item, spec["from"]) if "from" in spec else None
    if "index" in spec:
        if isinstance(val, list) and len(val) > spec["index"]:
            val = val[spec["index"]]
        else:
            return default
    if "map" in spec:
        return spec["map"].get(val, default)
    if "lookup" in spec:
        # JSON lookup keys are strings; coerce numeric tool codes (e.g. shellcheck
        # code 2129) so they match "2129".
        tbl = spec["lookup"]
        if val in tbl:
            return tbl[val]
        return tbl.get(str(val), default)
    if val is None:
        return default
    if spec.get("int"):
        try:
            val = int(str(val).split("-")[0].split(":")[0])
        except (ValueError, TypeError):
            return default
    if spec.get("truncate"):
        val = str(val)[:spec["truncate"]]
    return val


def map_item(lane, toolcfg, item):
    out = {}
    for fld, spec in toolcfg["map"].items():
        out[fld] = _field(spec, item)
    if out.get("line") is None:
        out["line"] = 1
    out.update(toolcfg.get("const", {}))
    out.update(lane.get("finding_const", {}))
    out["reference"] = lane["reference"]
    out["origin"] = lane["origin"]
    out["tool"] = toolcfg["name"]
    return out


def map_raw(lane, toolcfg, raw_text):
    if toolcfg.get("input_format") == "jsonl":
        # one JSON object per line (e.g. staticcheck -f json)
        arr = [json.loads(l) for l in raw_text.splitlines() if l.strip()]
    else:
        data = json.loads(raw_text)
        fp = toolcfg.get("findings_path")
        if fp:
            arr = _get(data, fp) or []
        else:
            arr = data if isinstance(data, list) else []  # tool emits a root array
    return [map_item(lane, toolcfg, it) for it in arr]


def _build_argv(invoke, target, tmp):
    """Substitute {target}/{tmp}; expand a `{files:GLOB}` arg into the matching
    files under target (for tools that take a file list, e.g. shellcheck)."""
    import fnmatch
    argv = []
    for a in invoke:
        if a.startswith("{files:") and a.endswith("}"):
            glob = a[len("{files:"):-1]
            for root, _d, files in os.walk(target):
                for fn in sorted(files):
                    if fnmatch.fnmatch(fn, glob):
                        argv.append(os.path.join(root, fn))
        else:
            argv.append(a.replace("{target}", target).replace("{tmp}", tmp))
    return argv


def _applicable(toolcfg, target):
    glob = toolcfg.get("applicable_glob")
    if not glob:
        return True
    import fnmatch
    for root, _dirs, files in os.walk(target):
        for fn in files:
            if fnmatch.fnmatch(fn, glob):
                return True
    return False


def run_live(lane, target):
    findings = []
    ran, skipped = [], []
    tmp = tempfile.mkdtemp()
    for tc in lane["tools"]:
        if not shutil.which(tc["probe"]):
            skipped.append({"tool": tc["name"], "reason": "tool-missing"})
            continue
        if not _applicable(tc, target):
            skipped.append({"tool": tc["name"],
                            "reason": tc.get("inapplicable_reason", "tool-missing")})
            continue
        argv = _build_argv(tc["invoke"], target, tmp)
        env = os.environ.copy()
        env.update(tc.get("env", {}))
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=env)
        except Exception as e:
            sys.stderr.write(f"runner: {tc['name']} failed: {e}\n")
            continue
        out = tc["output"]
        if out == "stdout":
            raw = proc.stdout
        elif out.startswith("file:"):
            path = out[5:].replace("{tmp}", tmp)
            raw = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        else:
            raw = ""
        try:
            findings.extend(map_raw(lane, tc, raw))
            ran.append(tc["name"])
        except Exception as e:
            sys.stderr.write(f"runner: {tc['name']} parse failed: {e}\n")
    for fobj in findings:
        sys.stdout.write(json.dumps(fobj) + "\n")
    status = "ok" if ran and not skipped else ("partial" if ran else "unavailable")
    sentinel = {lane["status_key"]: status if ran else "unavailable",
                "tools": sorted(ran), "runs": len(ran), "findings": len(findings)}
    if skipped:
        sentinel["skipped"] = skipped
    if not ran:
        sentinel = {lane["status_key"]: "unavailable", "tools": []}
    sys.stdout.write(json.dumps(sentinel) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lane")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--map-only")
    ap.add_argument("--tool")
    args = ap.parse_args()
    lane = load_lane(args.lane)
    if args.map_only:
        tc = next(t for t in lane["tools"] if t["name"] == args.tool)
        raw = open(args.map_only, encoding="utf-8").read()
        for fobj in map_raw(lane, tc, raw):
            sys.stdout.write(json.dumps(fobj) + "\n")
        return
    if not args.target:
        ap.error("target required unless --map-only")
    run_live(lane, args.target)


if __name__ == "__main__":
    main()
