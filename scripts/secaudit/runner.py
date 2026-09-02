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
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

LANES = os.path.join(os.path.dirname(__file__), "lanes")

# Never feed tool invocations files from VCS metadata or vendored dependency
# trees. Without this, a scan of a git repo (e.g. --diff mode) would pass
# `.git/**` internals and `node_modules/**` to the lane's tool. NOTE: unlike
# inventory.py's SKIP_DIRS, this deliberately does NOT prune build/dist/target —
# those hold scannable BUILT ARTIFACTS (android apkleaks reads
# `build/outputs/apk/*.apk`; the image/windows lanes read tarballs/PEs there).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "vendor",
             ".pipeline"}


def _walk(target):
    """os.walk over target, pruning SKIP_DIRS in place."""
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        yield root, dirs, files


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
         "fallback":spec, "default":d}
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
        sval = str(val)
        if sval in tbl:
            return tbl[sval]
        # lookup_prefix: match a table key that is a prefix of the value — lets a
        # sniff FAMILY (e.g. "WordPress.DB.PreparedSQL") map every sub-code
        # ("...PreparedSQLPlaceholders.LikeWildcardsInQuery") without enumerating
        # them. Keys are checked longest-first so a more specific prefix wins.
        if spec.get("lookup_prefix"):
            for k in sorted(tbl, key=len, reverse=True):
                if sval.startswith(k):
                    return tbl[k]
        return default
    if val is None:
        # `fallback`: a second spec tried only when the first resolves to
        # nothing (cargo-audit: prefer the CVE alias, else the RUSTSEC id).
        if "fallback" in spec:
            return _field(spec["fallback"], item)
        return default
    if spec.get("int"):
        try:
            val = int(str(val).split("-")[0].split(":")[0])
        except (ValueError, TypeError):
            return default
    if spec.get("truncate"):
        val = str(val)[:spec["truncate"]]
    if "regex" in spec:                         # extract a match from the value
        import re
        m = re.search(spec["regex"], str(val))
        if not m:
            return default
        return m.group(1) if m.groups() else m.group(0)
    if "before" in spec:                       # substring before a delimiter
        val = str(val).split(spec["before"])[0]
    if spec.get("cvss_band"):                   # numeric CVSS base score -> severity tier
        try:
            sc = float(val)
        except (TypeError, ValueError):
            return spec.get("default", "MEDIUM")
        return ("CRITICAL" if sc >= 9 else "HIGH" if sc >= 7
                else "MEDIUM" if sc >= 4 else "LOW" if sc > 0 else "MEDIUM")
    return val


def map_item(lane, toolcfg, block, ctx):
    out = dict(lane.get("finding_const", {}))  # lane defaults
    for fld, spec in block["map"].items():
        out[fld] = _field(spec, ctx)
    if out.get("line") is None:
        out["line"] = 1
    out.update(toolcfg.get("const", {}))    # tool-wide const
    out.update(block.get("const", {}))      # per-source const (e.g. kubesec critical->HIGH) wins
    out["reference"] = lane["reference"]
    out["origin"] = lane["origin"]
    out["tool"] = toolcfg["name"]
    return out


def _flatten(arr, flatten, flatten_missing=None):
    """Walk `flatten` (None | key | [keys...]) producing (leaf, immediate_parent)
    pairs. Nested keys (e.g. ["packages","vulnerabilities"]) descend levels;
    the leaf's immediate parent is exposed to the map as `_parent`.
    `flatten_missing: "self"` keeps a parent that has no children under the
    key as a leaf of its own instead of dropping it."""
    if not flatten:
        return [(it, None) for it in arr]
    keys = [flatten] if isinstance(flatten, str) else list(flatten)
    level = [(it, None) for it in arr]
    for k in keys:
        nxt = []
        for parent, _gp in level:
            if not isinstance(parent, dict):
                continue
            if flatten_missing == "self" and not _get(parent, k):
                # The parent carries no children under this key. mobsfscan's
                # app-wide rules are the live case: "does not use certificate
                # pinning" has no `files` array because it is a claim about
                # the whole target, not a line in it. With plain `flatten` such
                # a rule is discarded, which is how the repaired android lane
                # reported 0 findings while 6 rules fired. Yield the parent as
                # its own leaf (and its own `_parent`, so the same `_parent.*`
                # map applies); per-file fields fall to their map defaults.
                nxt.append((parent, parent))
                continue
            # Dotted keys descend several levels in one step, so the leaf's
            # `_parent` stays the element that carries the identifying fields
            # rather than an intermediate wrapper (e.g. guarddog's
            # "result.results" keeps `dependency`/`version` reachable).
            val = _get(parent, k)
            if isinstance(val, dict):
                # A rule-keyed object rather than an array — the same shape
                # `iterate: "values"` handles at the base level. Iterate the
                # values and expose the key as `_key`, so the rule name is
                # mappable. Previously this fell through to iterating the dict,
                # which yields KEYS (strings) and silently produced no usable
                # findings.
                for rule, hits in val.items():
                    if hits is None or hits is False:
                        continue          # rule ran, did not match
                    if isinstance(hits, dict):
                        hits = [hits]
                    elif isinstance(hits, (str, int, float, bool)):
                        # A rule may store its message directly instead of a list
                        # of hits — guarddog's metadata detectors do exactly this
                        # (`results[rule] = message`), while its source-code rules
                        # append dicts. Iterating a string would walk characters
                        # and silently yield nothing, so lift it into one finding.
                        hits = [{"message": str(hits)}]
                    for child in (hits or []):
                        if isinstance(child, dict):
                            nxt.append(({**child, "_key": rule}, parent))
            else:
                for child in (val or []):
                    nxt.append((child, parent))
        level = nxt
    return level


def _passes_filter(filt, ctx):
    if not filt:
        return True
    if isinstance(filt, list):                  # every clause must pass
        return all(_passes_filter(f, ctx) for f in filt)
    val = _get(ctx, filt["field"])
    if "startswith" in filt:
        return isinstance(val, str) and val.startswith(filt["startswith"])
    if "equals" in filt:
        return val == filt["equals"]
    if "in" in filt:
        return val in filt["in"]
    if "not_in" in filt:
        # Exclusion list: a tool whose diagnostics mix security findings with
        # config/licence lint (cargo-deny) keeps every code it may add later
        # and drops only the families named here.
        return val not in filt["not_in"]
    if "gt" in filt:
        try:
            return float(val) > float(filt["gt"])
        except (TypeError, ValueError):
            return False
    return True


def _blocks(toolcfg):
    """A tool is either a single block (top-level findings_path/flatten/map/const)
    or a list of `sources` (each its own findings_path/flatten/filter/map/const),
    whose findings are unioned. Multi-source covers tools that emit several
    independent arrays (kubesec critical/advise; addons-linter errors/warnings/notices)."""
    return toolcfg.get("sources") or [toolcfg]


def _xml_items(text, tag):
    """Parse XML (e.g. android-lint) into dicts: each `<tag attr=..>` element's
    attributes become keys; each child element's attributes become a nested dict
    under the child's tag (first child per tag wins)."""
    import re
    # Harden against XML entity-expansion (billion-laughs / quadratic blowup):
    # legitimate tool output never declares a DTD, so refuse any document that
    # does rather than hand it to expat. Stdlib-only — defusedxml would break
    # the no-third-party-deps design.
    if re.search(r"<!DOCTYPE|<!ENTITY", text):
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    items = []
    for el in root.iter(tag):
        d = dict(el.attrib)
        for child in el:
            d.setdefault(child.tag, dict(child.attrib))
        items.append(d)
    return items


def _validator_items(lane, toolcfg, tsv_text):
    r"""Synthesize one finding per failing (rc != 0) per-file validator row.
    Input is TSV: <relpath>\t<rc>\t<message>. For pass/fail validators
    (virt-xml-validate, and later sing-box/xray/jq) that emit no findings
    array — a finding is synthesized from the validator's diagnostic, never
    mapped from JSON. `dedupe_by: "file"` keeps the first failing diagnostic
    per file; `line_regex` lifts a line number from the message."""
    import re
    synth = toolcfg["synth"]
    line_re = toolcfg.get("line_regex")
    dedupe = toolcfg.get("dedupe_by")
    seen = set()
    out = []
    for row in tsv_text.splitlines():
        if not row.strip():
            continue
        parts = row.split("\t", 2)
        if len(parts) < 2:
            continue
        rel, rc = parts[0], parts[1]
        msg = parts[2] if len(parts) > 2 else ""
        try:
            if int(rc) == 0:
                continue
        except ValueError:
            continue
        if dedupe == "file":
            if rel in seen:
                continue
            seen.add(rel)
        line = 0
        if line_re:
            m = re.search(line_re, msg)
            if m:
                line = int(m.group(1))
        # `message_regex` narrows a chatty validator's combined output to the
        # part that is actually the diagnostic. xray prints a version banner and
        # a run of [Info] lines before its error, and without this the finding's
        # title would be the banner. Group 1 if the pattern captures, else the
        # whole match; no match leaves the message as-is rather than blanking
        # it, so a changed output format degrades to noisy, never to empty.
        msg_re = toolcfg.get("message_regex")
        if msg_re:
            mm = re.search(msg_re, msg)
            if mm:
                msg = mm.group(1) if mm.groups() else mm.group(0)
        snippet = msg[:200]
        f = dict(lane.get("finding_const", {}))
        for k, v in synth.items():
            f[k] = v.replace("{msg}", snippet) if isinstance(v, str) else v
        f["file"] = rel
        f["line"] = line
        f["reference"] = lane["reference"]
        f["origin"] = lane["origin"]
        f["tool"] = toolcfg["name"]
        out.append(f)
    return out


def map_raw(lane, toolcfg, raw_text):
    if toolcfg.get("mode") == "validator":
        return _validator_items(lane, toolcfg, raw_text)
    fmt = toolcfg.get("input_format")
    if fmt == "jsonl":
        preitems, data = [json.loads(l) for l in raw_text.splitlines() if l.strip()], None
    elif fmt == "xml":
        preitems, data = _xml_items(raw_text, toolcfg.get("xml_item", "issue")), None
    else:
        preitems, data = None, json.loads(raw_text)
    out = []
    for block in _blocks(toolcfg):
        if preitems is not None:
            base = preitems
        else:
            fp = block.get("findings_path")
            base = (_get(data, fp) or []) if fp else (data if isinstance(data, list) else [])
            if block.get("iterate") == "values" and isinstance(base, dict):
                # tool emits a rule-keyed object (e.g. njsscan {"nodejs":{rule:{...}}});
                # iterate the values, exposing the key as `_key`.
                base = [{**v, "_key": k} for k, v in base.items() if isinstance(v, dict)]
        filt = block.get("filter")
        for leaf, parent in _flatten(base, block.get("flatten"),
                                     block.get("flatten_missing")):
            ctx = leaf if parent is None else {**leaf, "_parent": parent}
            if not _passes_filter(filt, ctx):
                continue
            out.append(map_item(lane, toolcfg, block, ctx))
    return out


def _in_scope(target, path, scope):
    """True when `path` is within the --diff changed-file scope (or scope is off)."""
    if scope is None:
        return True
    return os.path.relpath(path, target) in scope


def _probe_bin(toolcfg):
    """First available binary named by `probe`, or None.

    `probe` is normally one name. It may also be a LIST of interchangeable
    names, for a tool published under more than one (mcp-scan also ships as
    snyk-agent-scan). The resolved name is substituted for `{probe}` in
    `invoke`, so a wrapper is handed the binary that was actually found rather
    than re-deriving it and possibly disagreeing with the probe."""
    probe = toolcfg["probe"]
    names = [probe] if isinstance(probe, str) else list(probe)
    for n in names:
        if shutil.which(n):
            return n
    return None


def _build_argv(invoke, target, tmp, scope=None, probe=None):
    """Substitute {target}/{tmp}/{probe}; expand a `{files:GLOB}` arg into the
    matching files under target (for tools that take a file list, e.g.
    shellcheck). When `scope` is a set of changed relpaths (--diff), only those
    files are passed."""
    import fnmatch
    argv = []
    for a in invoke:
        if a.startswith("{files:") and a.endswith("}"):
            globs = a[len("{files:"):-1].split("|")    # any-of, for tools that
            for root, _d, files in _walk(target):      # match several name shapes
                for fn in sorted(files):
                    if any(fnmatch.fnmatch(fn, g) for g in globs):
                        p = os.path.join(root, fn)
                        if _in_scope(target, p, scope):
                            argv.append(p)
        else:
            argv.append(a.replace("{target}", target)
                         .replace("{tmp}", tmp)
                         .replace("{probe}", probe or "")
                         .replace("{scripts}", os.path.dirname(os.path.abspath(__file__))))
    return argv


def _applicable(toolcfg, target, scope=None):
    # Semantic applicability predicate (not a filename glob). "git-repo" mirrors
    # inventory.py's own .git check exactly, so a tool gated on repo-ness (e.g.
    # trufflehog history scan) stays in lockstep with the inventory — including
    # git worktrees / submodules where `.git` is a redirect FILE, not a dir.
    when = toolcfg.get("applicable_when")
    if when == "git-repo":
        return os.path.exists(os.path.join(target, ".git"))
    glob = toolcfg.get("applicable_glob")
    if not glob:
        return True
    globs = [glob] if isinstance(glob, str) else list(glob)
    import fnmatch
    for root, _dirs, files in _walk(target):
        for fn in files:
            if any(fnmatch.fnmatch(fn, g) for g in globs):
                if _in_scope(target, os.path.join(root, fn), scope):
                    return True
    return False


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _select_files(target, fsel, scope=None):
    """Files a validator should check: name-glob match, optional content grep
    (e.g. *.xml containing a libvirt root element). Mirrors the agent's
    `find ... -exec grep -l` precondition."""
    import fnmatch
    import re
    globs = fsel.get("glob", "*").split("|")   # any-of, as in {files:a|b}
    rx = re.compile(fsel["grep"]) if fsel.get("grep") else None
    sel = []
    for root, _d, files in _walk(target):
        for fn in sorted(files):
            if not any(fnmatch.fnmatch(fn, g) for g in globs):
                continue
            p = os.path.join(root, fn)
            if not _in_scope(target, p, scope):
                continue
            if rx is not None:
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        if not rx.search(fh.read()):
                            continue
                except OSError:
                    continue
            sel.append(p)
    return sel


def _relativize(fobj, target):
    """A `file` the tool reported as an absolute path under the target becomes
    target-relative. mobsfscan and others echo the path they were handed, and
    an absolute path would make the finding's fingerprint (which hashes
    `file`) specific to the host and the checkout location, so the same
    finding would read as NEW on every machine and every re-clone."""
    f = fobj.get("file")
    if not isinstance(f, str) or not os.path.isabs(f):
        return
    root = os.path.abspath(target)
    try:
        rel = os.path.relpath(f, root)
    except ValueError:
        return
    if not rel.startswith(".."):
        fobj["file"] = rel


def run_live(lane, target, scope=None):
    findings = []
    # `failed` is the third outcome the runner contracts have always documented
    # (windows-runner.md: "Build tools_available, tools_clean_skipped,
    # tools_failed") and that this engine did not implement. Without it a tool
    # whose output would not parse was appended to NEITHER list: it vanished
    # from the sentinel, and a lane where 2 of 3 tools failed still reported
    # `ok` with 0 findings — a clean bill of health over an unscanned target.
    ran, skipped, failed = [], [], []
    tmp = tempfile.mkdtemp()
    for tc in lane["tools"]:
        probe_bin = _probe_bin(tc)
        if probe_bin is None:
            skipped.append({"tool": tc["name"], "reason": "tool-missing"})
            continue
        if tc.get("mode") == "validator":
            files = _select_files(target, tc.get("file_select", {}), scope)
            if not files:
                skipped.append({"tool": tc["name"],
                                "reason": tc.get("inapplicable_reason", "tool-missing")})
                continue
            rows = []
            for fp in files:
                argv = [a.replace("{file}", fp)
                         .replace("{target}", target)
                         .replace("{probe}", probe_bin)
                         .replace("{scripts}", os.path.dirname(os.path.abspath(__file__)))
                        for a in tc["invoke"]]
                try:
                    proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)
                except Exception as e:
                    sys.stderr.write(f"runner: {tc['name']} failed on {fp}: {e}\n")
                    continue
                rel = os.path.relpath(fp, target)
                # Strip ANSI SGR sequences: sing-box colourises its diagnostics,
                # and the raw escapes would land in a finding's title/evidence
                # and render as garbage in the report.
                combined = _ANSI_RE.sub("", proc.stdout + proc.stderr)
                combined = combined.replace("\t", " ").replace("\n", " ").strip()
                rows.append(f"{rel}\t{proc.returncode}\t{combined}")
            try:
                findings.extend(map_raw(lane, tc, "\n".join(rows)))
                ran.append(tc["name"])
            except Exception as e:
                sys.stderr.write(f"runner: {tc['name']} parse failed: {e}\n")
                failed.append({"tool": tc["name"], "reason": "parse-failed"})
            continue
        if not _applicable(tc, target, scope):
            skipped.append({"tool": tc["name"],
                            "reason": tc.get("inapplicable_reason", "tool-missing")})
            continue
        argv = _build_argv(tc["invoke"], target, tmp, scope, probe_bin)
        env = os.environ.copy()
        # `{tmp}`/`{target}` substitute in env values too, so a tool that
        # writes build output next to its input (cargo-geiger compiles the
        # target and fills `target/`) can be pointed at the scratch dir and
        # honour rule 6 of every runner contract: never write into the
        # caller's project.
        env.update({k: str(v).replace("{tmp}", tmp).replace("{target}", target)
                    for k, v in tc.get("env", {}).items()})
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=env)
        except Exception as e:
            sys.stderr.write(f"runner: {tc['name']} failed: {e}\n")
            failed.append({"tool": tc["name"], "reason": "run-failed"})
            continue
        rc_reasons = tc.get("rc_reasons")
        if rc_reasons and proc.returncode != 0:
            # A bundled wrapper that distinguishes "nothing of my shape is here"
            # (a clean skip, with this tool's own reason) from "I failed". One
            # exit code per outcome beats a boolean, because a lane's clean-skip
            # vocabulary is per-tool and a failure is not a skip.
            reason = rc_reasons.get(str(proc.returncode)) or rc_reasons.get("*")
            if reason:
                skipped.append({"tool": tc["name"], "reason": reason})
                continue
        if tc.get("fail_on_rc") and proc.returncode != 0:
            # A bundled wrapper opts into this: non-zero means it could not
            # finish reading the target. Its findings are still mapped below —
            # what changes is that the lane reports `partial` with a reason
            # instead of a clean `ok` over a target it did not fully inspect.
            # Deliberately NOT applied to external tools, which routinely exit
            # non-zero merely because they found something.
            skipped.append({"tool": tc["name"],
                            "reason": tc.get("failure_reason", "run-incomplete")})
        out = tc["output"]
        if out == "stdout":
            raw = proc.stdout
        elif out == "stderr":
            # cargo-deny writes every diagnostic, JSON format included, to
            # stderr and nothing to stdout.
            raw = proc.stderr
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
            # The tool's own last words are the only clue to WHY its output
            # would not parse (a build error, a missing index, a usage
            # error); without them a failure is a bare reason code.
            tail = (proc.stderr or "").strip().splitlines()[-5:]
            for ln in tail:
                sys.stderr.write(f"runner:   {tc['name']} stderr: {ln[:300]}\n")
            failed.append({"tool": tc["name"], "reason": "parse-failed"})
    for fobj in findings:
        _relativize(fobj, target)
        sys.stdout.write(json.dumps(fobj) + "\n")
    # A failure is never `ok`. A clean skip is a decision the lane made; a
    # failure is a tool the lane could not read, and reporting that as `ok`
    # states coverage the run does not have.
    status = ("ok" if ran and not skipped and not failed
              else ("partial" if ran else "unavailable"))
    sentinel = {lane["status_key"]: status if ran else "unavailable",
                "tools": sorted(ran), "runs": len(ran), "findings": len(findings)}
    if skipped:
        sentinel["skipped"] = skipped
    if failed:
        sentinel["failed"] = failed
    if not ran:
        sentinel = {lane["status_key"]: "unavailable", "tools": []}
        if failed:
            sentinel["failed"] = failed
    sys.stdout.write(json.dumps(sentinel) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lane")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--map-only")
    ap.add_argument("--tool")
    ap.add_argument("--files", help="changed-file list (--diff scoping): one relpath per line")
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
    scope = None
    if args.files:
        with open(args.files, encoding="utf-8") as f:
            scope = {ln.strip() for ln in f if ln.strip()}
    run_live(lane, args.target, scope)


if __name__ == "__main__":
    main()
