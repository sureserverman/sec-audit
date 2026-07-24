#!/usr/bin/env python3
"""Decide what changed since the last audit, and which lanes must re-run (§2.5).

Consumes the previous state (statestore) + the current file manifest
(fingerprint.py) and emits a changeset the orchestrator reads once:

  {"mode", "baseline_run", "files": {added, modified, deleted, unchanged},
   "lanes": {<lane>: {rerun, reason, files, carried}}, "invalidations": [...]}

**The bias is always toward re-running.** A lane is skipped only when we can
positively show nothing it looks at has changed, its own definition is
byte-identical, its last run succeeded, and it is not stale. Anything we cannot
prove — an unknown lane, an unreadable state, a lane whose last run degraded —
re-runs. The cost of a needless re-run is tokens; the cost of a wrongly skipped
lane is an unreported vulnerability.

Rerun triggers, evaluated in this fixed order (first match wins, and the matched
reason is carried into the report so a reader can always see why something was
or was not re-checked):

  1. --full / no baseline / unknown lane      (unconditional)
  2. lane definition digest changed            (new rules ⇒ old verdict is stale)
  3. an applicable file was added/modified/deleted
  4. the lane's previous run did not end `ok`  (degraded ⇒ never trust the gap)
  5. the lane's tool versions changed
  6. staleness TTL exceeded (default 30 days)
  7. the lane is always-on by nature (secrets / dast)

Usage:
  changeset.py --target <path> --manifest <manifest.json> [--state <state.json>]
               [--lanes <inventory.json>] [--full] [--staleness-days N]
               [--now <ISO8601>] [--tool-versions <json>]
"""
import fnmatch
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_STALENESS_DAYS = 30

# Which file shapes each lane actually looks at. A lane MISSING from this map is
# not assumed safe to skip — it re-runs unconditionally (see ALWAYS_RERUN_REASON).
# Patterns are fnmatch against the target-relative path AND its basename, so
# both "*.py" and ".github/workflows/*" work.
LANE_PATTERNS = {
    # broad code reasoning — any source or config change is in scope
    "sec-expert": ["*"],
    "sast": ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java", "*.rb",
             "*.php", "*.c", "*.cc", "*.cpp", "*.cs", "*.scala", "*.kt", "*.swift"],
    "python": ["*.py", "requirements*.txt", "pyproject.toml", "poetry.lock",
               "Pipfile", "Pipfile.lock", "uv.lock", "setup.py", "setup.cfg", "tox.ini"],
    "go": ["*.go", "go.mod", "go.sum"],
    "shell": ["*.sh", "*.bash", "*.ksh", "*.zsh", "*.dash"],
    "rust": ["*.rs", "Cargo.toml", "Cargo.lock", "deny.toml", "rust-toolchain*"],
    "c-cpp": ["*.c", "*.cc", "*.cpp", "*.cxx", "*.c++", "*.h", "*.hpp", "*.hxx"],
    "php": ["*.php", "composer.json", "composer.lock", "*.inc"],
    "iac": ["*.tf", "*.tfvars", "*.hcl", "*.tfstate"],
    "gh-actions": [".github/workflows/*", ".github/actions/*", "action.yml", "action.yaml"],
    "virt": ["Dockerfile*", "Containerfile*", "*.dockerfile", "*.containerfile",
             "docker-compose*.yml", "docker-compose*.yaml", "compose*.yml",
             "compose*.yaml", "*.compose.yml", "*.compose.yaml", "*.xml"],
    "k8s": ["*.yml", "*.yaml"],
    "ansible": ["*.yml", "*.yaml", "ansible.cfg", "inventory*", "*.j2"],
    "webext": ["manifest.json", "*.js", "*.ts", "*.html", "*.css", "*.json"],
    "webapp": ["*.js", "*.ts", "*.jsx", "*.tsx", "*.vue", "*.svelte", "*.rb", "*.py",
               "*.php", "*.go", "*.java", "*.erb", "*.blade.php", "Gemfile", "Gemfile.lock"],
    "android": ["*.java", "*.kt", "*.kts", "AndroidManifest.xml", "*.gradle",
                "*.apk", "*.aar", "*.xml", "*.pro", "gradle.lockfile"],
    "ios": ["*.swift", "*.m", "*.mm", "*.h", "Info.plist", "*.pbxproj",
            "Package.swift", "Package.resolved", "Podfile", "Podfile.lock", "*.entitlements"],
    "macos": ["*.plist", "*.pkg", "*.dmg", "*.app", "*.swift", "*.m", "*.entitlements"],
    "windows": ["*.exe", "*.dll", "*.msi", "*.msix", "*.csproj", "*.sln", "*.ps1", "*.manifest"],
    "linux": ["*.service", "*.socket", "*.timer", "*.desktop", "debian/*", "*.spec",
              "*.deb", "*.rpm", "*.AppImage"],
    "image": ["*.tar", "*sbom.json", "*.oci", "index.json", "oci-layout"],
    "ai-tools": ["plugin.json", ".mcp.json", "opencode.json", "*.claude/*", "*.cursor/*",
                 "AGENTS.md", "SKILL.md", "*.mdc", "agents/*.md", "skills/*", "commands/*.md",
                 "hooks*.json", "settings.json"],
    "netcfg": ["torrc*", "*.conf", "wg*.conf", "config.json", "sing-box*.json", "xray*.json"],
    "supply-chain": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                     "requirements*.txt", "pyproject.toml", "poetry.lock", "uv.lock",
                     "Pipfile.lock"],
}

# Lanes whose inputs are NOT the working tree, so a file manifest can never
# prove they are unchanged (§2 already carves these out for --diff):
#   secrets — gitleaks scans the tree but trufflehog scans git HISTORY, which
#             grows on every commit independently of the working tree.
#   dast    — the input is a running instance; its state is invisible to hashes.
ALWAYS_ON = {
    "secrets": "always-on: trufflehog scans git history, which changes independently of the tree",
    "dast": "always-on: the target is a live instance, not a file tree",
}

ALWAYS_RERUN_REASON = "no change-signature defined for this lane — re-running (fail-safe)"


def _digest_file(path, h):
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 16), b""):
                h.update(block)
    except OSError:
        h.update(b"<missing>")


def _digest_tree(root, h):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            h.update(os.path.relpath(p, root).encode("utf-8"))
            _digest_file(p, h)


def lane_digest(lane, plugin_root=PLUGIN_ROOT):
    """Digest of everything that defines what this lane detects.

    If the rules change, last run's verdict is stale even when no project file
    moved — this is the trigger that stops a new scanner rule from being
    invisible to an unchanged tree."""
    h = hashlib.sha256()
    h.update(lane.encode("utf-8"))
    _digest_file(os.path.join(plugin_root, "scripts", "secaudit", "lanes", f"{lane}.json"), h)
    _digest_file(os.path.join(plugin_root, "agents", f"{lane}-runner.md"), h)
    if lane == "sec-expert":
        _digest_file(os.path.join(plugin_root, "agents", "sec-expert.md"), h)
        # sec-expert reasons out of the reference packs; a changed pack is a
        # changed detector.
        refs = os.path.join(plugin_root, "skills", "sec-audit", "references")
        if os.path.isdir(refs):
            _digest_tree(refs, h)
    else:
        _digest_file(os.path.join(plugin_root, "scripts", "secaudit", "runner.py"), h)
    return h.hexdigest()[:16]


def matches(rel, patterns):
    base = os.path.basename(rel)
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


def diff_manifests(old, new):
    old = old or {}
    new = new or {}
    added = sorted(k for k in new if k not in old)
    deleted = sorted(k for k in old if k not in new)
    modified = sorted(k for k in new
                      if k in old and new[k].get("sha256") != old[k].get("sha256"))
    unchanged = sorted(k for k in new
                       if k in old and new[k].get("sha256") == old[k].get("sha256"))
    return {"added": added, "modified": modified, "deleted": deleted,
            "unchanged": unchanged}


def diff_deps(old, new):
    """Classify the dependency set added / removed / version_changed / unchanged.

    Keyed by `ecosystem|name`, because the same package name in two ecosystems
    is two different packages. A version change is detected even when the
    manifest FILE hash is unchanged — a transitive bump inside a regenerated
    lockfile still moves a version, and that alone justifies re-querying the
    feeds for that package."""
    old = old or {}
    new = new or {}
    added, removed, changed, unchanged = [], [], [], []
    for key, meta in sorted(new.items()):
        if key not in old:
            added.append({"package": key, "version": meta.get("version")})
        elif old[key].get("version") != meta.get("version"):
            changed.append({"package": key, "from": old[key].get("version"),
                            "to": meta.get("version")})
        else:
            unchanged.append(key)
    for key, meta in sorted(old.items()):
        if key not in new:
            removed.append({"package": key, "version": meta.get("version")})
    return {"added": added, "removed": removed, "version_changed": changed,
            "unchanged": len(unchanged),
            # Every package whose identity moved needs a fresh advisory lookup;
            # unchanged ones are still re-queried in batch (§5), but these are
            # the ones whose CACHED verdict is definitely invalid.
            "requery": sorted({d["package"] for d in added}
                              | {d["package"] for d in changed})}


def deps_from_depinv(doc):
    """Flatten a depinv.py document into {`eco|name`: {version, ...}}."""
    out = {}
    for eco in (doc or {}).get("ecosystems", []) or []:
        name_eco = eco.get("ecosystem")
        for p in eco.get("packages", []) or []:
            out[f"{name_eco}|{p.get('name')}"] = {
                "version": p.get("version"),
                "resolution": p.get("resolution"),
                "manifest": eco.get("manifest"),
            }
    return out


def programs_from_depinv(doc):
    out = {}
    for g in (doc or {}).get("programs", []) or []:
        out[f"{g.get('kind')}|{g.get('name')}|{g.get('source')}"] = {
            "version": g.get("version"), "ecosystem": g.get("ecosystem"),
            "pinned": g.get("pinned"),
        }
    return out


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def compute(state, new_manifest, applicable_lanes, *, full=False, now=None,
            staleness_days=DEFAULT_STALENESS_DAYS, tool_versions=None,
            plugin_root=PLUGIN_ROOT, depinv=None):
    now = now or datetime.now(timezone.utc)
    tool_versions = tool_versions or {}
    state = state or {}
    lane_state = state.get("lane_state") or {}
    runs = state.get("runs") or []
    baseline = runs[-1]["run_id"] if runs else None

    files = diff_manifests(state.get("manifest"), new_manifest)
    touched = files["added"] + files["modified"] + files["deleted"]
    invalidations = []

    no_baseline = baseline is None or not state.get("manifest")
    mode = "full" if (full or no_baseline) else "incremental"

    lanes = {}
    for lane in sorted(applicable_lanes):
        prev = lane_state.get(lane) or {}
        digest = lane_digest(lane, plugin_root)
        carried = int(prev.get("findings", 0) or 0)

        def decide(rerun, reason, matched=None):
            entry = {"rerun": rerun, "reason": reason}
            if rerun:
                entry["files"] = matched if matched is not None else []
            else:
                entry["carried"] = carried
                entry["last_run"] = prev.get("last_run")
            lanes[lane] = entry

        # 1 — unconditional
        if full:
            decide(True, "forced by --full")
            continue
        if no_baseline:
            decide(True, "no previous audit for this project — first run is always full")
            continue
        if lane not in LANE_PATTERNS and lane not in ALWAYS_ON:
            decide(True, ALWAYS_RERUN_REASON)
            continue
        # An always-on lane re-runs whatever else is true, so it is decided here:
        # letting it fall through would report an incidental reason (a changed
        # digest) for a lane that was never eligible to be skipped.
        if lane in ALWAYS_ON:
            decide(True, ALWAYS_ON[lane])
            continue

        # 2 — the lane's own definition changed
        if prev.get("digest") and prev["digest"] != digest:
            msg = f"lane definition changed ({prev['digest']}→{digest})"
            invalidations.append(f"lane_definition_digest {lane} {prev['digest']}→{digest}")
            decide(True, msg)
            continue
        if not prev.get("digest"):
            decide(True, "no recorded lane definition digest — cannot prove the rules are unchanged")
            continue

        # 3 — applicable files moved
        pats = LANE_PATTERNS[lane]
        matched = [f for f in touched if matches(f, pats)]
        if matched:
            n = len(matched)
            decide(True, f"{n} applicable file{'s' if n != 1 else ''} changed", matched[:50])
            continue

        # 4 — the previous run did not complete cleanly
        if prev.get("status") not in ("ok", None):
            decide(True, f"previous run ended {prev.get('status')!r} — re-verifying")
            continue
        if prev.get("status") is None:
            decide(True, "no recorded status for the previous run — re-verifying")
            continue

        # 5 — tool versions moved under us
        prev_tools = prev.get("tool_versions") or {}
        now_tools = tool_versions.get(lane) or {}
        if now_tools and prev_tools and now_tools != prev_tools:
            invalidations.append(f"tool_versions {lane} {prev_tools}→{now_tools}")
            decide(True, f"tool versions changed ({prev_tools} → {now_tools})")
            continue

        # 6 — staleness
        last = _parse_ts(prev.get("last_run_at"))
        if last is None:
            decide(True, "no timestamp on the previous run — re-verifying")
            continue
        age = now - last
        if age > timedelta(days=staleness_days):
            decide(True, f"last verified {age.days} days ago (> {staleness_days}d staleness TTL)")
            continue

        decide(False, f"no applicable file changed since {baseline}")

    out = {"mode": mode,
           "baseline_run": baseline,
           "staleness_days": staleness_days,
           "files": {"added": files["added"], "modified": files["modified"],
                     "deleted": files["deleted"], "unchanged": len(files["unchanged"])},
           "lanes": lanes,
           "invalidations": invalidations}
    if depinv is not None:
        out["deps"] = diff_deps(state.get("deps"), deps_from_depinv(depinv))
        out["programs"] = diff_deps(state.get("programs"), programs_from_depinv(depinv))
    return out


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    args = {}
    flags = set()
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("--full",):
            flags.add("full")
        elif a.startswith("--"):
            key = a[2:]
            if "=" in key:
                key, val = key.split("=", 1)
            else:
                i += 1
                if i >= len(argv):
                    sys.stderr.write(f"changeset: {a} needs a value\n")
                    return 2
                val = argv[i]
            args[key] = val
        i += 1

    if "manifest" not in args:
        sys.stderr.write("usage: changeset.py --manifest <file> [--state <file>] "
                         "[--lanes <file>] [--full] [--now ISO] [--staleness-days N]\n")
        return 2

    manifest_doc = _load(args["manifest"])
    new_manifest = manifest_doc.get("manifest", manifest_doc)
    state = _load(args["state"]) if args.get("state") and os.path.exists(args["state"]) else {}
    if args.get("lanes") and os.path.exists(args["lanes"]):
        inv = _load(args["lanes"])
        applicable = list((inv.get("lanes") or inv).keys())
    else:
        applicable = sorted(set(LANE_PATTERNS) | set(ALWAYS_ON))
    tool_versions = _load(args["tool-versions"]) if args.get("tool-versions") else {}
    depinv = _load(args["depinv"]) if args.get("depinv") and os.path.exists(args["depinv"]) \
        else None

    out = compute(
        state, new_manifest, applicable,
        full="full" in flags,
        now=_parse_ts(args.get("now")),
        staleness_days=int(args.get("staleness-days", DEFAULT_STALENESS_DAYS)),
        tool_versions=tool_versions,
        plugin_root=args.get("plugin-root", PLUGIN_ROOT),
        depinv=depinv)
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
