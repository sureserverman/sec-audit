#!/usr/bin/env python3
"""Resolve the portfolio state home for a sec-audit target (SKILL §1.5).

As of v1.29 sec-audit persists its outputs — state, reports, run history — into
the audited project's *portfolio* home rather than into the audited tree itself:

    <portfolio_root>/<area>/<name>/security/

This script resolves that directory and nothing else. It is deliberately
side-effect free: it never creates a directory (statestore.py does that on the
first save, after the orchestrator has confirmed with the user when required),
so tests and dry runs can call it freely.

Resolution order (first match wins, reported in `source`):
  1. `--state-dir DIR`   explicit override — the escape hatch for an unmounted
                         vault or a CI runner. No portfolio lookup at all.
  2. registry            longest-prefix match against ~/.claude/projects-registry.yaml,
                         so a subdirectory of a registered project resolves to
                         that project's home. `enabled: false` entries are ignored.
  3. inferred            an unregistered target under <dev_root>/<area>/<name>/...
                         borrows that layout. `confirm_required` is set — the
                         orchestrator asks before a new portfolio dir is created.
  4. adhoc               anything else: _adhoc/<sha1(abspath)[:12]>-<basename>,
                         deterministic so repeat runs of the same target share state.

Usage: statehome.py <target_path> [--state-dir DIR]
Env overrides (tests + non-standard hosts):
  SECAUDIT_PORTFOLIO_ROOT   default /mnt/vault/Portfolio
  SECAUDIT_REGISTRY         default ~/.claude/projects-registry.yaml
  SECAUDIT_DEV_ROOT         default ~/dev

Exit codes: 0 resolved · 2 usage error · 3 state root unavailable (message names
--state-dir, because that is the user's way out).
"""
import hashlib
import json
import os
import sys

DEFAULT_PORTFOLIO_ROOT = "/mnt/vault/Portfolio"


def _env(name, default):
    return os.environ.get(name) or default


def portfolio_root():
    return os.path.abspath(_env("SECAUDIT_PORTFOLIO_ROOT", DEFAULT_PORTFOLIO_ROOT))


def registry_path():
    return _env("SECAUDIT_REGISTRY",
                os.path.join(os.path.expanduser("~"), ".claude", "projects-registry.yaml"))


def dev_root():
    return os.path.abspath(_env("SECAUDIT_DEV_ROOT",
                                os.path.join(os.path.expanduser("~"), "dev")))


def parse_registry(path):
    """Line-oriented parse of projects-registry.yaml -> [{path, name, area}].

    Deliberately NOT a YAML parser: the rest of scripts/secaudit/ is stdlib-only
    (no PyYAML dependency for a shipped plugin), and the registry's schema is a
    flat list of `- path:` records with scalar `name`/`area`/`enabled` fields.
    Entries with `enabled: false` are dropped — a disabled project is not tracked.
    A record missing `name` or `area` is skipped rather than guessed at.
    """
    out = []
    cur = None
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return out

    def flush(rec):
        if rec and rec.get("path") and rec.get("name") and rec.get("area") \
                and rec.get("enabled", True):
            out.append({"path": os.path.abspath(os.path.expanduser(rec["path"])),
                        "name": rec["name"], "area": rec["area"]})

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            # A new list item ends the previous record.
            flush(cur)
            cur = {}
            stripped = stripped[2:].strip()
            if not stripped:
                continue
        if cur is None:
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key == "enabled":
            cur["enabled"] = val.lower() not in ("false", "no", "0")
        elif key in ("path", "name", "area"):
            cur[key] = val
    flush(cur)
    return out


def _is_within(child, parent):
    """True if `child` is `parent` or lives under it — compared on path
    boundaries, so /home/u/dev/foo-bar is NOT inside /home/u/dev/foo."""
    child = os.path.abspath(child)
    parent = os.path.abspath(parent)
    if child == parent:
        return True
    return child.startswith(parent.rstrip(os.sep) + os.sep)


def match_registry(target, entries):
    """Longest-prefix match so a subdir of a registered project resolves to it."""
    best = None
    for e in entries:
        if _is_within(target, e["path"]):
            if best is None or len(e["path"]) > len(best["path"]):
                best = e
    return best


def _writable_ancestor(path):
    """Walk up to the nearest existing ancestor; True if it is writable.

    The state home usually does not exist yet on a first run — what matters is
    whether we would be *able* to create it."""
    p = os.path.abspath(path)
    while True:
        if os.path.exists(p):
            return os.path.isdir(p) and os.access(p, os.W_OK)
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


def resolve(target, state_dir=None):
    target = os.path.abspath(os.path.expanduser(target))

    if state_dir:
        home = os.path.abspath(os.path.expanduser(state_dir))
        return {"home": home,
                "project": {"name": os.path.basename(target.rstrip(os.sep)),
                            "area": "", "path": target},
                "source": "override",
                "exists": os.path.isdir(home),
                "confirm_required": False}

    root = portfolio_root()
    entry = match_registry(target, parse_registry(registry_path()))
    if entry:
        home = os.path.join(root, entry["area"], entry["name"], "security")
        return {"home": home,
                "project": {"name": entry["name"], "area": entry["area"],
                            "path": entry["path"]},
                "source": "registry",
                "exists": os.path.isdir(home),
                "confirm_required": False}

    dr = dev_root()
    if _is_within(target, dr) and target != dr:
        rel = os.path.relpath(target, dr).split(os.sep)
        if len(rel) >= 2:
            area, name = rel[0], rel[1]
            home = os.path.join(root, area, name, "security")
            return {"home": home,
                    "project": {"name": name, "area": area,
                                "path": os.path.join(dr, area, name)},
                    "source": "inferred",
                    "exists": os.path.isdir(home),
                    # Creating a portfolio home for a project the registry does
                    # not know about is the user's call, not ours.
                    "confirm_required": not os.path.isdir(home)}

    slug = hashlib.sha1(target.encode("utf-8")).hexdigest()[:12]
    name = os.path.basename(target.rstrip(os.sep)) or "root"
    home = os.path.join(root, "_adhoc", f"{slug}-{name}", "security")
    return {"home": home,
            "project": {"name": name, "area": "_adhoc", "path": target},
            "source": "adhoc",
            "exists": os.path.isdir(home),
            "confirm_required": not os.path.isdir(home)}


def main(argv):
    args, state_dir, i = [], None, 1
    while i < len(argv):
        a = argv[i]
        if a == "--state-dir":
            i += 1
            if i >= len(argv):
                sys.stderr.write("statehome: --state-dir needs a value\n")
                return 2
            state_dir = argv[i]
        elif a.startswith("--state-dir="):
            state_dir = a.split("=", 1)[1]
        else:
            args.append(a)
        i += 1

    if len(args) != 1:
        sys.stderr.write("usage: statehome.py <target_path> [--state-dir DIR]\n")
        return 2

    res = resolve(args[0], state_dir)
    if not _writable_ancestor(res["home"]):
        which = "state dir" if res["source"] == "override" else "portfolio root"
        sys.stderr.write(
            f"statehome: {which} is missing or not writable: {res['home']}\n"
            "  sec-audit persists its state and reports there and will not fall back\n"
            "  to writing inside the audited project. Mount the vault, or re-run with\n"
            "  --state-dir=<writable path>.\n")
        return 3
    sys.stdout.write(json.dumps(res, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
