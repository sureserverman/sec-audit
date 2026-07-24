#!/usr/bin/env python3
"""Deterministic dependency + program inventory for sec-audit (§2 / §4).

Until v1.31 the package list came from the sec-expert LLM agent
(`__dep_inventory__`). That cannot underpin incremental dep-diffing or a
version-safety table: two runs over an unchanged lockfile could produce
different package sets, and a "safe version" claim built on a guessed version
string is worse than no claim.

This module extracts packages from **resolved lockfiles first**, falling back to
declared manifests, and records which of the two it used:

  resolution: "lockfile"   exact installed versions — safe to evaluate ranges on
  resolution: "pinned"     an exact `==` pin in a manifest — also exact
  resolution: "declared"   a manifest RANGE, recorded VERBATIM, never resolved
  resolution: "unparsed"   present but unreadable — reported, never dropped

Only `lockfile` and `pinned` are exact enough to support a "this version is
safe" claim; `declared` and `unparsed` can only ever yield UNKNOWN downstream.

Ecosystem strings match OSV's vocabulary exactly (PyPI, npm, crates.io, Go,
RubyGems, Packagist, Maven, NuGet, CocoaPods, SwiftPM), because they feed
`querybatch` directly.

It also extracts **programs** — base images, OS packages pinned in a Dockerfile,
CI action pins and toolchain pins — which is the "and so on" half of the version
question a dependency lockfile never answers.

Usage: depinv.py <target> [--files <listfile>]
Output: {"ecosystems": [{"ecosystem", "packages": [...]}], "programs": [...],
         "notes": [...]}
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit.inventory import SKIP_DIRS  # noqa: E402

MAX_BYTES = 8 << 20  # don't slurp a pathological lockfile


def _read(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _json(path):
    raw = _read(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _pkg(name, version, *, direct=None, manifest=None, resolution="lockfile"):
    return {"name": name, "version": version, "direct": direct,
            "manifest": manifest, "resolution": resolution}


# --------------------------------------------------------------------------
# PyPI
# --------------------------------------------------------------------------
def parse_requirements(raw, manifest):
    """Only `==` pins are versions. A `>=` line is a declared RANGE, kept
    verbatim with resolution="declared" — resolving it would be a guess."""
    out = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()          # drop env markers
        line = re.sub(r"\[[^\]]*\]", "", line)        # drop extras
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s,]+)$", line)
        if m:
            # An `==` pin IS the installed version, so it is exact — but it came
            # from a manifest, not a resolved lockfile, so say `pinned` rather
            # than claim a lockfile that does not exist.
            out.append(_pkg(m.group(1), m.group(2), direct=True, manifest=manifest,
                            resolution="pinned"))
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*([<>=!~].*)$", line)
        if m:
            out.append(_pkg(m.group(1), m.group(2).strip(), direct=True,
                            manifest=manifest, resolution="declared"))
        elif re.match(r"^[A-Za-z0-9._-]+$", line):
            out.append(_pkg(line, None, direct=True, manifest=manifest,
                            resolution="declared"))
    return out


def parse_poetry_lock(raw, manifest):
    out = []
    name = version = None
    category_direct = None
    for line in raw.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = version = None
            category_direct = None
            continue
        m = re.match(r'^name\s*=\s*"(.+)"$', s)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^version\s*=\s*"(.+)"$', s)
        if m and name:
            version = m.group(1)
            out.append(_pkg(name, version, direct=category_direct, manifest=manifest))
            name = version = None
    return out


def parse_pipfile_lock(doc, manifest):
    out = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (doc.get(section) or {}).items():
            v = (meta or {}).get("version") or ""
            out.append(_pkg(name, v.lstrip("="), direct=direct, manifest=manifest))
    return out


def parse_uv_lock(raw, manifest):
    """uv.lock is TOML with [[package]] name/version pairs (same shape as
    poetry.lock for our purposes)."""
    return parse_poetry_lock(raw, manifest)


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------
def parse_package_lock(doc, manifest):
    out = []
    if isinstance(doc.get("packages"), dict):          # lockfileVersion 2/3
        for path, meta in doc["packages"].items():
            if not path or not isinstance(meta, dict):
                continue                                # "" is the root project
            name = meta.get("name") or path.split("node_modules/")[-1]
            if not meta.get("version"):
                continue
            direct = path.count("node_modules/") <= 1
            out.append(_pkg(name, meta["version"], direct=direct, manifest=manifest))
    elif isinstance(doc.get("dependencies"), dict):    # lockfileVersion 1
        def walk(deps, direct):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    out.append(_pkg(name, meta["version"], direct=direct,
                                    manifest=manifest))
                    walk(meta.get("dependencies"), False)
        walk(doc["dependencies"], True)
    return out


def parse_yarn_lock(raw, manifest):
    """Handles both classic (v1) and berry (YAML-ish) forms: an entry header
    line listing one or more specs, followed by an indented `version` field."""
    out = []
    pending = []
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            pending = []
            header = line.rstrip(":").strip()
            for spec in header.split(","):
                spec = spec.strip().strip('"')
                if not spec or spec.startswith("__"):
                    continue
                at = spec.rfind("@")
                if at > 0:
                    pending.append(spec[:at])
            continue
        m = re.match(r'^\s+"?version"?[:=]?\s*"?([^"\s]+)"?', line)
        if m and pending:
            for name in pending:
                out.append(_pkg(name, m.group(1), manifest=manifest))
            pending = []
    return out


def parse_pnpm_lock(raw, manifest):
    """pnpm-lock.yaml package keys: `/name@version:` (v6+) or `/name/version:`."""
    out = []
    for line in raw.splitlines():
        m = re.match(r"^\s{2}/?(@?[^@:/][^:]*?)[@/]([0-9][^:(]*)(\([^)]*\))?:\s*$", line)
        if m:
            name, version = m.group(1).strip("'\""), m.group(2).strip()
            if name and version:
                out.append(_pkg(name, version, manifest=manifest))
    return out


def parse_package_json(doc, manifest):
    out = []
    for field, direct in (("dependencies", True), ("devDependencies", True),
                          ("optionalDependencies", True)):
        for name, spec in (doc.get(field) or {}).items():
            out.append(_pkg(name, spec, direct=direct, manifest=manifest,
                            resolution="declared"))
    return out


# --------------------------------------------------------------------------
# other ecosystems
# --------------------------------------------------------------------------
def parse_cargo_lock(raw, manifest):
    out = []
    name = None
    for line in raw.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = None
            continue
        m = re.match(r'^name\s*=\s*"(.+)"$', s)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^version\s*=\s*"(.+)"$', s)
        if m and name:
            out.append(_pkg(name, m.group(1), manifest=manifest))
            name = None
    return out


def parse_go_sum(raw, manifest):
    """go.sum lists every module version in the graph, twice (zip + /go.mod).
    Dedupe, and strip the /go.mod suffix."""
    seen = set()
    out = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mod, ver = parts[0], parts[1]
        ver = ver.replace("/go.mod", "")
        key = (mod, ver)
        if key in seen:
            continue
        seen.add(key)
        out.append(_pkg(mod, ver, manifest=manifest))
    return out


def parse_go_mod(raw, manifest):
    out = []
    for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[^\s]+)\s+(v[^\s/]+)",
                         raw, re.M):
        out.append(_pkg(m.group(1), m.group(2), direct=True, manifest=manifest,
                        resolution="declared"))
    return out


def parse_gemfile_lock(raw, manifest):
    """Gemfile.lock indents `specs:` by 2, each resolved gem by 4, and that
    gem's own dependency constraints by 6. Only the 4-space level carries
    resolved versions — a 6-space line is a constraint like `(>= 1.0)`, not an
    installed version, and must not be mistaken for one."""
    out = []
    in_specs = False
    for line in raw.splitlines():
        if re.match(r"^\s{2}specs:", line):
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
        if in_specs:
            m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$", line)
            if m:
                out.append(_pkg(m.group(1), m.group(2), manifest=manifest))
    return out


def parse_composer_lock(doc, manifest):
    out = []
    for section, direct in (("packages", True), ("packages-dev", True)):
        for p in (doc.get(section) or []):
            if isinstance(p, dict) and p.get("name"):
                out.append(_pkg(p["name"], (p.get("version") or "").lstrip("v"),
                                direct=direct, manifest=manifest))
    return out


def parse_gradle_lockfile(raw, manifest):
    out = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([\w.\-]+:[\w.\-]+):([^=\s]+)", line)
        if m:
            out.append(_pkg(m.group(1), m.group(2), manifest=manifest))
    return out


def parse_pom(raw, manifest):
    out = []
    for m in re.finditer(
            r"<dependency>\s*(?:<!--.*?-->\s*)*<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?",
            raw, re.S):
        g, a, v = m.group(1).strip(), m.group(2).strip(), (m.group(3) or "").strip()
        res = "declared"
        if v.startswith("${"):
            v = None      # a property reference we will not pretend to resolve
        out.append(_pkg(f"{g}:{a}", v or None, direct=True, manifest=manifest,
                        resolution=res))
    return out


def parse_packages_lock_json(doc, manifest):
    out = []
    for _tfm, deps in (doc.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            v = (meta or {}).get("resolved") or (meta or {}).get("requested")
            if v:
                out.append(_pkg(name, v, manifest=manifest))
    return out


def parse_podfile_lock(raw, manifest):
    out = []
    in_pods = False
    for line in raw.splitlines():
        if line.startswith("PODS:"):
            in_pods = True
            continue
        if line and not line[0].isspace():
            in_pods = False
        if in_pods:
            m = re.match(r"^\s{2}- ([\w.\-/+]+) \(([^)]+)\)", line)
            if m:
                out.append(_pkg(m.group(1), m.group(2), manifest=manifest))
    return out


def parse_package_resolved(doc, manifest):
    out = []
    pins = doc.get("pins")
    if pins is None:
        pins = (doc.get("object") or {}).get("pins") or []
    for p in pins or []:
        name = p.get("identity") or p.get("package")
        state = p.get("state") or {}
        v = state.get("version") or state.get("revision")
        if name and v:
            out.append(_pkg(name, v, manifest=manifest))
    return out


# Priority order per ecosystem: the FIRST match that parses wins, so a resolved
# lockfile always beats the declared manifest beside it.
ECOSYSTEMS = [
    ("PyPI", [
        ("poetry.lock",   lambda p: parse_poetry_lock(_read(p) or "", "poetry.lock")),
        ("uv.lock",       lambda p: parse_uv_lock(_read(p) or "", "uv.lock")),
        ("Pipfile.lock",  lambda p: parse_pipfile_lock(_json(p) or {}, "Pipfile.lock")),
        ("requirements.txt", lambda p: parse_requirements(_read(p) or "", "requirements.txt")),
    ]),
    ("npm", [
        ("package-lock.json", lambda p: parse_package_lock(_json(p) or {}, "package-lock.json")),
        ("pnpm-lock.yaml",    lambda p: parse_pnpm_lock(_read(p) or "", "pnpm-lock.yaml")),
        ("yarn.lock",         lambda p: parse_yarn_lock(_read(p) or "", "yarn.lock")),
        ("package.json",      lambda p: parse_package_json(_json(p) or {}, "package.json")),
    ]),
    ("crates.io", [
        ("Cargo.lock", lambda p: parse_cargo_lock(_read(p) or "", "Cargo.lock")),
    ]),
    ("Go", [
        ("go.sum", lambda p: parse_go_sum(_read(p) or "", "go.sum")),
        ("go.mod", lambda p: parse_go_mod(_read(p) or "", "go.mod")),
    ]),
    ("RubyGems", [
        ("Gemfile.lock", lambda p: parse_gemfile_lock(_read(p) or "", "Gemfile.lock")),
    ]),
    ("Packagist", [
        ("composer.lock", lambda p: parse_composer_lock(_json(p) or {}, "composer.lock")),
    ]),
    ("Maven", [
        ("gradle.lockfile", lambda p: parse_gradle_lockfile(_read(p) or "", "gradle.lockfile")),
        ("pom.xml",         lambda p: parse_pom(_read(p) or "", "pom.xml")),
    ]),
    ("NuGet", [
        ("packages.lock.json", lambda p: parse_packages_lock_json(_json(p) or {}, "packages.lock.json")),
    ]),
    ("CocoaPods", [
        ("Podfile.lock", lambda p: parse_podfile_lock(_read(p) or "", "Podfile.lock")),
    ]),
    ("SwiftPM", [
        ("Package.resolved", lambda p: parse_package_resolved(_json(p) or {}, "Package.resolved")),
    ]),
]


def _find(target, basename, files=None):
    """First match for a basename, shallowest first (a root lockfile beats a
    vendored copy). Returns an absolute path or None."""
    hits = []
    if files is not None:
        hits = [os.path.join(target, r) for r in files
                if os.path.basename(r) == basename]
    else:
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if basename in names:
                hits.append(os.path.join(root, basename))
    hits.sort(key=lambda p: (p.count(os.sep), p))
    return hits[0] if hits else None


def collect(target, files=None):
    ecosystems, notes = [], []
    for eco, candidates in ECOSYSTEMS:
        for basename, parser in candidates:
            path = _find(target, basename, files)
            if not path or not os.path.isfile(path):
                continue
            try:
                pkgs = parser(path)
            except Exception as e:                     # never abort the audit
                notes.append(f"{eco}: {basename} could not be parsed ({e})")
                pkgs = []
            if pkgs:
                seen, uniq = set(), []
                for p in pkgs:
                    key = (p["name"], p["version"])
                    if key in seen:
                        continue
                    seen.add(key)
                    uniq.append(p)
                ecosystems.append({"ecosystem": eco, "manifest": basename,
                                   "packages": uniq})
                break
            notes.append(f"{eco}: {basename} present but yielded no packages "
                         "(unparsed — reported rather than silently dropped)")
            ecosystems.append({"ecosystem": eco, "manifest": basename,
                               "packages": [], "resolution": "unparsed"})
            break
    return {"ecosystems": ecosystems, "notes": notes}


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    files = None
    if "--files" in argv:
        with open(argv[argv.index("--files") + 1], encoding="utf-8") as f:
            files = [ln.strip() for ln in f if ln.strip()]
    if not args:
        sys.stderr.write("usage: depinv.py <target> [--files <listfile>]\n")
        return 2
    target = args[0]
    out = collect(target, files)
    try:
        from secaudit.programs import collect_programs
        out["programs"] = collect_programs(target, files)
    except ImportError:
        out["programs"] = []
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    total = sum(len(e["packages"]) for e in out["ecosystems"])
    sys.stderr.write(f"depinv: {len(out['ecosystems'])} ecosystem(s), {total} package(s), "
                     f"{len(out.get('programs', []))} program(s)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
