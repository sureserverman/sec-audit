#!/usr/bin/env python3
"""Program / runtime version extraction — the half a lockfile never covers.

A dependency lockfile answers "which libraries", never "which nginx", "which
base image", "which Go toolchain". Those carry CVEs too, and on a container
image they usually carry the *most* of them. This module extracts them:

  base-image   FROM nginx:1.25.2            -> Debian/Alpine-adjacent CVE surface
  os-package   apt-get install curl=7.88.1  -> Debian / Ubuntu / Alpine ecosystems
  ci-action    uses: actions/checkout@v4    -> GitHub Actions ecosystem
  toolchain    .nvmrc / .tool-versions / rust-toolchain.toml / go directive

Two honesty rules drive the output:

1. A **floating tag** (`FROM node:20`, `uses: actions/checkout@v4`) is not a
   version. It is recorded with `pinned: false` and a null version — reporting
   it as "version 20" would invite a safety claim about a moving target. The
   floating tag is itself a finding worth surfacing (CWE-1357 / unpinned
   dependency), which is the caller's business, not this module's.
2. An entry with no OSV ecosystem mapping (a bare toolchain pin) is emitted with
   `ecosystem: null` so downstream renders it UNKNOWN rather than implying the
   feeds cleared it.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit.inventory import SKIP_DIRS  # noqa: E402

# A tag that is a real version pin vs a moving one. `1.25.2` / `3.19.1-alpine`
# pin; `20`, `latest`, `stable`, `lts` move under you.
_PINNED_TAG = re.compile(r"^\d+\.\d+(\.\d+)?([.\-+][\w.\-]+)?$")
# Debian-family base images map to the Debian OSV ecosystem; alpine to Alpine.
_DISTRO_ECOSYSTEM = {
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
}


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _entry(kind, name, version, *, source, ecosystem=None, pinned=True, note=None):
    e = {"kind": kind, "name": name, "version": version, "ecosystem": ecosystem,
         "pinned": pinned, "source": source}
    if note:
        e["note"] = note
    return e


def parse_dockerfile(raw, source):
    out = []
    for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", raw, re.M | re.I):
        ref = m.group(1)
        if ref.lower() in ("scratch",) or ref.startswith("$"):
            continue
        # strip a digest, then split the tag
        digest = None
        if "@" in ref:
            ref, digest = ref.split("@", 1)
        name, _, tag = ref.rpartition(":")
        explicit_tag = bool(name)
        if not explicit_tag:               # no tag at all -> implicit :latest
            name, tag = ref, "latest"
        base = name.split("/")[-1].lower()
        eco = _DISTRO_ECOSYSTEM.get(base)
        if digest:
            # The digest IS the identity here. Report the tag only if one was
            # actually written — synthesising "latest" for `alpine@sha256:…`
            # would be inventing a version the Dockerfile never states.
            out.append(_entry("base-image", name, tag if explicit_tag else None,
                              source=source, ecosystem=eco, pinned=True,
                              note=f"digest-pinned ({digest[:19]}…)"))
        elif _PINNED_TAG.match(tag or ""):
            out.append(_entry("base-image", name, tag, source=source, ecosystem=eco))
        else:
            out.append(_entry("base-image", name, None, source=source, ecosystem=eco,
                              pinned=False,
                              note=f"floating tag {tag!r} — not a version; "
                                   "the image contents can change without notice"))
    # apt / apk pins inside RUN layers
    for m in re.finditer(r"(?:apt-get|apt)\s+install[^\n]*?\s([a-z0-9][\w.+-]*)=([\w.:+~-]+)",
                         raw, re.I):
        out.append(_entry("os-package", m.group(1), m.group(2), source=source,
                          ecosystem="Debian"))
    for m in re.finditer(r"apk\s+add[^\n]*?\s([a-z0-9][\w.+-]*)=([\w.:+~-]+)", raw, re.I):
        out.append(_entry("os-package", m.group(1), m.group(2), source=source,
                          ecosystem="Alpine"))
    return out


def parse_workflow(raw, source):
    out = []
    for m in re.finditer(r"^\s*-?\s*uses:\s*['\"]?([\w.\-]+/[\w.\-/]+)@([^\s'\"]+)",
                         raw, re.M):
        action, ref = m.group(1), m.group(2)
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            out.append(_entry("ci-action", action, ref[:12], source=source,
                              ecosystem="GitHub Actions", note="SHA-pinned"))
        elif _PINNED_TAG.match(ref.lstrip("v")):
            out.append(_entry("ci-action", action, ref.lstrip("v"), source=source,
                              ecosystem="GitHub Actions"))
        else:
            out.append(_entry("ci-action", action, None, source=source,
                              ecosystem="GitHub Actions", pinned=False,
                              note=f"moving ref {ref!r} — a tag can be repointed at "
                                   "any commit (CWE-829)"))
    return out


def parse_toolchain(path, rel):
    base = os.path.basename(path)
    raw = _read(path)
    if raw is None:
        return []
    out = []
    if base == ".nvmrc":
        v = raw.strip().lstrip("v")
        if v:
            out.append(_entry("toolchain", "node", v if _PINNED_TAG.match(v) else None,
                              source=rel, pinned=bool(_PINNED_TAG.match(v)),
                              note=None if _PINNED_TAG.match(v) else f"loose pin {v!r}"))
    elif base == ".tool-versions":
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.strip().startswith("#"):
                out.append(_entry("toolchain", parts[0], parts[1], source=rel))
    elif base in ("rust-toolchain", "rust-toolchain.toml"):
        m = re.search(r'channel\s*=\s*"([^"]+)"', raw) or re.match(r"\s*(\S+)\s*$", raw)
        if m:
            v = m.group(1)
            out.append(_entry("toolchain", "rust", v if _PINNED_TAG.match(v) else None,
                              source=rel, pinned=bool(_PINNED_TAG.match(v)),
                              note=None if _PINNED_TAG.match(v) else f"channel {v!r}"))
    elif base == "go.mod":
        m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", raw, re.M)
        if m:
            out.append(_entry("toolchain", "go", m.group(1), source=rel))
    elif base == ".python-version":
        v = raw.strip()
        if v:
            out.append(_entry("toolchain", "python", v if _PINNED_TAG.match(v) else None,
                              source=rel, pinned=bool(_PINNED_TAG.match(v))))
    return out


_DOCKERFILE = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$", re.I)
_TOOLCHAIN_FILES = {".nvmrc", ".tool-versions", "rust-toolchain", "rust-toolchain.toml",
                    "go.mod", ".python-version"}


def collect_programs(target, files=None):
    out = []
    if files is not None:
        rels = list(files)
    else:
        rels = []
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in names:
                rels.append(os.path.relpath(os.path.join(root, fn), target))
    for rel in sorted(rels):
        path = os.path.join(target, rel)
        if not os.path.isfile(path):
            continue
        base = os.path.basename(rel)
        if _DOCKERFILE.match(base):
            raw = _read(path)
            if raw:
                out.extend(parse_dockerfile(raw, rel))
        elif rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            raw = _read(path)
            if raw:
                out.extend(parse_workflow(raw, rel))
        elif base in _TOOLCHAIN_FILES:
            out.extend(parse_toolchain(path, rel))
    # dedupe (kind, name, version, source)
    seen, uniq = set(), []
    for e in out:
        key = (e["kind"], e["name"], e["version"], e["source"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    return uniq


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: programs.py <target> [--files <listfile>]\n")
        return 2
    files = None
    if "--files" in argv:
        with open(argv[argv.index("--files") + 1], encoding="utf-8") as f:
            files = [ln.strip() for ln in f if ln.strip()]
    progs = collect_programs(argv[1], files)
    sys.stdout.write(json.dumps({"programs": progs}, indent=2, sort_keys=True) + "\n")
    sys.stderr.write(f"programs: {len(progs)} entr(ies)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
