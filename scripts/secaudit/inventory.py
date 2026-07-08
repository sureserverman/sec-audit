#!/usr/bin/env python3
"""Deterministic §2 inventory pre-pass for sec-audit.

Walks a target tree and emits the unambiguous, file-glob/content-grep portion
of the inventory as JSON: detected dependency `ecosystems` and `lanes`. The
judgemental detections (macOS-vs-iOS Info.plist disambiguation, uncovered-tech
fingerprinting) stay in SKILL §2 as LLM reasoning — this script only handles
the deterministic signals so the orchestrator doesn't burn tokens re-deriving
file existence.

Usage: inventory.py <target_path>   ->  {"ecosystems":[...], "lanes":{...}}
"""
import json
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "vendor",
             "target", "dist", "build", ".pipeline"}


def walk(target):
    """Yield (relpath, filename) for every file under target, skipping vendored dirs."""
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            yield os.path.relpath(os.path.join(root, fn), target), fn


def detect(target):
    names = set()        # basenames present
    rels = []            # relative paths
    exts = set()
    for rel, fn in walk(target):
        names.add(fn)
        rels.append(rel)
        _, e = os.path.splitext(fn)
        exts.add(e.lower())

    def any_name(*ns):
        return any(n in names for n in ns)

    def any_ext(*es):
        return any(e in exts for e in es)

    def grep(rel, pattern):
        try:
            with open(os.path.join(target, rel), encoding="utf-8", errors="replace") as f:
                return re.search(pattern, f.read()) is not None
        except OSError:
            return False

    # --- ecosystems (dependency manifests) ---
    ecosystems = []
    eco_map = [
        ("PyPI", ("requirements.txt", "pyproject.toml", "setup.py", "poetry.lock", "Pipfile.lock")),
        ("npm", ("package.json", "package-lock.json")),
        ("Go", ("go.mod", "go.sum")),
        ("RubyGems", ("Gemfile", "Gemfile.lock")),
        ("crates.io", ("Cargo.toml", "Cargo.lock")),
        ("Packagist", ("composer.json", "composer.lock")),
    ]
    for eco, manifests in eco_map:
        m = next((x for x in manifests if x in names), None)
        if m:
            ecosystems.append({"ecosystem": eco, "manifest": m})
    if "pom.xml" in names or any(r.endswith("build.gradle") or r.endswith("build.gradle.kts") for r in rels):
        ecosystems.append({"ecosystem": "Maven", "manifest": "pom.xml" if "pom.xml" in names else "build.gradle"})

    # --- lanes (deterministic signals only) ---
    lanes = {}
    py = any_name("requirements.txt", "pyproject.toml", "setup.py", "poetry.lock", "Pipfile.lock") or ".py" in exts
    npm = any_name("package.json", "package-lock.json")
    if py:
        lanes["python"] = True
    if any_name("go.mod"):
        lanes["go"] = True
    if ".sh" in exts:
        lanes["shell"] = True
    if any_name("Cargo.toml"):
        lanes["rust"] = True
    if any_ext(".tf"):
        lanes["iac"] = True
    if any(r.startswith(".github/workflows/") and r.endswith((".yml", ".yaml")) for r in rels):
        lanes["gh-actions"] = True
    if any_name("Dockerfile", "Containerfile"):
        lanes["virt"] = True
    if any(r.endswith((".tar", ".sbom.json")) or r.endswith("sbom.json") for r in rels):
        lanes["image"] = True
    # webext: a manifest.json that declares manifest_version
    for rel, fn in [(r, os.path.basename(r)) for r in rels]:
        if fn == "manifest.json" and grep(rel, r'"manifest_version"'):
            lanes["webext"] = True
            break
    # k8s: a yaml with both apiVersion: and kind:
    for rel in rels:
        if rel.endswith((".yml", ".yaml")) and grep(rel, r'(?m)^apiVersion:') and grep(rel, r'(?m)^kind:'):
            lanes["k8s"] = True
            break
    # ai-tools config shapes
    if any_name("plugin.json", ".mcp.json", "opencode.json") or \
       any(r.endswith(".claude/settings.json") for r in rels):
        lanes["ai-tools"] = True
    # supply-chain rides on the PyPI/npm manifests
    if py or npm:
        lanes["supply-chain"] = ["pypi"] * py + ["npm"] * npm
    # secrets: applies to any non-empty tree (gitleaks scans the working tree);
    # append "git-history" when a .git repo is present (trufflehog scans history).
    # .git is in SKIP_DIRS so walk() never yields its contents — probe directly.
    if rels:
        modes = ["tree"]
        if os.path.exists(os.path.join(target, ".git")):
            modes.append("git-history")
        lanes["secrets"] = modes

    return {"ecosystems": ecosystems, "lanes": lanes}


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: inventory.py <target_path>\n")
        sys.exit(2)
    json.dump(detect(sys.argv[1]), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
