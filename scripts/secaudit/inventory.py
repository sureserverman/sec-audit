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


def detect(target, files=None):
    # files=None -> walk the whole tree (default). files=<iterable of relpaths>
    # -> restrict detection to exactly those paths (--diff scoping): only lanes
    # whose signals appear among the changed files fire.
    names = set()        # basenames present
    rels = []            # relative paths
    exts = set()
    source = walk(target) if files is None else ((rel, os.path.basename(rel)) for rel in files)
    for rel, fn in source:
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
    # c-cpp fires on a C/C++ SOURCE file (not header-only — a vendored/JNI `*.h`
    # is ubiquitous and would FP). cppcheck + flawfinder then scan the tree.
    if any_ext(".c", ".cc", ".cpp", ".cxx", ".c++"):
        lanes["c-cpp"] = True
    # php fires on a *.php source or composer.json. Sub-shape "wordpress" when a
    # WP signal is present (wp-config.php, a `Theme Name:` style.css header, or a
    # functions.php using add_action), else "generic" — the phpcs WPCS security
    # sniffs are tuned for WordPress. (Packagist deps are enriched separately.)
    if ".php" in exts or any_name("composer.json"):
        # WordPress signal: a theme (`Theme Name:` style.css header or an
        # add_action functions.php), a plugin (a `Plugin Name:` docblock header
        # in any *.php — the plugin analogue of the theme header), or a
        # wp-config.php. Else "generic" (Laravel / Symfony / framework-less).
        wp = (any_name("wp-config.php")
              or any(os.path.basename(r) == "style.css" and grep(r, r"(?mi)^\s*Theme Name:") for r in rels)
              or any(os.path.basename(r) == "functions.php" and grep(r, r"add_action\s*\(") for r in rels)
              or any(r.endswith(".php") and grep(r, r"(?mi)^\s*\*?\s*Plugin Name:") for r in rels))
        lanes["php"] = ["wordpress"] if wp else ["generic"]
    if any_ext(".tf"):
        lanes["iac"] = True
    if any(r.startswith(".github/workflows/") and r.endswith((".yml", ".yaml")) for r in rels):
        lanes["gh-actions"] = True
    # virt fires on a Containerfile OR a docker-compose file. Compose detection
    # is name-glob + a `services:`/`version:` content grep so an unrelated
    # `compose.yml` (rare) doesn't trip the lane; kics (--type DockerCompose)
    # then scans the matched compose files for privileged/host-namespace/
    # capability misconfigurations.
    # Match the SAME compose name-shapes as the kics `applicable_glob` in
    # lanes/virt.json (docker-compose*/compose*/*.compose .y(a)ml), case-sensitive
    # like the runner's fnmatch — so inventory never reports virt on a file kics
    # would then clean-skip as no-compose-file (or vice versa). The `([.-].*)?`
    # boundary stops `docker-composer.yml` (not a compose file) from matching.
    def _is_compose_name(b):
        return bool(re.match(r"(docker-)?compose([.-].*)?\.ya?ml$", b)
                    or re.search(r"\.compose\.ya?ml$", b))
    compose_files = [r for r in rels if _is_compose_name(os.path.basename(r))]
    has_compose = any(grep(r, r"(?m)^\s*(services|version):") for r in compose_files)
    if any_name("Dockerfile", "Containerfile") or has_compose:
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
    args = sys.argv[1:]
    files = None
    if "--files" in args:
        i = args.index("--files")
        try:
            listfile = args[i + 1]
        except IndexError:
            sys.stderr.write("inventory.py: --files needs a path\n")
            sys.exit(2)
        with open(listfile, encoding="utf-8") as f:
            files = [ln.strip() for ln in f if ln.strip()]
        args = args[:i] + args[i + 2:]
    if not args:
        sys.stderr.write("usage: inventory.py <target_path> [--files <listfile>]\n")
        sys.exit(2)
    json.dump(detect(args[0], files), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
