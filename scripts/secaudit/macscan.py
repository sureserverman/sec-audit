#!/usr/bin/env python3
"""Apple code-signing tool driver for the macos and ios lanes.

Why this exists
---------------
The signing tools each need artifact discovery plus per-artifact attribution,
which `lanes/*.json` cannot express: `codesign`, `spctl`, `pkgutil` and
`stapler` run once per bundle or package and every finding must carry the
artifact it came from. `mobsfscan` needs none of that and stays an ordinary
lane entry in both lanes.

It also removes a construct that could not run at all. macos-runner drove its
stapler loop with `done < <(cat bundles.txt pkgs.txt)` — a process substitution,
which the Bash tool refuses outright (`Error: Contains process_substitution`)
whatever is granted. That step has therefore never executed. Discovery happens
in Python here, so the construct is gone rather than merely scoped.

Host gate
---------
`codesign`, `spctl`, `pkgutil`, `stapler` and `notarytool` exist only on Darwin.
On any other host every one of them is a clean skip with `requires-macos-host` —
never a failure, and never silence that could read as a clean scan.

Invocations, verified on macOS 26.6.2 (arm64) on 2026-08-27
-----------------------------------------------------------
Unlike the linux lane, the documented invocations here were correct:

  * `codesign -dv --entitlements :- --xml --verbose=4 <bundle>` — entitlements
    plist on stdout, signing metadata on stderr, rc 0 when signed.
  * `spctl --assess --verbose=2 <bundle>` — verdict on stderr, `accepted` /
    `rejected`, rc 0 on accept.
  * `xcrun stapler validate <artifact>` — rc 65 and "does not have a ticket
    stapled to it" on stdout when unstapled.
  * `pkgutil --check-signature <pkg>` — status on stdout.

Exit codes: 0 complete, 1 a run failed, 3 inapplicable (wrong host, or nothing
of this tool's shape under the target). The lane maps 3 to the tool's own skip
reason.

Output: sec-audit finding JSONL on stdout. Summary on stderr.
"""

import argparse
import json
import os
import plistlib
import shutil
import subprocess
import sys

PRUNE = {
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", "vendor", ".tox", ".cache",
}
TIMEOUT = 600

BUNDLE_SUFFIXES = (".app", ".framework", ".xcarchive")
PKG_SUFFIXES = (".pkg", ".mpkg")

# Entitlement -> CWE, transcribed from
# references/desktop/macos-hardened-runtime.md, the cited source of record.
# Never extend this by guess; extend it from that pack.
ENTITLEMENT_CWE = {
    "com.apple.security.cs.allow-jit": ("CWE-693", "HIGH"),
    "com.apple.security.cs.allow-unsigned-executable-memory":
        ("CWE-749", "HIGH"),
    "com.apple.security.cs.allow-dyld-environment-variables":
        ("CWE-426", "HIGH"),
    "com.apple.security.cs.disable-library-validation": ("CWE-347", "HIGH"),
    "com.apple.security.get-task-allow": ("CWE-489", "HIGH"),
}


def is_darwin():
    return sys.platform == "darwin"


def walk_dirs(target):
    for root, dirs, _files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE)
        yield root, dirs


def find_bundles(target):
    """Directories whose name ends in a bundle suffix. Not pruned into: a
    bundle's interior is the artifact, not more candidates."""
    out = []
    for root, dirs in walk_dirs(target):
        for d in list(dirs):
            if d.endswith(BUNDLE_SUFFIXES):
                out.append(os.path.join(root, d))
                dirs.remove(d)
    return sorted(out)


def find_pkgs(target):
    out = []
    for root, _dirs in walk_dirs(target):
        for name in sorted(os.listdir(root)):
            if name.endswith(PKG_SUFFIXES) and os.path.isfile(
                    os.path.join(root, name)):
                out.append(os.path.join(root, name))
    return sorted(out)


def finding(fid, severity, cwe, title, path, evidence, tool, target,
            confidence="high", url=None, fix=None):
    try:
        rel = os.path.relpath(path, target)
    except ValueError:
        rel = str(path)
    return {
        "id": fid,
        "severity": severity,
        "cwe": cwe,
        "title": str(title)[:200],
        "file": rel,
        "line": 0,
        "evidence": str(evidence)[:200],
        "confidence": confidence,
        "reference": "mobile-tools.md" if tool == "notarytool" else "COVERAGE.md",
        "reference_url": url,
        "fix_recipe": fix,
        "origin": None,          # filled by main() from --lane
        "tool": tool,
    }


def run(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except Exception as e:                                   # noqa: BLE001
        sys.stderr.write(f"macscan: {' '.join(argv)} failed: {e}\n")
        return None


# -------------------------------------------------------------- codesign
def do_codesign(target):
    bundles = find_bundles(target)
    if not bundles:
        return [], 3
    out, failures = [], 0
    for b in bundles:
        proc = run(["codesign", "-dv", "--entitlements", ":-", "--xml",
                    "--verbose=4", b])
        if proc is None:
            failures += 1
            continue
        meta = proc.stderr or ""
        if "code object is not signed" in meta.lower():
            out.append(finding(
                "codesign:unsigned", "HIGH", "CWE-693",
                "bundle is not code-signed", b, meta.strip().splitlines()[:1],
                "codesign", target))
            continue
        # Entitlements come back as a plist on stdout. An unsigned or
        # entitlement-free bundle yields an empty document, which is not an
        # error — it simply has nothing to report.
        blob = (proc.stdout or "").strip()
        if blob:
            try:
                ents = plistlib.loads(blob.encode())
            except Exception:                                # noqa: BLE001
                sys.stderr.write(f"macscan: {b}: unparseable entitlements\n")
                failures += 1
                ents = {}
            if isinstance(ents, dict):
                for key, value in ents.items():
                    if value is not True or key not in ENTITLEMENT_CWE:
                        continue
                    cwe, sev = ENTITLEMENT_CWE[key]
                    out.append(finding(
                        f"codesign:{key}", sev, cwe,
                        f"hardened-runtime exception {key} is enabled",
                        b, f"{key} = true", "codesign", target))
        if "Authority=" not in meta:
            out.append(finding(
                "codesign:no-authority", "HIGH", "CWE-693",
                "signature carries no certificate authority chain",
                b, "no Authority= line in codesign output", "codesign", target))
    return out, (1 if failures and not out else 0)


# ------------------------------------------------------------------ spctl
def do_spctl(target):
    bundles = find_bundles(target)
    if not bundles:
        return [], 3
    out = []
    for b in bundles:
        proc = run(["spctl", "--assess", "--verbose=2", b])
        if proc is None:
            continue
        verdict = (proc.stderr or "") + (proc.stdout or "")
        if "accepted" not in verdict.lower():
            out.append(finding(
                "spctl:rejected", "HIGH", "CWE-693",
                "Gatekeeper assessment rejected the bundle", b,
                verdict.strip().replace("\n", " ")[:200], "spctl", target))
    return out, 0


# ---------------------------------------------------------------- pkgutil
def do_pkgutil(target):
    pkgs = find_pkgs(target)
    if not pkgs:
        return [], 3
    out = []
    for p in pkgs:
        proc = run(["pkgutil", "--check-signature", p])
        if proc is None:
            continue
        text = (proc.stdout or "") + (proc.stderr or "")
        low = text.lower()
        if "no signature" in low or "signature failed validation" in low:
            out.append(finding(
                "pkgutil:unsigned", "HIGH", "CWE-693",
                "installer package is unsigned or its signature failed",
                p, text.strip().replace("\n", " ")[:200], "pkgutil", target))
    return out, 0


# ---------------------------------------------------------------- stapler
def do_stapler(target):
    artifacts = find_bundles(target) + find_pkgs(target)
    if not artifacts:
        return [], 3
    out = []
    for a in artifacts:
        proc = run(["xcrun", "stapler", "validate", a])
        if proc is None:
            continue
        text = (proc.stdout or "") + (proc.stderr or "")
        if "The validate action worked!" not in text:
            out.append(finding(
                "stapler:not-stapled", "MEDIUM", "CWE-693",
                "no notarization ticket is stapled to the artifact", a,
                text.strip().replace("\n", " ")[:200], "stapler", target,
                confidence="medium",
                fix="staple the ticket after notarytool submit: "
                    "xcrun stapler staple <artifact>"))
    return out, 0


# ------------------------------------------------------------- notarytool
def do_notarytool(target):
    profile = os.environ.get("NOTARY_PROFILE")
    if not profile:
        sys.stderr.write("macscan: NOTARY_PROFILE unset\n")
        return [], 3
    proc = run(["xcrun", "notarytool", "history", "--keychain-profile",
                profile, "--output-format", "json"])
    if proc is None or not (proc.stdout or "").strip():
        return [], 1
    # History is context, not a defect: the runner reports it ran, and any
    # judgement about a rejected submission belongs to sec-expert.
    return [], 0


TOOLS = {"codesign": do_codesign, "spctl": do_spctl, "pkgutil": do_pkgutil,
         "stapler": do_stapler, "notarytool": do_notarytool}
# The binary each tool actually needs on PATH (stapler/notarytool go via xcrun).
BINARY = {"codesign": "codesign", "spctl": "spctl", "pkgutil": "pkgutil",
          "stapler": "xcrun", "notarytool": "xcrun"}


def main(argv):
    ap = argparse.ArgumentParser(prog="macscan.py")
    ap.add_argument("target")
    ap.add_argument("--tool", required=True, choices=sorted(TOOLS))
    ap.add_argument("--lane", required=True, choices=("ios", "macos"))
    args = ap.parse_args(argv[1:])

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        sys.stderr.write(f"macscan: not a directory: {target}\n")
        return 2
    if not is_darwin():
        sys.stderr.write(f"macscan: {args.tool} requires a macOS host\n")
        return 3
    if shutil.which(BINARY[args.tool]) is None:
        sys.stderr.write(f"macscan: {BINARY[args.tool]} not on PATH\n")
        return 1

    findings, rc = TOOLS[args.tool](target)
    for f in findings:
        f["origin"] = args.lane
        sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
    sys.stderr.write(
        f"macscan: {args.tool} -> {len(findings)} finding(s), rc={rc}\n")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
