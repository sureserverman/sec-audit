#!/usr/bin/env python3
"""Windows PE driver for the sec-audit windows lane (BL-002, 2026-09-02).

Why a wrapper and not three plain lane entries: every Windows tool here is
per-artifact — it takes ONE PE and its findings must be attributed to THAT
PE — and the lane schema expresses one invocation per tool over the whole
target. The wrapper discovers the PEs, runs the tool once per artifact, and
emits already-shaped findings (JSONL, one per line) that the lane maps 1:1.
Doing the discovery here also removes the `find … | while read` loop the
agent used to carry, which is exactly the construct the Bash permission
matcher refuses under a scoped grant (docs/plans-notes/bash-scope-inventory.md).

Shapes below are what the tools ACTUALLY emit (captured 2026-09-02 on
binskim 4.4.9.11 / osslsigncode 2.14), which differs from the reference in
three places the reference now documents:
  * binskim SARIF results carry `message.id` + `message.arguments`, not
    `message.text`; the text template lives in the rule's `messageStrings`.
  * binskim's `--level`/`--kind` are quoted semicolon lists ("Error;Warning"),
    there is no `--force`, and it refuses to overwrite an existing output file.
  * osslsigncode prints `No signature found` for an unsigned PE (not "lacks
    `Signature verification: ok`"), `Timestamp is not available` (not
    `Timestamp: none`) and `Message digest algorithm: SHA1` in upper case.

Exit codes (the lane's `rc_reasons` map them to that tool's clean-skip reason):
  0  ran; findings (if any) on stdout
  1  the tool binary is not on PATH                       -> tool-missing
  2  target is not a directory                            -> run-incomplete
  3  no PE artifact under the target                      -> no-pe
  4  sigcheck on a non-Windows host                       -> requires-windows-host
  5  the tool ran but produced no readable output for any PE -> run-incomplete
"""
import argparse
import csv
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

TIMEOUT = 300
PE_SUFFIXES = (".exe", ".dll", ".msi", ".msix", ".sys")
SKIP_DIRS = {".git", "node_modules", ".pipeline", "vendor", ".venv", "venv"}
REFERENCE = "windows-tools.md"

# BinSkim BA-series rule -> CWE, transcribed from references/windows-tools.md
# ("binskim -> sec-audit finding"). Extend from that table, never by guess.
BINSKIM_CWE = {
    "BA2001": "CWE-693", "BA2002": "CWE-1104", "BA2005": "CWE-1104",
    "BA2006": "CWE-693", "BA2007": "CWE-693", "BA2008": "CWE-693",
    "BA2009": "CWE-693", "BA2010": "CWE-119", "BA2011": "CWE-121",
    "BA2012": "CWE-121", "BA2013": "CWE-121", "BA2014": "CWE-121",
    "BA2015": "CWE-693", "BA2016": "CWE-119", "BA2018": "CWE-693",
    "BA2021": "CWE-266", "BA2024": "CWE-200", "BA2025": "CWE-121",
}
BINSKIM_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


def is_windows_host():
    if sys.platform.startswith("win") or os.environ.get("OS") == "Windows_NT":
        return True
    return bool(re.match(r"(MINGW|MSYS|CYGWIN)", platform.system() or ""))


def find_pes(target):
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.lower().endswith(PE_SUFFIXES):
                out.append(os.path.join(root, name))
    return sorted(out)


def finding(fid, severity, cwe, title, path, evidence, tool, target,
            confidence="high", url=None, fix=None):
    try:
        rel = os.path.relpath(path, target)
    except ValueError:
        rel = str(path)
    return {
        "id": fid, "severity": severity, "cwe": cwe,
        "title": str(title)[:200], "file": rel, "line": 0,
        "evidence": str(evidence)[:200], "confidence": confidence,
        "reference": REFERENCE, "reference_url": url, "fix_recipe": fix,
        "origin": "windows", "tool": tool,
    }


def run(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except Exception as e:                                   # noqa: BLE001
        sys.stderr.write(f"winscan: {' '.join(argv)} failed: {e}\n")
        return None


# ---------------------------------------------------------------- binskim
def _sarif_message(result, rules):
    """SARIF 2.1 message resolution: `message.text` when present, else the
    rule's `messageStrings[message.id].text` with `{n}` arguments filled."""
    msg = result.get("message") or {}
    if msg.get("text"):
        return msg["text"]
    rule = None
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        rule = rules[idx]
    if rule is None:
        rule = next((r for r in rules if r.get("id") == result.get("ruleId")), None)
    if rule and msg.get("id"):
        tmpl = ((rule.get("messageStrings") or {}).get(msg["id"]) or {}).get("text", "")
        for i, arg in enumerate(msg.get("arguments") or []):
            tmpl = tmpl.replace("{%d}" % i, str(arg))
        if tmpl:
            return tmpl.replace("\r\n", " ").replace("\n", " ")
    return result.get("ruleId") or ""


def do_binskim(target, pes):
    out, analysed = [], 0
    tmp = tempfile.mkdtemp()
    for i, pe in enumerate(pes):
        sarif = os.path.join(tmp, f"binskim-{i}.sarif")
        # Default result kind is Fail only; Pass/NotApplicable are not findings.
        proc = run(["binskim", "analyze", pe, "-o", sarif,
                    "--sarif-output-version", "Current"])
        if proc is None or not os.path.exists(sarif):
            sys.stderr.write(f"winscan: binskim produced no SARIF for {pe}: "
                             f"{(proc.stderr if proc else '')[:200]}\n")
            continue
        try:
            with open(sarif, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"winscan: binskim SARIF unreadable for {pe}: {e}\n")
            continue
        analysed += 1
        for runobj in doc.get("runs") or []:
            rules = ((runobj.get("tool") or {}).get("driver") or {}).get("rules") or []
            by_id = {r.get("id"): r for r in rules}
            for res in runobj.get("results") or []:
                if res.get("kind", "fail") != "fail":
                    continue
                rid = res.get("ruleId") or "unknown"
                text = _sarif_message(res, rules)
                rule = by_id.get(rid) or {}
                out.append(finding(
                    f"binskim:{rid}", BINSKIM_SEVERITY.get(res.get("level"), "MEDIUM"),
                    BINSKIM_CWE.get(rid), text, pe, text, "binskim", target,
                    url=rule.get("helpUri"),
                    fix=(" ".join(((rule.get("fullDescription") or {}).get("text") or "").split())
                         or None)))
    shutil.rmtree(tmp, ignore_errors=True)
    return out, (0 if analysed else 5)


# ------------------------------------------------------------ osslsigncode
def do_osslsigncode(target, pes):
    out, analysed = [], 0
    for pe in pes:
        proc = run(["osslsigncode", "verify", "-in", pe])
        if proc is None:
            continue
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            sys.stderr.write(f"winscan: osslsigncode printed nothing for {pe}\n")
            continue
        analysed += 1
        # Non-zero exit is the normal outcome for anything but a trusted,
        # timestamped signature; the signals are in the text, not the rc.
        if any("No signature found" in l for l in lines):
            out.append(finding(
                "osslsigncode:unsigned", "HIGH", "CWE-693",
                "PE binary carries no Authenticode signature", pe,
                next(l for l in lines if "No signature found" in l),
                "osslsigncode", target,
                fix="Sign the binary (signtool sign /fd sha256 /tr <TSA URL> /td sha256, "
                    "or osslsigncode sign -h sha256 -ts <TSA URL>)"))
            continue
        if any(l.startswith("Signature verification: failed") for l in lines):
            err = next((l for l in lines if l.startswith("Error:")), None)
            out.append(finding(
                "osslsigncode:signature-invalid", "HIGH", "CWE-347",
                "Authenticode signature does not verify against the system trust store",
                pe, err or "Signature verification: failed", "osslsigncode", target,
                fix="Re-sign with a certificate that chains to a trusted code-signing CA"))
        if any("Timestamp is not available" in l for l in lines):
            out.append(finding(
                "osslsigncode:no-timestamp", "MEDIUM", "CWE-324",
                "Signature carries no trusted timestamp — it expires with the certificate",
                pe, "Timestamp is not available", "osslsigncode", target,
                fix="Re-sign with a timestamp (signtool /tr <TSA URL> /td sha256, "
                    "or osslsigncode sign -ts <TSA URL>)"))
        digest = next((l for l in lines
                       if re.match(r"Message digest algorithm\s*:\s*SHA1\b", l, re.I)), None)
        if digest:
            out.append(finding(
                "osslsigncode:sha1-digest", "MEDIUM", "CWE-327",
                "Signature uses a SHA-1 message digest", pe, digest,
                "osslsigncode", target,
                fix="Re-sign with /fd sha256 (signtool) or -h sha256 (osslsigncode)"))
    return out, (0 if analysed else 5)


# ---------------------------------------------------------------- sigcheck
def do_sigcheck(target, pes):
    """Windows only; never executed on the hosts this plugin is developed on,
    so the parse is defensive and stays close to the documented CSV columns
    (Path, Verified, Date, Publisher, ...). Unverified as of 2026-09-02."""
    out, analysed = [], 0
    for pe in pes:
        proc = run(["sigcheck", "-a", "-q", "-h", "-c", "-nobanner", pe])
        if proc is None or not (proc.stdout or "").strip():
            continue
        rows = list(csv.DictReader(io.StringIO(proc.stdout)))
        if not rows:
            continue
        analysed += 1
        row = rows[0]
        verified = (row.get("Verified") or "").strip()
        publisher = (row.get("Publisher") or "").strip()
        raw = ",".join(f"{k}={v}" for k, v in row.items() if k in ("Path", "Verified", "Publisher", "Date"))
        if verified == "Unsigned":
            out.append(finding("sigcheck:unsigned", "HIGH", "CWE-693",
                               "PE binary is unsigned (sigcheck)", pe, raw, "sigcheck", target))
        elif verified.startswith("Signed (expired"):
            out.append(finding("sigcheck:expired", "HIGH", "CWE-324",
                               "Signing certificate has expired", pe, raw, "sigcheck", target))
        elif verified.startswith("Signed") and not publisher:
            out.append(finding("sigcheck:no-publisher", "MEDIUM", "CWE-295",
                               "Signed binary with no publisher", pe, raw, "sigcheck", target))
    return out, (0 if analysed else 5)


TOOLS = {"binskim": do_binskim, "osslsigncode": do_osslsigncode, "sigcheck": do_sigcheck}


def main(argv):
    ap = argparse.ArgumentParser(prog="winscan.py")
    ap.add_argument("target")
    ap.add_argument("--tool", required=True, choices=sorted(TOOLS))
    args = ap.parse_args(argv[1:])

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        sys.stderr.write(f"winscan: not a directory: {target}\n")
        return 2
    if args.tool == "sigcheck" and not is_windows_host():
        # Host gate first: the documented precedence is requires-windows-host
        # over no-pe, and the binary is Windows-only anyway.
        sys.stderr.write("winscan: sigcheck requires a Windows host\n")
        return 4
    if shutil.which(args.tool) is None:
        sys.stderr.write(f"winscan: {args.tool} not on PATH\n")
        return 1
    pes = find_pes(target)
    if not pes:
        sys.stderr.write(f"winscan: no PE artifact under {target}\n")
        return 3

    findings, rc = TOOLS[args.tool](target, pes)
    for f in findings:
        sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
    sys.stderr.write(f"winscan: {args.tool} -> {len(findings)} finding(s) over "
                     f"{len(pes)} PE(s), rc={rc}\n")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
