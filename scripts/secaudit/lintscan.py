#!/usr/bin/env python3
"""Android Lint driver for the android lane (BL-00D, 2026-09-03).

Two facts about the standalone `lint` binary (Android SDK cmdline-tools,
lint 8.9.0) that the lane's plain `lint --xml - <target>` invocation got wrong:

  1. `--xml -` is not stdout. lint treats `-` as a file name, writes the report
     to a file literally called `-` in the working directory and prints
     nothing — the same shape as the mobsfscan `--output -` bug. The lane
     parsed empty stdout and reported `parse-failed` over every target.
  2. lint REFUSES a Gradle project: the only issue it emits is
     `LintError` / "`app` is a Gradle project. To correctly analyze Gradle
     projects, you should run `gradlew lint` instead." Real Android projects
     are Gradle projects, so the standalone tool can never analyse them; the
     old lane would have mapped that refusal into a HIGH finding blaming the
     caller's code.

So the analysis has two honest paths, in order:
  * a lint report the project ALREADY produced (`**/build/reports/
    lint-results*.xml`, what `gradlew lint` writes) — parsed as-is. This is
    the only way a Gradle project is ever analysed here; the runner contract
    forbids running the build.
  * otherwise `lint --xml <scratch> <target>` — which works for non-Gradle
    trees (manifest + source checks, with `MissingClass` noise because there is
    no bytecode). If that run reports only the Gradle refusal, the target is
    a Gradle project without a report: exit 3 → clean skip
    `gradle-project-no-lint-report`, never a finding.

Output: the lint XML document on stdout (existing reports are merged into one
document, `<location file>` made target-relative), which the lane maps with
its existing `input_format: xml` rules.

Exit codes: 0 report on stdout; 1 lint not on PATH (only reached when no
report exists); 2 not a directory; 3 Gradle project with no lint report;
5 lint ran but wrote no readable report.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SKIP_DIRS = {".git", "node_modules", ".pipeline", "vendor", ".gradle"}
TIMEOUT = 600


def find_reports(target):
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if os.path.basename(root) == "reports" and os.path.basename(os.path.dirname(root)) == "build":
            for f in files:
                if f.startswith("lint-results") and f.endswith(".xml"):
                    out.append(os.path.join(root, f))
    return sorted(out)


def relativize(root, target, base=None):
    """Make every `<location file>` target-relative. Absolute paths (what
    `gradlew lint` writes) are relativised to the target; relative paths (what
    standalone lint writes, relative to the module it was pointed at) are first
    resolved against `base`, the module directory."""
    for issue in root.iter("issue"):
        for loc in issue.iter("location"):
            f = loc.get("file")
            if not f:
                continue
            if not os.path.isabs(f) and base:
                f = os.path.join(base, f)
            if os.path.isabs(f):
                try:
                    rel = os.path.relpath(f, target)
                except ValueError:
                    continue
                if not rel.startswith(".."):
                    loc.set("file", rel)


def merge(paths, target):
    merged = None
    for p in paths:
        try:
            root = ET.parse(p).getroot()
        except (OSError, ET.ParseError) as e:
            sys.stderr.write(f"lintscan: unreadable report {p}: {e}\n")
            continue
        # <module>/build/reports/lint-results*.xml -> the module directory is
        # the base for any relative path the report carries.
        module = os.path.dirname(os.path.dirname(os.path.dirname(p)))
        relativize(root, target, base=module)
        if merged is None:
            merged = root
        else:
            for issue in root.findall("issue"):
                merged.append(issue)
    return merged


def is_gradle_refusal(root):
    issues = root.findall("issue")
    return bool(issues) and all(
        i.get("id") == "LintError" and "Gradle project" in (i.get("message") or "")
        for i in issues)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: lintscan.py <target>\n"); return 2
    target = os.path.abspath(argv[1])
    if not os.path.isdir(target):
        sys.stderr.write(f"lintscan: not a directory: {target}\n"); return 2

    reports = find_reports(target)
    if reports:
        root = merge(reports, target)
        if root is None:
            return 5
        sys.stderr.write(f"lintscan: using {len(reports)} existing lint report(s) "
                         f"({len(root.findall('issue'))} issues)\n")
        sys.stdout.write(ET.tostring(root, encoding="unicode"))
        return 0

    if shutil.which("lint") is None:
        sys.stderr.write("lintscan: lint not on PATH and no lint report under target\n")
        return 1
    tmp = tempfile.mkdtemp()
    report = os.path.join(tmp, "lint-results.xml")
    try:
        subprocess.run(["lint", "--xml", report, target], capture_output=True, text=True,
                       timeout=TIMEOUT, stdin=subprocess.DEVNULL, cwd=tmp)
    except Exception as e:                                       # noqa: BLE001
        sys.stderr.write(f"lintscan: lint failed: {e}\n"); return 5
    if not os.path.exists(report):
        sys.stderr.write("lintscan: lint wrote no report\n"); return 5
    try:
        root = ET.parse(report).getroot()
    except ET.ParseError as e:
        sys.stderr.write(f"lintscan: lint report unreadable: {e}\n"); return 5
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if is_gradle_refusal(root):
        sys.stderr.write("lintscan: Gradle project with no lint report — run "
                         "`gradlew lint` and re-audit; standalone lint cannot analyse it\n")
        return 3
    relativize(root, target, base=target)
    sys.stderr.write(f"lintscan: standalone lint -> {len(root.findall('issue'))} issue(s)\n")
    sys.stdout.write(ET.tostring(root, encoding="unicode"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
