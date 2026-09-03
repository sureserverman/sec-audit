#!/usr/bin/env python3
"""OWASP ZAP baseline driver for the dast lane (2026-09-03).

Until this existed the lane's invocation was `zap-baseline.py -J -` — no
target URL at all, and `-J -` names a report file literally called `-`
(zap-baseline writes `-J` into its working directory, `/zap/wrk` in docker)
while stdout carries the human progress log. The lane could not have scanned
anything on any host.

What this does
  * takes the target URL (`--url`), rejects anything that is not http(s);
  * runs `zap-baseline.py -t <url> -J report.json -I` either from a local
    install (`zap-baseline.py` on PATH) or through the official image
    (`ghcr.io/zaproxy/zaproxy:stable`) with the scratch dir mounted at
    /zap/wrk and host networking so loopback targets on the dev box work;
  * prints the JSON report to stdout for the lane's `site[].alerts[]` map.
`-I` makes the exit code ignore WARN-level alerts: alerts are findings, not a
tool failure. The report is written to the engine's scratch dir, never into
the caller's project.

Exit codes: 0 report on stdout; 1 neither zap-baseline.py nor docker;
2 target dir missing; 3 no URL; 4 URL is not http(s); 5 ZAP wrote no report.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
TIMEOUT = 1800


def main(argv):
    ap = argparse.ArgumentParser(prog="zapscan.py")
    ap.add_argument("target")
    ap.add_argument("--url", default=os.environ.get("DAST_TARGET_URL") or "")
    ap.add_argument("--runner", choices=("zap-baseline.py", "docker"), default=None)
    args = ap.parse_args(argv[1:])
    if not os.path.isdir(args.target):
        sys.stderr.write(f"zapscan: not a directory: {args.target}\n"); return 2
    url = args.url.strip()
    if not url:
        sys.stderr.write("zapscan: no target URL\n"); return 3
    if not (url.startswith("http://") or url.startswith("https://")):
        sys.stderr.write(f"zapscan: rejected non-HTTP target {url!r}\n"); return 4

    runner = args.runner
    if runner is None:
        runner = "zap-baseline.py" if shutil.which("zap-baseline.py") else (
            "docker" if shutil.which("docker") else None)
    if runner is None or shutil.which(runner) is None:
        sys.stderr.write("zapscan: neither zap-baseline.py nor docker on PATH\n"); return 1

    work = tempfile.mkdtemp(prefix="zap-")
    os.chmod(work, 0o777)          # the image runs as the unprivileged `zap` user
    report = os.path.join(work, "report.json")
    if runner == "docker":
        argv2 = ["docker", "run", "--rm", "--network", "host", "-u", "zap",
                 "-v", f"{work}:/zap/wrk:rw", IMAGE,
                 "zap-baseline.py", "-t", url, "-J", "report.json", "-I"]
    else:
        argv2 = ["zap-baseline.py", "-t", url, "-J", "report.json", "-I"]
    try:
        proc = subprocess.run(argv2, capture_output=True, text=True, timeout=TIMEOUT,
                              stdin=subprocess.DEVNULL, cwd=work)
    except Exception as e:                                       # noqa: BLE001
        sys.stderr.write(f"zapscan: {runner} failed: {e}\n")
        shutil.rmtree(work, ignore_errors=True); return 5
    for ln in (proc.stdout or "").splitlines()[-3:]:
        sys.stderr.write(f"zapscan: {ln[:200]}\n")
    if not os.path.exists(report):
        sys.stderr.write(f"zapscan: no report written (rc={proc.returncode}): "
                         f"{(proc.stderr or '')[-300:]}\n")
        shutil.rmtree(work, ignore_errors=True); return 5
    with open(report, encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
