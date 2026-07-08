#!/usr/bin/env python3
"""Compute the changed-file set for sec-audit's --diff mode.

Usage: diffscope.py <target> [ref]
  bare       -> working-tree changes (staged + unstaged vs HEAD) + untracked files
  with ref   -> the above PLUS everything changed on this branch since <ref>
                (three-dot merge-base: `<ref>...HEAD`)

Prints one target-relative path per line on stdout. Deleted files are excluded
(there is nothing to scan). Exits non-zero with a stderr message when <target>
is not a git repository or <ref> cannot be resolved. Pure stdlib; shells out to
`git` (always present wherever a repo is checked out).
"""
import subprocess
import sys


def _git(target, *args):
    return subprocess.run(["git", "-C", target, *args],
                          capture_output=True, text=True)


def _lines(text):
    return [ln for ln in text.splitlines() if ln.strip()]


def changed_files(target, ref=None):
    probe = _git(target, "rev-parse", "--is-inside-work-tree")
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        raise SystemExit(f"diffscope: {target} is not a git repository")

    files = set()
    # Working-tree changes vs HEAD (staged + unstaged), excluding deletions.
    # Tolerate failure so a repo with no commits (no HEAD) still yields untracked.
    wt = _git(target, "diff", "--name-only", "--diff-filter=d", "HEAD")
    if wt.returncode == 0:
        files.update(_lines(wt.stdout))
    # Untracked files (respecting .gitignore).
    untracked = _git(target, "ls-files", "--others", "--exclude-standard")
    files.update(_lines(untracked.stdout))
    # Branch changes since <ref> (three-dot merge-base). Fail loudly on a bad ref.
    if ref:
        br = _git(target, "diff", "--name-only", "--diff-filter=d", f"{ref}...HEAD")
        if br.returncode != 0:
            raise SystemExit(
                f"diffscope: cannot diff against ref {ref!r}: {br.stderr.strip()}")
        files.update(_lines(br.stdout))
    return sorted(files)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: diffscope.py <target> [ref]\n")
        sys.exit(2)
    target = sys.argv[1]
    ref = sys.argv[2] if len(sys.argv) > 2 else None
    for f in changed_files(target, ref):
        sys.stdout.write(f + "\n")


if __name__ == "__main__":
    main()
