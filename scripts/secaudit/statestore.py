#!/usr/bin/env python3
"""Schema-versioned persistence for sec-audit's incremental state (SKILL §1.5).

Owns three files under the state home resolved by statehome.py:

    audit-state.json    the incremental brain — file manifest, lane state,
                        findings by fingerprint, deps, programs, feed timestamps
    history.jsonl       append-only, one line per run, never rewritten
    advisory-cache.json (Stage 5) trimmed advisory projections by id

Design rules, in priority order:

1. **Never silently lose a baseline.** A missing state file is a first run and
   yields the empty skeleton. A *corrupt* or *future-schema* state file is an
   error, not an empty skeleton — silently discarding it would make every
   carried finding look NEW and every fixed finding vanish, which is exactly the
   failure mode incremental mode must not have. The user is told to re-run with
   --full, which rebaselines deliberately.
2. **Atomic writes.** Write to a sibling .tmp and os.replace() it, so a crash
   mid-write leaves the previous state intact rather than a truncated file.
   Concurrent audits of one project are last-writer-wins, never corrupt.
3. **Bounded growth.** `runs[]` inside the state keeps the most recent
   MAX_RUNS entries; the full record lives in history.jsonl.

Usage:
  statestore.py load       <home>            -> state JSON on stdout
  statestore.py save       <home>            <- state JSON on stdin
  statestore.py append-run <home>            <- run   JSON on stdin
  statestore.py skeleton                     -> empty schema-v1 state
"""
import json
import os
import sys

SCHEMA = 1
MAX_RUNS = 50
STATE_FILE = "audit-state.json"
HISTORY_FILE = "history.jsonl"


class StateError(Exception):
    """Unusable existing state — never swallowed into an empty skeleton."""


def skeleton(project=None):
    return {
        "schema": SCHEMA,
        "project": project or {"name": "", "area": "", "path": ""},
        "runs": [],
        "manifest": {},     # relpath -> {sha256, size}          (Stage 2)
        "lane_state": {},   # lane    -> {last_run, status, ...}  (Stage 2)
        "findings": {},     # fingerprint -> {first_seen, ...}    (Stage 2)
        "deps": {},         # "eco|name" -> {version, ...}        (Stage 3)
        "programs": {},     # "kind|name" -> {version, ...}       (Stage 3)
        "feeds": {},        # feed -> {fetched_at}                (Stage 5)
    }


def state_path(home):
    return os.path.join(home, STATE_FILE)


def history_path(home):
    return os.path.join(home, HISTORY_FILE)


def load(home, project=None):
    """Return the stored state, or a fresh skeleton on a first run.

    Raises StateError for a corrupt or unsupported-schema file — see rule 1."""
    p = state_path(home)
    if not os.path.exists(p):
        return skeleton(project)
    try:
        with open(p, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError) as e:
        raise StateError(
            f"{p} is unreadable or not valid JSON ({e}). Refusing to treat a "
            "damaged baseline as 'no previous audit' — that would report every "
            "existing finding as NEW. Re-run with --full to rebaseline, or "
            "restore the file.")
    if not isinstance(state, dict) or "schema" not in state:
        raise StateError(f"{p} is not a sec-audit state file (no `schema` key).")
    got = state.get("schema")
    if got != SCHEMA:
        if isinstance(got, int) and got > SCHEMA:
            raise StateError(
                f"{p} was written by a newer sec-audit (schema {got}, this build "
                f"understands {SCHEMA}). Upgrade the plugin, or re-run with "
                "--full --state-dir=<fresh path>.")
        raise StateError(
            f"{p} has schema {got!r}, this build understands {SCHEMA}. Re-run "
            "with --full to rebaseline.")
    # Tolerate a state written before a key existed: fill missing sections so
    # callers can assume the full shape without defensive .get() everywhere.
    base = skeleton(state.get("project"))
    base.update(state)
    return base


def save(home, state):
    """Atomically write the state file, creating the home on first use."""
    if state.get("schema") != SCHEMA:
        raise StateError(f"refusing to save state with schema {state.get('schema')!r}")
    os.makedirs(home, exist_ok=True)
    p = state_path(home)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    # Test seam: prove the previous state survives a crash between write and
    # rename. Never set in production; the .tmp is cleaned up so no partial
    # file is left behind either way.
    if os.environ.get("SECAUDIT_STATESTORE_FAIL_BEFORE_REPLACE"):
        os.unlink(tmp)
        raise StateError("simulated failure before atomic replace (test seam)")
    os.replace(tmp, p)
    return p


def append_run(home, run, state=None):
    """Append one run record to history.jsonl and to the state's capped runs[]."""
    if not isinstance(run, dict) or not run.get("run_id"):
        raise StateError("run record needs a `run_id`")
    os.makedirs(home, exist_ok=True)
    with open(history_path(home), "a", encoding="utf-8") as f:
        f.write(json.dumps(run, sort_keys=True) + "\n")
    if state is None:
        state = load(home)
    runs = [r for r in state.get("runs", []) if r.get("run_id") != run["run_id"]]
    runs.append(run)
    state["runs"] = runs[-MAX_RUNS:]
    save(home, state)
    return state


def previous_run(state):
    """The most recent completed run, or None on a first audit."""
    runs = state.get("runs") or []
    return runs[-1] if runs else None


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__.split("Usage:")[1])
        return 2
    cmd = argv[1]
    try:
        if cmd == "skeleton":
            sys.stdout.write(json.dumps(skeleton(), indent=2) + "\n")
            return 0
        if len(argv) < 3:
            sys.stderr.write(f"statestore: {cmd} needs a <home>\n")
            return 2
        home = argv[2]
        if cmd == "load":
            sys.stdout.write(json.dumps(load(home), indent=2) + "\n")
        elif cmd == "save":
            save(home, json.load(sys.stdin))
        elif cmd == "append-run":
            append_run(home, json.load(sys.stdin))
        else:
            sys.stderr.write(f"statestore: unknown command {cmd!r}\n")
            return 2
    except StateError as e:
        sys.stderr.write(f"statestore: {e}\n")
        return 4
    except ValueError as e:
        sys.stderr.write(f"statestore: invalid JSON on stdin ({e})\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
