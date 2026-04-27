# nice-dns: bridges.env parse bug on macOS install

You are continuing work on the `nice-dns` repo. A second Claude validated the
install on a Mac via `install-mac.sh` and the chain failed to come up because
of a code bug. Apply the patch below on this host (where the canonical repo
lives), commit, and push to `origin/main`. Then the Mac validator will re-run
and complete the §Verify checks.

## What broke

Install aborted at `install-mac.sh:164` with:

```
/Users/user/.config/nice-dns/bridges.env: line 4: 37.218.245.14:38224: command not found
```

`unbound` and `pi-hole` came up cleanly. Pi-hole's new build-time gravity step
worked perfectly — 7 Dockerfile steps, ~850k gravity domains, 19s. `tor-haproxy`
never started, no DNS pin, no LaunchAgent.

## Root cause

Commit `7d871aa` ("write bridges.env without surrounding quotes for podman
`--env-file`") fixed Linux but broke Mac. The Mac install script consumes the
same file via bash dot-source:

```bash
# install-mac.sh:164
. "${XDG_CONFIG_HOME:-$HOME/.config}/nice-dns/bridges.env"
```

Bash `source` on `BRIDGE1=obfs4 1.2.3.4:5678 FPR cert=… iat-mode=0` does NOT
read the whole line as one value. It assigns `BRIDGE1=obfs4` for the duration
of one command, then tries to execute `1.2.3.4:5678` as that command — hence
the "command not found" on the IP:port token.

Verified on the Mac:

```
$ cat > /tmp/t.env <<'EOF'
BRIDGE1=obfs4 1.2.3.4:5678 ABCDEF cert=foo iat-mode=0
EOF
$ bash -c '. /tmp/t.env; echo "BRIDGE1=[$BRIDGE1]"'
/tmp/t.env: line 1: 1.2.3.4:5678: command not found
BRIDGE1=[]
```

The comment in `scripts/fetch-bridges.sh:82-86` claiming bash `source`
correctly parses `KEY=value with spaces` without quotes is wrong. The three
consumers (podman `--env-file`, systemd `EnvironmentFile=`, bash `source`)
cannot all share one file format if any of them is bash source — quotes are
required for bash and forbidden for the other two. So one consumer needs a
different parser. The least invasive fix is to stop using bash source on Mac.

## Patch 1 — `install-mac.sh`

Replace lines 163–166 (the `. bridges.env` block):

```bash
# shellcheck disable=SC1090,SC1091
. "${XDG_CONFIG_HOME:-$HOME/.config}/nice-dns/bridges.env"
: "${BRIDGE1:?bridges.env did not export BRIDGE1}"
: "${BRIDGE2:?bridges.env did not export BRIDGE2}"
```

with a non-shell parse:

```bash
# bridges.env is written without surrounding quotes for podman --env-file /
# systemd EnvironmentFile= compatibility (Linux quadlets), so bash `source`
# can't be used here — it would split on whitespace inside the obfs4 line.
# Parse the two keys directly with sed instead.
_bridges_file="${XDG_CONFIG_HOME:-$HOME/.config}/nice-dns/bridges.env"
BRIDGE1="$(sed -n 's/^BRIDGE1=//p' "$_bridges_file")"
BRIDGE2="$(sed -n 's/^BRIDGE2=//p' "$_bridges_file")"
: "${BRIDGE1:?bridges.env did not export BRIDGE1}"
: "${BRIDGE2:?bridges.env did not export BRIDGE2}"
```

(Keep the surrounding context — `"$HERE/scripts/fetch-bridges.sh"` on the
preceding line and the `"$CONTAINER_BIN" run -d --name "tor-${VARIANT}" …`
block that follows — unchanged. Do NOT refactor the rest of the script.)

## Patch 2 — `scripts/fetch-bridges.sh`

Replace the misleading comment at lines ~82–86 (the block above
`umask 077`). The current text claims:

```
# Write atomically. NO surrounding quotes on values: podman --env-file does
# NOT strip quotes (they become part of the value, breaking the obfs4 regex
# in the container's start.sh). systemd EnvironmentFile= and bash `source`
# both parse "KEY=value with spaces" correctly without quoting, so unquoted
# is the only format that works for all three consumers.
```

The "bash `source` … parse[s] correctly" claim is wrong. Replace with:

```
# Write atomically. NO surrounding quotes on values: podman --env-file and
# systemd EnvironmentFile= both treat quotes as literal characters, which
# breaks the obfs4 regex in tor-haproxy/tor-socat start.sh. Bash `source`,
# in contrast, requires quotes around space-containing values — so the Mac
# install script (install-mac.sh) reads BRIDGE1/BRIDGE2 with `sed`, not
# `source`, and this unquoted format works for all three consumers.
```

Also update the docstring at the top of `fetch-bridges.sh` (around lines 5–6)
that says:

```
# `set -a; . bridges.env` (install-mac.sh).
```

to:

```
# `sed -n 's/^KEY=//p'` (install-mac.sh — bash `source` is unsafe on values
# with spaces and no quotes).
```

## Commit

One commit, two files:

```
fix(mac): parse bridges.env with sed, not bash source

bash dot-source on `KEY=value with spaces` (no quotes) splits the value
on whitespace and tries to execute the tail as a command, so install-mac.sh
aborted on every fresh Mac install after 7d871aa removed quotes for podman
--env-file compatibility. Replace `. bridges.env` with `sed -n 's/^KEY=//p'`
which doesn't invoke a shell. Also correct the comments in fetch-bridges.sh
that claimed bash source handled the unquoted format.

Verified on macOS 26 / container 0.11.0: pi-hole + unbound + tor-haproxy
chain came up after the patch.
```

(Adjust author / co-author trailers per your usual policy.)

## After push

Tell the Mac validator the commit is on `origin/main`. They will re-run

```
bash <(curl -sL https://raw.githubusercontent.com/sureserverman/nice-dns/main/install-mac.sh)
```

and continue with the §Verify checks. Image layers are cached on the Mac
(both `pi-hole:latest` and `unbound:latest`), so a re-run will only need to
fetch the patched install script + re-run the Tor bootstrap (~30–60s).

## Do NOT

- Refactor the surrounding install script. Targeted change only.
- Change the on-disk format of `bridges.env`. Re-quoting it would re-break
  podman `--env-file` on Linux (commit `7d871aa` is the canonical fix).
- Change the Linux quadlet `EnvironmentFile=` consumers — they remain
  correct on the unquoted format.
- Skip the comment fix in `fetch-bridges.sh`. The wrong comment is what led
  the previous round to assume bash source was safe.
