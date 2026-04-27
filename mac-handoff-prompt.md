You are continuing a task from a Claude Code instance running on a different
host. Your job is to finish validating a multi-container DNS-privacy stack
called **nice-dns** on this Mac. The previous instance hit Apple's `container`
runtime vmnet limitation (vmnet bridge port-attachment requires user-session
entitlements that SSH-spawned processes don't have), so it bounced the task
to you to run from a real console session.

## Context — what was done before you

Five sibling repos were security-reviewed: `nice-dns`, `tor-haproxy`,
`tor-socat`, `hardened-unbound`. Many fixes landed in each. **All commits
are now pushed to origin/main** — the README's curl-pipe install command
will fetch the latest code.

Most relevant recent commits in `nice-dns`:

- `46df721` — `fix(install)`: add `--dns 1.1.1.1` to both `podman build`
  (Linux) and `container build` (Mac). Pi-hole's image build runs
  `pihole -g` which has a 120s "wait for DNS resolution" precheck; pinning
  the build's resolver makes that step network-independent of the host.
- `e1973e4` — `fix(mac)`: pin pi-hole `DNS1=172.31.240.251#5335` (with the
  port suffix; unbound listens on 5335).
- `ebd3b44` — `fix(pihole)`: in pi-hole v6, `domainlist.type=0` is **allow**,
  not deny. The 5 "custom" domains (`chatgpt.com`, `googleadservices.com`,
  etc.) the user originally had were on their **allowlist**, not denylist.
  File renamed `pihole/custom-denylist.txt` → `pihole/custom-allowlist.txt`.
- `da4c9b6` — `fix(pihole)`: build `gravity.db` (28 adlists, ~850k domains)
  AT IMAGE BUILD TIME via `RUN pihole -g` in `pihole/Dockerfile`. This
  recreates the original "fast first-start" UX without committing the
  100 MB gravity blob to git.
- `7d871aa` — `fix(bridges)`: write `bridges.env` without surrounding
  quotes (podman `--env-file` doesn't strip quotes; the value would arrive
  in the container with literal `'…'` chars and fail the obfs4 regex).

## Environmental gotchas already discovered on this Mac

1. **Home router DNS at `192.168.0.1` censors `bridges.torproject.org`**
   (returns no answer) and **partially breaks `dl-cdn.alpinelinux.org`**
   (returns CNAME but no A record). Mac's Wi-Fi DNS should already be set
   to `1.1.1.1 1.0.0.1` — verify with `networksetup -getdnsservers Wi-Fi`.
   If it isn't:
   ```
   sudo networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1
   sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
   ```

2. **A working `bridges.env` already exists** at
   `~/.config/nice-dns/bridges.env` (mode 600, two `BRIDGE1=`/`BRIDGE2=`
   lines from Tor Moat, **no surrounding quotes**). `fetch-bridges.sh` is
   idempotent — if the file is present and valid it won't re-fetch.

3. **Run from a real Terminal session**, NOT SSH. Apple `container 0.11.0`'s
   vmnet bridge requires user-session entitlements; from SSH the bridge has
   no carrier and containers can't reach the network.

4. The Mac is currently in an **uninstalled state** — no LaunchAgent, no
   `/usr/local/sbin/start-container*` helpers, no `dnsnet` network, no
   running pi-hole/unbound/tor-haproxy containers. Image layers may be
   cached.

5. Apple `container build` may hit **stale-cached layers** from a prior
   build that used the OLD Dockerfile. If you see only 4 build steps for
   pi-hole instead of 7, force-rebuild with:
   ```
   /opt/homebrew/bin/container image rm pi-hole:latest
   /opt/homebrew/bin/container build --no-cache --dns 1.1.1.1 -t pi-hole \
     -f ~/.nice-dns-local/pihole/Dockerfile ~/.nice-dns-local/pihole/
   ```
   (or fully clean and re-run the installer).

## Your job

1. **Confirm baseline state.** Verify Wi-Fi DNS is `1.1.1.1`, container
   runtime is up (`container system status`), no `dnsnet` network exists,
   no nice-dns LaunchAgent.

2. **Run the install via the README's canonical command:**
   ```
   bash <(curl -sL https://raw.githubusercontent.com/sureserverman/nice-dns/main/install-mac.sh)
   ```
   Watch the `pihole/Dockerfile` build step output. It should show 7 steps
   (apk upgrade, COPY etc, COPY adlists, COPY allowlist, RUN pihole -g,
   RUN chmod, ENTRYPOINT). If you see only 4 steps, the cache hit; clear
   pi-hole image and re-run the installer.

3. **Wait for the chain to come up.** Tor bootstrap takes 30–90 seconds on
   first install. The install script polls for up to 150s with `dig
   @172.31.240.250 +time=3 +short cloudflare.com`. If it gives up, the
   install exits 1 — at that point check `~/Library/Logs/nice-dns.log`
   and individual containers via `container logs <name>`.

4. **Run the README §Verify checks:**
   ```bash
   # Should resolve normally
   dig @172.31.240.250 cloudflare.com
   dig @172.31.240.250 github.com
   dig @172.31.240.250 wikipedia.org

   # Should return 0.0.0.0 (gravity blocking)
   dig @172.31.240.250 +short pubads.g.doubleclick.net
   dig @172.31.240.250 +short adservice.google.com
   dig @172.31.240.250 +short ads.exoclick.com

   # Should return real IPs (allowlist override)
   dig @172.31.240.250 +short chatgpt.com
   dig @172.31.240.250 +short www.googleadservices.com

   # Pi-hole admin UI
   curl -sf -o /dev/null -w "HTTP %{http_code}\n" http://172.31.240.250/admin/

   # Pi-hole admin password is randomly generated on first start
   container exec pi-hole cat /etc/pihole/cli_pw
   ```

5. **Confirm the LaunchAgent persists across login.** Check
   `~/Library/LaunchAgents/org.nice-dns.start-container.plist` exists and
   is loaded:
   ```
   launchctl list | grep nice-dns
   ```

6. **Confirm system DNS is pinned to pi-hole** for at least one network
   service:
   ```
   networksetup -getdnsservers Wi-Fi
   # expected: 172.31.240.250
   ```

## What to report back

- Full output of the install command (especially the pi-hole Dockerfile
  build steps — confirm 7-step run and that `pihole -g` produced ~850k
  gravity domains).
- Results of the §Verify checks (each domain → resolved IP).
- Whether the chain came up within the 150s install-script window.
- Any unexpected errors during install.
- If anything fails: container logs (`container logs pi-hole 2>&1 | tail
  -40`, same for unbound and tor-haproxy), and `~/Library/Logs/nice-dns.log`.

## Constraints

- **Do not** edit code unless validation fails for a code-bug reason. If
  it does, identify the file + line + minimal patch and ask the user to
  apply it on their originating host (where the canonical repo lives) and
  push.
- **Do not** run `sudo softwareupdate --install-rosetta` if it prompts —
  Rosetta is already installed (the install script will skip it).
- The Pi-hole admin password is randomly generated on first start; capture
  it from `cli_pw` and tell the user. (The user can change it later with
  `container exec -it pi-hole pihole -a -p '<pw>'`.)
- If Apple's container build hits the stale-cache problem (only 4 steps
  for pi-hole instead of 7), `container image rm pi-hole:latest` and
  re-run the installer rather than passing `--no-cache` to the install
  script (which doesn't have that flag).

Begin by doing the baseline confirmation, then run the install. Report
back when done.
