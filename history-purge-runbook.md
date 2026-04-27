# History purge runbook — leaked secrets in nice-dns + tor-haproxy + tor-socat

**This runbook destroys git history. Read it twice. Test on a fresh clone first.**

## What's in history that shouldn't be

### `nice-dns`
- `pihole/etc/tls.pem` — EC private key (TLS for Pi-hole web UI)
- `pihole/etc/tls.crt`, `tls_ca.crt` — paired certs
- `pihole/etc/cli_pw` — Pi-hole CLI session token
- `pihole/etc/pihole.toml` historical content — leaked admin pwhash (Balloon-SHA256)
- `pihole/etc/pihole-FTL.db*` — DNS query history (privacy)
- `pihole/etc/gravity.db` — blocklist DB (102 MB, large but not sensitive on its own)
- `pihole/etc/dhcp.leases`
- `pihole/etc/listsCache/`, `pihole/etc/hosts/custom.list`

### `tor-haproxy`
- `start.sh` historical content — two real obfs4 bridges (IP, fingerprint, base64 cert) baked into the default values

### `tor-socat`
- `start.sh` historical content — same two obfs4 bridge defaults

## Prerequisites

```bash
# Install git-filter-repo (NOT git filter-branch — that's deprecated and slow).
# Debian/Ubuntu:
sudo apt-get install git-filter-repo
# macOS:
brew install git-filter-repo
# Or pipx:
pipx install git-filter-repo
```

## Step 0 — Backup

```bash
cd ~/dev
for repo in nice-dns tor-haproxy tor-socat; do
  cp -a "$repo" "$repo.backup-$(date +%Y%m%d)"
done
```

## Step 1 — Purge `nice-dns`

```bash
cd ~/dev/nice-dns

# Make sure your working tree is clean and you've already committed the
# security-fix changes from this branch. The purge runs against committed
# history, not the working tree.
git status

# The new files (scripts/, adlists-default.txt, custom-denylist.txt) and
# the modified ones (.gitignore, install-*.sh, pihole.toml, quadlets) need
# to be committed first if they aren't already.
git add -A
git commit -m "security: scrub leaked TLS, cli_pw, pwhash; restore adlists via auto-seed; SHA-pin actions; fetch bridges via Moat"

# Now purge the secret paths from ALL history.
git filter-repo \
  --path pihole/etc/tls.pem \
  --path pihole/etc/tls.crt \
  --path pihole/etc/tls_ca.crt \
  --path pihole/etc/cli_pw \
  --path pihole/etc/gravity.db \
  --path pihole/etc/pihole-FTL.db \
  --path pihole/etc/pihole-FTL.db-shm \
  --path pihole/etc/pihole-FTL.db-wal \
  --path pihole/etc/dhcp.leases \
  --path pihole/etc/listsCache \
  --path pihole/etc/hosts \
  --invert-paths

# Scrub the leaked pwhash from any historical pihole.toml content. The
# replacement leaves the line intact but removes the secret value.
cat > /tmp/nice-dns-replace.txt <<'EOF'
regex:pwhash = "\$BALLOON-SHA256\$[^"]+"==>pwhash = ""
EOF
git filter-repo --replace-text /tmp/nice-dns-replace.txt --force
rm /tmp/nice-dns-replace.txt
```

## Step 2 — Purge `tor-haproxy`

```bash
cd ~/dev/tor-haproxy

git status
git add -A && git commit -m "security: remove hardcoded obfs4 bridge defaults; USER app + setcap; SHA-pin actions; rate-limit haproxy" || true

# Strip the literal bridge fingerprints + certs from every historical
# version of start.sh. Use --replace-text so blame/log are preserved but
# the secret tokens are redacted.
cat > /tmp/tor-haproxy-replace.txt <<'EOF'
B93BAE4F17CEACD9E491920C5D283C0D4C3D6D3D==>REDACTED-FPR-1
p+n8+6mTYmEMpFy+rDuQSyNy4X5pxarA9MzDknqk+WAukqpVa+uE0JJymTK8b8wSyK5pJw==>REDACTED-CERT-1
CEF423251E83353BD875CB5327B458F4C8751170==>REDACTED-FPR-2
HMCEwtFxM3OK68PTtZ0NXeYlabBRrRGF1IddIEfXk0J7Dmuq7Y2zgohCwjluwFE0AuH8Zg==>REDACTED-CERT-2
109.110.170.208:29323==>REDACTED-IP-1
84.22.109.77:8088==>REDACTED-IP-2
EOF
git filter-repo --replace-text /tmp/tor-haproxy-replace.txt --force
rm /tmp/tor-haproxy-replace.txt
```

## Step 3 — Purge `tor-socat`

```bash
cd ~/dev/tor-socat

git status
git add -A && git commit -m "security: remove hardcoded bridge defaults; USER app; socat max-children; pin lyrebird; SHA-pin actions" || true

# tor-socat had the EXACT same default bridges as tor-haproxy.
cat > /tmp/tor-socat-replace.txt <<'EOF'
B93BAE4F17CEACD9E491920C5D283C0D4C3D6D3D==>REDACTED-FPR-1
p+n8+6mTYmEMpFy+rDuQSyNy4X5pxarA9MzDknqk+WAukqpVa+uE0JJymTK8b8wSyK5pJw==>REDACTED-CERT-1
CEF423251E83353BD875CB5327B458F4C8751170==>REDACTED-FPR-2
HMCEwtFxM3OK68PTtZ0NXeYlabBRrRGF1IddIEfXk0J7Dmuq7Y2zgohCwjluwFE0AuH8Zg==>REDACTED-CERT-2
109.110.170.208:29323==>REDACTED-IP-1
84.22.109.77:8088==>REDACTED-IP-2
EOF
git filter-repo --replace-text /tmp/tor-socat-replace.txt --force
rm /tmp/tor-socat-replace.txt
```

## Step 4 — Verify

```bash
# Each command should return EMPTY. If anything matches, the purge missed something.
cd ~/dev/nice-dns
git log -p --all -- pihole/etc/tls.pem | head
git log --all -p | grep -F 'BEGIN EC PRIVATE KEY' | head
git log --all -p | grep -F 'BALLOON-SHA256' | head

cd ~/dev/tor-haproxy
git log --all -p | grep -F 'B93BAE4F17CEACD9E491920C5D283C0D4C3D6D3D' | head

cd ~/dev/tor-socat
git log --all -p | grep -F 'CEF423251E83353BD875CB5327B458F4C8751170' | head
```

## Step 5 — Force push

`git filter-repo` removes the `origin` remote on purpose to make you stop and think.

```bash
# For each repo:
git remote add origin git@github.com:sureserverman/<repo>.git

# Notify any collaborators FIRST. Force-push rewrites every SHA — they
# must re-clone (not pull/rebase). Open issues, PR refs, GitHub Actions
# run history all stay; only commit SHAs change.
git push --force-with-lease --all origin
git push --force-with-lease --tags origin
```

## Step 6 — Rotate compromised material

History purge does NOT un-leak secrets that were ever fetched by anyone (CI logs, mirrors, Wayback Machine, any clone made before the purge). Treat as compromised regardless:

| What | Why | How to rotate |
|---|---|---|
| Pi-hole admin password | pwhash leaked, Balloon-SHA256 is brute-forceable offline | Already scrubbed; new install starts password-less. Run `pihole -a -p '<new>'` after install. |
| Pi-hole TLS key | EC private key was in repo | Already removed from disk; pihole-FTL regenerates self-signed cert on first start. |
| Pi-hole `cli_pw` | Auth token leaked | Pihole regenerates on every container start. |
| obfs4 bridges | Operator-private bridges? Or public BridgeDB? Either way, treat as enumerable. | Decommission those two specific bridges if you operated them. New installs auto-fetch fresh bridges via Moat. |
| Docker Hub published images (`sureserver/tor-haproxy:latest`, `tor-socat:latest`) | Still contain the old `start.sh` with hardcoded bridges baked into image layers | Push a new `v*` tag → new GH Actions workflow rebuilds → re-push. Then optionally delete old tags from Docker Hub. |

## Step 7 — Set follow-ups

- `~/.config/nice-dns/bridges.env` already exists on your machine — pre-populated by `scripts/fetch-bridges.sh`. Other operators get fresh bridges on their first install.
- Subscribe to GitHub Security advisories on the repos.
- Consider adding `gitleaks` as a pre-commit hook to prevent recurrence (one of the un-fixed sec-audit LOW findings).
