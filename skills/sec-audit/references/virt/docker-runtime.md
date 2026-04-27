# Docker Runtime — Daemon and Socket Hardening

## Source

- https://docs.docker.com/reference/cli/dockerd/ — `dockerd` daemon reference (canonical flag/option list)
- https://docs.docker.com/engine/security/ — Docker Engine security overview
- https://docs.docker.com/engine/security/userns-remap/ — user-namespace remapping (`userns-remap`)
- https://docs.docker.com/engine/security/rootless/ — rootless mode
- https://docs.docker.com/engine/security/protect-access/ — protecting the daemon socket (TLS or systemd activation)
- https://docs.docker.com/engine/swarm/secrets/ — Swarm-mode secrets
- https://www.cisecurity.org/benchmark/docker — CIS Docker Benchmark (latest)
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 Application Container Security Guide
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html — OWASP Docker Security Cheat Sheet

## Scope

Covers Docker Engine **runtime** configuration: `/etc/docker/daemon.json`, the `dockerd` command line, the daemon socket (`/var/run/docker.sock` and TCP variants), Compose / Stack files (`docker-compose.yml`, `compose.yaml`) at the runtime layer, and Swarm-mode secret/config patterns. Out of scope: Dockerfile authoring (covered by `containers/dockerfile-hardening.md` — cross-link, do not duplicate); Kubernetes admission (covered by `infra/k8s-workloads.md` and `infra/k8s-api.md`); image registry trust (separate concern). Image-tag pinning patterns at the Compose layer are in scope here.

## Dangerous patterns (regex/AST hints)

### Docker socket bind-mounted into a container — CWE-250

- Why: Mounting `/var/run/docker.sock` into a container hands that container full root-equivalent control over the host's Docker daemon — it can launch privileged containers, mount the host filesystem, and pivot to host root. This is a structural escalation, not a software bug; the mount itself is the vulnerability. Even "read-only" socket mounts do not help, because `docker exec` requests are POSTs that arrive over the same socket. The CIS Docker Benchmark 2.x §5 explicitly disallows it for non-trusted workloads. The safe pattern is to use rootless Docker, a socket-proxy (e.g. `tecnativa/docker-socket-proxy` with a strict ACL), or to grant Docker API access via mTLS to a specific authenticated client.
- Grep: `(?:^|\s)(?:-v|--volume|volumes:\s*-?\s*)["']?/var/run/docker\.sock`
- File globs: `docker-compose.y?(a)ml`, `compose.y?(a)ml`, `*.compose.y?(a)ml`, shell scripts, k8s manifests
- Source: https://www.cisecurity.org/benchmark/docker

### Daemon listens on TCP without TLS (`-H tcp://0.0.0.0:2375`) — CWE-319

- Why: The classic remote-code-execution pivot. `dockerd -H tcp://0.0.0.0:2375` exposes the unauthenticated Docker API to the network — anyone who can reach port 2375 can spawn a privileged container that mounts `/` from the host. Internet-exposed `:2375` is a perennial top entry on Shodan and a documented mass-compromise vector. The only safe TCP exposure is `:2376` with mutual TLS (`--tlsverify --tlscacert --tlscert --tlskey`) and a tight ACL on the listener.
- Grep: `["']?-H["']?\s*=?\s*["']?tcp://[^"']*:2375` OR daemon.json `"hosts":\s*\[[^\]]*"tcp://[^"]*:2375`
- File globs: `daemon.json`, `/etc/docker/daemon.json`, `docker.service`, `*.systemd`, shell scripts
- Source: https://docs.docker.com/engine/security/protect-access/

### `userns-remap` not configured — CWE-269

- Why: Without user-namespace remapping, UID 0 inside a container is UID 0 on the host. Combined with any of the dozen container-escape primitives (`CAP_SYS_ADMIN`, kernel keyring leaks, mount-tricks, `/proc` writes), an in-container root escalates trivially to host root. With `userns-remap`, the container's UID 0 maps to a non-privileged subuid on the host (e.g. `100000`); a successful escape lands on an unprivileged uid. CIS Docker Benchmark §2.8 mandates `userns-remap` for production. Note: `userns-remap` is incompatible with privileged-container, host-PID, host-IPC, and `--read-only` patterns that depend on UID 0 — this is not a drop-in flag, but its absence on a multi-tenant host is a documented hardening gap.
- Grep: daemon.json missing `"userns-remap"` key in a non-rootless deployment.
- File globs: `daemon.json`
- Source: https://docs.docker.com/engine/security/userns-remap/

### `no-new-privileges` not set in container runtime defaults — CWE-250

- Why: `no-new-privileges` blocks `setuid` and `setgid` binaries inside the container from gaining privileges via execve — it neutralises a whole class of in-container escalation primitives. Setting it daemon-wide via `daemon.json`'s `"no-new-privileges": true` makes it the default for every container; setting it per-container via `--security-opt=no-new-privileges` is the per-workload form. Compose files MUST declare `security_opt: ["no-new-privileges:true"]` for every service unless a specific suid binary is required (rare). CIS Docker Benchmark §5.25.
- Grep: daemon.json missing `"no-new-privileges": true` AND/OR Compose services without `security_opt` block listing it.
- File globs: `daemon.json`, `docker-compose.y?(a)ml`, `compose.y?(a)ml`
- Source: https://docs.docker.com/reference/cli/dockerd/

### `live-restore` disabled in production — CWE-693

- Why: `live-restore: true` allows the daemon to restart (e.g. for a security patch) without killing running containers. With `live-restore: false` (the default), every daemon restart kills every container — operators who fear that restart-storm delay security patches, leaving the host running an unpatched daemon. The flag does not weaken security; it removes a disincentive to patching. CIS Docker Benchmark §2.13 recommends enabling it on production hosts.
- Grep: daemon.json missing `"live-restore": true`.
- File globs: `daemon.json`
- Source: https://www.cisecurity.org/benchmark/docker

### `privileged: true` Compose service — CWE-250

- Why: `privileged: true` grants the container all Linux capabilities, removes the seccomp filter, removes the AppArmor profile, and bind-mounts every device under `/dev`. It is functionally equivalent to running the workload as root on the host. The legitimate use cases are Docker-in-Docker testbeds and a handful of system-management containers; everything else should drop to a minimal capability set with `cap_add` / `cap_drop`. CIS §5.4. NIST SP 800-190 §4.5.1.
- Grep: `^\s*privileged:\s*true\b`
- File globs: `docker-compose.y?(a)ml`, `compose.y?(a)ml`
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final

### Swarm secrets passed via environment variable — CWE-522

- Why: Swarm `secrets:` mount the secret as a file under `/run/secrets/<name>`, where it never enters the process environment and never appears in `ps`/`/proc/<pid>/environ`. Compose files that copy the secret into an env-var (`environment: { DB_PASSWORD: "{{ secret 'db_password' }}" }`-style or a literal `env_file` reference to a checked-in secret) defeat the file-mount design and expose the credential to any process that reads `/proc`. The safe pattern is to keep the secret as a file mount and have the application read it on startup (e.g. via `_FILE` env-var conventions like `POSTGRES_PASSWORD_FILE=/run/secrets/db_password`).
- Grep: `secrets:` block in a service plus `environment:` lines that reference the same secret name.
- File globs: `docker-compose.y?(a)ml`, `compose.y?(a)ml`
- Source: https://docs.docker.com/engine/swarm/secrets/

### Compose service uses mutable image tag (`:latest`, `:stable`, no tag) — CWE-829

- Why: `image: nginx:latest` resolves at pull time; the same compose file can yield a different image on Tuesday than on Monday because the registry tag was re-pointed. A compromised upstream maintainer (or a registry takeover) silently propagates to every consumer. Pinning by digest (`image: nginx@sha256:...`) makes the dependency immutable; the human-readable tag goes in a trailing comment. Equivalent rationale to GitHub Actions SHA-pinning (`infra/gh-actions-permissions.md`).
- Grep: `image:\s*[^@\n]+:latest\b` OR `image:\s*[^@:\n]+\s*$` (no tag) — and any tag that is NOT `@sha256:`.
- File globs: `docker-compose.y?(a)ml`, `compose.y?(a)ml`, `*.stack.y?(a)ml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Secure patterns

Minimal hardened `daemon.json`:

```json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "default-ulimits": { "nofile": { "Name": "nofile", "Hard": 65535, "Soft": 65535 } }
}
```

Source: https://docs.docker.com/reference/cli/dockerd/

Compose service with explicit security defaults and pinned image:

```yaml
services:
  api:
    image: ghcr.io/example/api@sha256:8b1f3a...   # pin v1.4.2
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    user: "10001:10001"
    secrets:
      - db_password
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password

secrets:
  db_password:
    external: true
```

Source: https://docs.docker.com/engine/swarm/secrets/

mTLS-protected daemon socket (TCP), unit-file form:

```ini
# /etc/systemd/system/docker.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd \
    -H unix:///var/run/docker.sock \
    -H tcp://0.0.0.0:2376 \
    --tlsverify \
    --tlscacert=/etc/docker/ca.pem \
    --tlscert=/etc/docker/server-cert.pem \
    --tlskey=/etc/docker/server-key.pem
```

Source: https://docs.docker.com/engine/security/protect-access/

## Fix recipes

### Recipe: remove `/var/run/docker.sock` mount, swap to a socket-proxy — addresses CWE-250

**Before (dangerous):**

```yaml
services:
  watchtower:
    image: containrrr/watchtower:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**After (safe):**

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy@sha256:abc123...   # v0.1.1
    environment:
      CONTAINERS: 1
      IMAGES: 1
      POST: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [internal]
    read_only: true
    security_opt: [no-new-privileges:true]

  watchtower:
    image: containrrr/watchtower@sha256:def456...           # v1.7.1
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375
    networks: [internal]
    # no docker.sock here

networks:
  internal:
    internal: true
```

Source: https://docs.docker.com/engine/security/protect-access/

### Recipe: replace `:latest` tag with digest pin — addresses CWE-829

**Before (dangerous):**

```yaml
services:
  web:
    image: nginx:latest
```

**After (safe):**

```yaml
services:
  web:
    image: nginx@sha256:0a399eb16751829e1af26fea27b20c3ec28d7ab1fb72182879dcae1cca21206a   # 1.27.0
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Recipe: enable userns-remap + no-new-privileges + live-restore — addresses CWE-269 / CWE-250 / CWE-693

**Before (dangerous):**

```json
{}
```

**After (safe):**

```json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "icc": false
}
```

Source: https://www.cisecurity.org/benchmark/docker

## Version notes

- `userns-remap` is incompatible with `--privileged`, `--pid=host`, `--ipc=host`, `--network=host`, and bind-mounted device files that the container expects to write as UID 0. Audit per-workload before flipping the daemon flag.
- Docker rootless mode (`dockerd-rootless-setuptool.sh`) is a stronger alternative to `userns-remap` for single-tenant hosts — the entire daemon runs as a non-root user, and a daemon compromise lands as that user, not root. Adoption gate is the lack of host-namespace networking and reduced storage-driver options.
- Docker Engine 25.x defaults `live-restore` and `icc:false` in the new-installation path; long-lived hosts upgraded from older versions retain their original `daemon.json` and may be missing both. Explicit declaration is the only way to be sure.

## Common false positives

- `/var/run/docker.sock` mount in a developer-only `docker-compose.override.yml` clearly scoped to a local dev environment — annotate with a comment noting the local-only scope; flag as MEDIUM not HIGH.
- `:latest` tag on a known-vendor base image used in a CI throwaway job (linter container, test runner) where the image has no persistence — still flag, but downgrade confidence to medium.
- Compose files in `examples/` or `docs/` directories under target — these are documentation, not deployed config; downgrade to LOW unless the repository's README points at them as the canonical deployment.
