# Docker Daemon / Container Security

## Source

- https://docs.docker.com/engine/security/ — Docker Engine security overview
- https://docs.docker.com/engine/security/seccomp/ — Docker seccomp profiles
- https://docs.docker.com/engine/security/apparmor/ — Docker AppArmor profiles
- https://docs.docker.com/engine/security/userns-remap/ — User namespace remapping
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 Application Container Security Guide
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html — OWASP Docker Security Cheat Sheet
- https://www.cisecurity.org/benchmark/docker — CIS Docker Benchmark

## Scope

Covers Docker Engine (CE and EE), Docker Compose v2, and Docker Swarm mode on Linux hosts. Applies to daemon configuration (`/etc/docker/daemon.json`), container runtime flags, and `docker.sock` exposure. Does not cover Podman, containerd direct usage, or Kubernetes CRI — see `containers/kubernetes.md` for Pod-level controls.

## Dangerous patterns (regex/AST hints)

### Docker socket mounted into container — CWE-269

- Why: Mounting `/var/run/docker.sock` gives the container full control of the Docker daemon and trivial host escape.
- Grep: `docker\.sock`
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`, `*.json`, `Dockerfile`
- Source: https://docs.docker.com/engine/security/#docker-daemon-attack-surface

### Privileged container — CWE-250

- Why: `--privileged` disables all seccomp/AppArmor restrictions and grants every Linux capability, equivalent to root on the host.
- Grep: `privileged:\s*true|--privileged`
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`, `*.sh`, `*.yaml`
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.3.1)

### Host namespace sharing (pid/net/ipc) — CWE-284

- Why: Sharing host PID/network/IPC namespaces removes isolation boundaries; `--pid=host` allows ptrace of host processes.
- Grep: `--pid=host|--net=host|--ipc=host|pid_mode:\s*host|network_mode:\s*host|ipc:\s*host`
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`, `*.sh`
- Source: https://docs.docker.com/engine/security/ (Kernel namespaces section)

### No-new-privileges not set — CWE-269

- Why: Without `no-new-privileges`, a setuid binary inside the container can escalate capabilities beyond the container's initial set.
- Grep: `security_opt` (absence of `no-new-privileges`)
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Capabilities not dropped — CWE-250

- Why: Default Docker capability set includes `NET_RAW`, `SYS_CHROOT`, and others unnecessary for most workloads; retaining them widens attack surface.
- Grep: `cap_add|--cap-add`
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`, `*.sh`
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.3.2)

### Writable root filesystem — CWE-732

- Why: A writable root filesystem allows an attacker who gains code execution to persist malware or modify binaries in the container.
- Grep: `read_only:\s*false` (or absence of `read_only: true`)
- File globs: `docker-compose*.yml`, `docker-compose*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Secure patterns

Minimal hardened Compose service definition:

```yaml
services:
  app:
    image: myapp:1.2.3@sha256:<digest>
    user: "1000:1000"
    read_only: true
    security_opt:
      - no-new-privileges:true
      - seccomp:profiles/restricted.json
      - apparmor:docker-default
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # only if port < 1024 is needed
    tmpfs:
      - /tmp
    volumes: []            # no docker.sock, no host paths
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

Daemon configuration with user namespace remapping and TLS:

```json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem"
}
```

Source: https://docs.docker.com/engine/security/userns-remap/

## Fix recipes

### Recipe: Remove docker.sock volume mount — addresses CWE-269

**Before (dangerous):**

```yaml
services:
  agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**After (safe):**

```yaml
services:
  agent:
    image: myagent:1.4.2@sha256:<digest>
    # Use a purpose-built Docker API proxy (e.g. Tecnativa/docker-socket-proxy)
    # that whitelists only the API endpoints the agent actually needs,
    # and mount that proxy socket instead — or refactor to avoid Docker-in-Docker.
    environment:
      - DOCKER_HOST=tcp://dockerproxy:2375
```

Source: https://docs.docker.com/engine/security/#docker-daemon-attack-surface

### Recipe: Drop all capabilities and add back minimal set — addresses CWE-250

**Before (dangerous):**

```yaml
services:
  web:
    image: nginx:1.25
    # no cap_drop, no cap_add — inherits full default set
```

**After (safe):**

```yaml
services:
  web:
    image: nginx:1.25.3@sha256:<digest>
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
```

Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.3.2)

### Recipe: Enable user namespace remapping — addresses CWE-250

**Before (dangerous):**

```json
{}
```

**After (safe — `/etc/docker/daemon.json`):**

```json
{
  "userns-remap": "default"
}
```

Source: https://docs.docker.com/engine/security/userns-remap/

### Recipe: Replace privileged with specific capabilities — addresses CWE-250

**Before (dangerous):**

```yaml
services:
  app:
    image: myapp:2.0
    privileged: true
```

**After (safe):**

```yaml
services:
  app:
    image: myapp:2.0.1@sha256:<digest>
    privileged: false
    cap_drop:
      - ALL
    cap_add:
      - SYS_PTRACE   # only the specific capability actually required
    security_opt:
      - no-new-privileges:true
      - seccomp:profiles/restricted.json
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Version notes

- User namespace remapping (`userns-remap`) is available since Docker Engine 1.10. On older engines the only mitigation is running a non-root user inside the container.
- `--security-opt no-new-privileges` has been supported since Docker 1.11.
- The `seccomp` default profile changed in Docker 20.10; verify your custom profiles against the updated syscall list at https://docs.docker.com/engine/security/seccomp/.
- Docker Desktop 4.x enables enhanced container isolation (hypervisor-level) on macOS/Windows, which is separate from Linux kernel namespace controls and does not replace the above hardening on Linux hosts.

## Common false positives

- `--privileged` in CI/CD "docker-in-docker" (dind) sidecar containers — required by design for dind; confirm the container is a build-time sidecar, not a runtime workload.
- `/var/run/docker.sock` mounted in Portainer, Watchtower, or Docker-socket-proxy containers — these management tools legitimately need daemon access; verify the container image is trusted and access is read-limited via socket proxy.
- `network_mode: host` in local performance benchmarking Compose files (`docker-compose.bench.yml`) — flag only if present in production Compose manifests.
- `cap_add: SYS_ADMIN` in `docker-compose.test.yml` for kernel-feature integration tests — acceptable in ephemeral CI environments, not in production service definitions.
