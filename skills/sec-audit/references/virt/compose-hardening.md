# Docker Compose Hardening (kics dockerCompose detective pack)

## Source

- https://docs.docker.com/reference/compose-file/services/ — Compose service reference (`privileged`, `cap_add`, `network_mode`, `pid`, `ipc`, `security_opt`, `volumes`)
- https://docs.kics.io/latest/queries/dockercompose-queries/ — kics dockerCompose query catalogue (the rule set this pack operationalises)
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html — OWASP Docker Security Cheat Sheet
- https://docs.docker.com/engine/security/ — Docker Engine security (capabilities, namespaces, socket exposure)
- https://cwe.mitre.org/ — CWE index

## Scope

The runtime-posture surface of a `docker-compose.y(a)ml` / `compose.y(a)ml`
file: how a service is granted privilege, which host namespaces it shares,
what it mounts, and whether its blast radius is bounded. This is the pack
`virt-runner`'s `kics --type DockerCompose` pass operationalises with
deterministic query IDs, and the pattern reference sec-expert reads for the
reasoning kics can't do (why a given privilege grant is or isn't justified by
the service's job). Out of scope: Dockerfile authorship (`kics` is scoped to
compose here; `hadolint` + `containers/dockerfile-hardening.md` own that),
image-content CVEs (the `image` lane), and Kubernetes manifests (the `k8s`
lane). Sibling runtime packs: `virt/docker-runtime.md`, `virt/podman.md`.

## Dangerous patterns (regex/AST hints)

### Privileged container — CWE-250

- Why: `privileged: true` grants the container all Linux capabilities, access to all host devices, and disables the seccomp/AppArmor/SELinux confinement — a container escape is then a full host compromise. Almost no service legitimately needs it; the rare cases (a Docker-in-Docker builder, a device-management daemon) should use targeted `cap_add` + `devices:` instead.
- Grep: `(?m)^\s*privileged:\s*true`
- kics query: `Privileged Containers Enabled` (`ae5b6871-…`), HIGH
- Source: https://docs.docker.com/engine/security/

### Docker socket mounted into a container — CWE-284

- Why: bind-mounting `/var/run/docker.sock` gives the container full control of the Docker daemon — it can start a new privileged container, mount the host root, and escape. Watchtower/portainer-style patterns do this routinely and are a top container-escape vector.
- Grep: `/var/run/docker\.sock`
- kics query: `Docker Socket Mounted In Container` (`d6355c88-…`), HIGH
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Shared host namespace (network / pid / ipc) — CWE-668

- Why: `network_mode: host` removes network isolation (the container sees and binds every host interface, defeating published-port scoping); `pid: host` lets the container see and signal every host process; `ipc: host` shares SysV/POSIX IPC. Each dissolves a boundary the container runtime exists to enforce.
- Grep: `(?m)^\s*network_mode:\s*["']?host` / `(?m)^\s*pid:\s*["']?host` / `(?m)^\s*ipc:\s*["']?host`
- kics queries: `Host Namespace is Shared` (`8af7162d-…`), `Shared Host Network / PID / IPC`, MEDIUM–HIGH
- Source: https://docs.docker.com/reference/compose-file/services/

### Unrestricted / dangerous added capability — CWE-250

- Why: `cap_add: [SYS_ADMIN]` (or `ALL`, `NET_ADMIN`, `SYS_PTRACE`) hands the container kernel-level powers. `SYS_ADMIN` alone is broad enough to be near-equivalent to `privileged`. Prefer dropping all and adding only the exact capability the service needs (`cap_drop: [ALL]` + a minimal `cap_add`).
- Grep: `(?m)^\s*cap_add:` followed by `SYS_ADMIN` / `NET_ADMIN` / `SYS_PTRACE` / `ALL`
- kics query: `Container Capabilities Unrestricted` (`…`), MEDIUM
- Source: https://docs.docker.com/engine/security/

### `no-new-privileges` not set — CWE-732

- Why: without `security_opt: [no-new-privileges:true]`, a setuid binary inside the container can still escalate the process's privileges past the container user. Setting it is a cheap, near-universal hardening that blocks a whole escalation class.
- Grep: absence of `no-new-privileges:true` in a service's `security_opt`, or an explicit `no-new-privileges:false`
- kics query: `No New Privileges Not Set` (`27fcc7d6-…`), MEDIUM
- Source: https://docs.docker.com/reference/compose-file/services/

### Sensitive host directory mounted — CWE-668

- Why: bind-mounting `/`, `/etc`, `/var/run`, `/proc`, or `/sys` from the host into a container exposes host configuration and runtime state; a writable mount lets the container tamper with the host.
- Grep: a `volumes:` entry whose source is `/`, `/etc`, `/proc`, `/sys`, `/var/run`, or `/root`
- kics query: `Volume Has Sensitive Host Directory`, HIGH
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### No resource limits (memory / cpus / pids) — CWE-770

- Why: a service with no `mem_limit` / `cpus` / `pids_limit` can exhaust host resources (a fork bomb or a memory leak in one container takes down every co-located service) — an availability / DoS hazard, not a privilege one, but a real blast-radius concern.
- Grep: a service with no `deploy.resources.limits` and no `mem_limit`/`cpus`/`pids_limit`
- kics queries: `Memory Not Limited` / `Cpus Not Limited` / `Pids Limit Not Set`, LOW–MEDIUM
- Source: https://docs.docker.com/reference/compose-file/services/

### Hardcoded secret in the environment block — CWE-798

- Why: `environment: { DB_PASSWORD: hunter2 }` commits the credential to the repo and bakes it into `docker inspect` output. Use Compose `secrets:` (file- or external-backed) or an env-file excluded from VCS. (This overlaps the `secrets` lane's remit; kics flags it as a compose-shaped `Passwords And Secrets` finding.)
- Grep: `(?m)^\s*(PASSWORD|SECRET|TOKEN|API_KEY|DB_PASSWORD):\s*\S`
- kics query: `Passwords And Secrets - Generic Password`, HIGH
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Secure patterns

A hardened service — no privilege, dropped capabilities, bounded resources,
secret via the `secrets:` mechanism:

```yaml
services:
  api:
    image: ghcr.io/example/api:1.4.0
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]          # only what it needs
    security_opt:
      - no-new-privileges:true
    pids_limit: 200
    mem_limit: 512m
    cpus: "1.0"
    secrets:
      - db_password                       # file/external, not inline env
secrets:
  db_password:
    external: true
```

Source: https://docs.docker.com/reference/compose-file/services/

## Fix recipes

### Recipe: Replace `privileged: true` with targeted capabilities — addresses CWE-250

**Before (dangerous):**

```yaml
services:
  net:
    image: example/net
    privileged: true
```

**After (safe):**

```yaml
services:
  net:
    image: example/net
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]                  # the actual capability the service uses
    security_opt:
      - no-new-privileges:true
```

Identify the exact capability the workload needs (`strace`/`--cap-add` bisection or the vendor's docs) and grant only that.

Source: https://docs.docker.com/engine/security/

### Recipe: Remove the docker-socket mount — addresses CWE-284

**Before (dangerous):**

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**After (safe):** talk to the daemon through a scoped, authenticated proxy
(e.g. `tecnativa/docker-socket-proxy`) that whitelists only the API endpoints
the service needs, or redesign so the container never needs daemon access.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## Version notes

- Compose spec v2/v3 both accept these keys; `deploy.resources.limits`
  (Swarm) vs top-level `mem_limit`/`cpus` (non-Swarm) differ — kics checks
  both shapes. Compose V2 (the `docker compose` plugin) is the current baseline.
- `security_opt: [no-new-privileges:true]` is honoured by the Docker and
  Podman compose backends alike.

## Common false positives

- `network_mode: host` on a service whose entire purpose is host-network
  packet handling (a monitoring agent, a DHCP relay) — legitimate, but confirm
  it is intentional and documented rather than copy-pasted.
- A short-lived one-shot build/CI service with no resource limits — the
  DoS-blast-radius concern is lower for ephemeral containers; flag LOW.
- A `secrets:`-backed value that kics's generic-password heuristic still
  matches on the *reference* name — verify the value is external/file-backed
  before treating it as a hardcoded credential.
