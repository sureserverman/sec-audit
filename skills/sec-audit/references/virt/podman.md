# Podman — Rootless Containers and Quadlet

## Source

- https://docs.podman.io/en/latest/markdown/podman.1.html — podman(1) command reference
- https://docs.podman.io/en/latest/markdown/podman-run.1.html — `podman run` flag reference
- https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html — Quadlet unit-file reference (`.container`, `.volume`, `.network`, `.pod`, `.kube`, `.image`, `.build`)
- https://github.com/containers/common/blob/main/docs/containers.conf.5.md — `containers.conf` reference
- https://github.com/containers/common/blob/main/docs/containers-policy.json.5.md — image-trust `policy.json`
- https://www.cisecurity.org/benchmark/podman — CIS Podman Benchmark (latest)
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/ — RHEL container guide (Podman canonical)
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190

## Scope

Covers Podman runtime configuration on Linux: rootless mode, `containers.conf`, `policy.json` image-trust, Quadlet unit files (`*.container`, `*.volume`, `*.network`, `*.pod`, `*.kube`, `*.image`, `*.build`) under `~/.config/containers/systemd/` (rootless) or `/etc/containers/systemd/` (rootful), `podman-compose` files, and the Podman socket (`podman.socket`, both rootless user-scope and rootful system-scope). Out of scope: Containerfile authoring (covered by `containers/dockerfile-hardening.md`); Kubernetes-style YAML emitted by `podman generate kube` (covered by `infra/k8s-workloads.md`).

## Dangerous patterns (regex/AST hints)

### Rootful Podman daemon enabled when not required — CWE-269

- Why: Podman's signature property is rootless operation: every container runs inside a user-namespace, and a container escape lands as the user, not root. Enabling the rootful `podman.socket` (system-scope) under `/run/podman/podman.sock` re-creates Docker's blast radius — anyone with socket access can launch privileged containers and pivot to host root. The legitimate rootful use cases are narrow (host-network requirement, `< 1024` port binds without `CAP_NET_BIND_SERVICE` ambient, certain device pass-throughs). Default to rootless; flag any systemd unit that enables the system-scoped socket without justification.
- Grep: `systemctl enable.*podman\.socket` (system-scope) OR `[Socket]` block in `/etc/systemd/system/podman.socket` overrides.
- File globs: `*.service`, `*.socket`, `containers.conf`, ansible/install scripts
- Source: https://docs.podman.io/en/latest/markdown/podman-system-service.1.html

### Quadlet `.container` file with `User=root` and no `UserNS=` — CWE-269

- Why: Quadlet `.container` files are systemd-native container declarations; they generate `.service` units at `daemon-reload`. A `.container` running as root WITHOUT a `UserNS=auto` (or `UserNS=keep-id` for user-mapped workloads) declaration runs the container's UID 0 as host UID 0 (in rootful mode) or user-namespace-mapped UID 0 (in rootless). For rootful Quadlets, `UserNS=auto` is the equivalent of Docker's `userns-remap`: it picks an unused subuid range and maps the container into it. Missing `UserNS=` on a rootful `.container` is the Podman-Quadlet equivalent of a missing `userns-remap` on Docker.
- Grep: `[Container]` blocks containing `User=root` (or absent — defaults to root) AND no `UserNS=` directive.
- File globs: `*.container`, `containers/systemd/*.container`
- Source: https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html

### Quadlet `.container` mounts `/run/podman/podman.sock` — CWE-250

- Why: Direct Podman-socket equivalent of Docker's `/var/run/docker.sock` mount (`docker-runtime.md`, same CWE class). A container with the rootful Podman socket can launch privileged sibling containers and pivot to host root. Even rootless socket-mounting hands the container the user's full Podman API — escape limited to that user, but any persistence the user has (cron, ssh keys, dotfiles) is reachable. Use a podman-socket-proxy ACL or rearchitect to avoid socket access.
- Grep: `Volume=.*\bpodman\.sock` OR `Volume=.*\b/run/(user/[0-9]+/)?podman/podman\.sock`
- File globs: `*.container`, `podman-compose.y?(a)ml`
- Source: https://docs.podman.io/en/latest/markdown/podman-system-service.1.html

### `--privileged` flag in `Exec=` or `PodmanArgs=` — CWE-250

- Why: Same blast radius as Docker's `privileged: true`: drops all capability filtering, disables seccomp, disables SELinux/AppArmor confinement on the container, and mounts every device. On rootless Podman the host-root pivot is blocked by the user namespace, but in-namespace root still has every capability that namespace supports — escape primitives that need only `CAP_SYS_ADMIN` (e.g. mount-namespace tricks) succeed. CIS Podman Benchmark §5.4. NIST SP 800-190 §4.5.1.
- Grep: `(?:^|\s)--privileged\b` in Quadlet `PodmanArgs=` lines, `podman run` shell invocations, or compose files.
- File globs: `*.container`, `podman-compose.y?(a)ml`, shell scripts, ansible playbooks
- Source: https://www.cisecurity.org/benchmark/podman

### `containers-policy.json` accepts unsigned images by default — CWE-345

- Why: `policy.json` controls image-trust evaluation: which signers are trusted for which registries. The shipping default on many distros is `{ "default": [{ "type": "insecureAcceptAnything" }] }`, which accepts any image from any registry without signature verification. A registry MITM, a typosquatted registry name, or a registry takeover lands a malicious image. The hardened pattern is `default: reject` plus per-registry `signedBy` keypaths (or `sigstoreSigned` for cosign). Red Hat's Skopeo/Podman supply-chain guide is the canonical source.
- Grep: `"insecureAcceptAnything"` as the `default` value OR absence of a per-registry `signedBy` block for any registry referenced by Quadlets/compose under target.
- File globs: `policy.json`, `containers-policy.json`, `/etc/containers/policy.json`, `~/.config/containers/policy.json`
- Source: https://github.com/containers/common/blob/main/docs/containers-policy.json.5.md

### `NoNewPrivileges=` not set on Quadlet `.container` — CWE-250

- Why: Quadlet emits a systemd `.service` from each `.container`. Without `NoNewPrivileges=true` in the `[Service]`-equivalent directives (`SecurityOpt=no-new-privileges:true` in the `[Container]` block, or via the generated unit's `NoNewPrivileges=`), suid binaries inside the container can elevate privileges via execve. Functionally equivalent to Docker's `no-new-privileges` daemon-default gap; Podman has no daemon-wide setting, so every Quadlet must declare it.
- Grep: `[Container]` blocks without any `SecurityOpt=no-new-privileges` OR `[Service]` overrides without `NoNewPrivileges=`.
- File globs: `*.container`
- Source: https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html

### Image referenced by mutable tag in Quadlet — CWE-829

- Why: Same supply-chain rationale as the Compose `:latest` pattern in `docker-runtime.md`. Quadlet's `Image=registry/repo:tag` pulls at unit start; a tag re-point silently propagates. Pin by digest (`Image=registry/repo@sha256:...`); record the human-readable tag in a comment. Skopeo (`skopeo inspect --format '{{.Digest}}'`) is the canonical lookup.
- Grep: `^\s*Image=[^@\n]+:[^@\n]+$` (tag form) AND NOT `Image=[^@]+@sha256:[0-9a-f]{64}`.
- File globs: `*.container`, `*.image`, `*.build`
- Source: https://github.com/containers/skopeo

## Secure patterns

Hardened rootless Quadlet `.container`:

```ini
# ~/.config/containers/systemd/api.container
[Unit]
Description=API service

[Container]
Image=ghcr.io/example/api@sha256:8b1f3a...   # v1.4.2
User=10001:10001
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
AddCapability=NET_BIND_SERVICE
SecurityLabelDisable=false
PublishPort=127.0.0.1:8080:8080
Volume=app-data.volume:/data:Z
Secret=db_password,target=/run/secrets/db_password,mode=0400
Environment=DB_PASSWORD_FILE=/run/secrets/db_password

[Install]
WantedBy=default.target
```

Source: https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html

Hardened `policy.json` (sigstore signature requirement per registry):

```json
{
  "default": [{ "type": "reject" }],
  "transports": {
    "docker": {
      "ghcr.io/example": [{
        "type": "sigstoreSigned",
        "keyPath": "/etc/containers/keys/example.pub"
      }],
      "registry.access.redhat.com": [{
        "type": "signedBy",
        "keyType": "GPGKeys",
        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
      }]
    }
  }
}
```

Source: https://github.com/containers/common/blob/main/docs/containers-policy.json.5.md

Rootless socket-proxy pattern (use `podman-socket-proxy` or block at the firewall level rather than mounting the socket directly):

```ini
[Container]
# DO NOT do this:
# Volume=%t/podman/podman.sock:/var/run/docker.sock

# Instead expose only the API surface needed via a proxy with an ACL.
Image=ghcr.io/tecnativa/docker-socket-proxy@sha256:...
Environment=CONTAINERS=1 IMAGES=1 POST=0
Volume=%t/podman/podman.sock:/var/run/docker.sock:ro
NoNewPrivileges=true
DropCapability=ALL
ReadOnly=true
```

Source: https://www.cisecurity.org/benchmark/podman

## Fix recipes

### Recipe: switch a rootful Quadlet to rootless + UserNS=auto — addresses CWE-269

**Before (dangerous):**

```ini
# /etc/containers/systemd/api.container  (rootful)
[Container]
Image=ghcr.io/example/api:latest
User=root
PublishPort=80:8080
```

**After (safe):**

```ini
# ~/.config/containers/systemd/api.container  (rootless user scope)
[Container]
Image=ghcr.io/example/api@sha256:8b1f3a...   # v1.4.2
UserNS=auto
User=10001:10001
NoNewPrivileges=true
DropCapability=ALL
AddCapability=NET_BIND_SERVICE
PublishPort=127.0.0.1:8080:8080
```

Source: https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html

### Recipe: replace `insecureAcceptAnything` with signedBy/sigstoreSigned — addresses CWE-345

**Before (dangerous):**

```json
{ "default": [{ "type": "insecureAcceptAnything" }] }
```

**After (safe):**

```json
{
  "default": [{ "type": "reject" }],
  "transports": {
    "docker": {
      "ghcr.io/example": [{
        "type": "sigstoreSigned",
        "keyPath": "/etc/containers/keys/example.pub"
      }]
    }
  }
}
```

Source: https://github.com/containers/common/blob/main/docs/containers-policy.json.5.md

### Recipe: pin Quadlet image by digest — addresses CWE-829

**Before (dangerous):**

```ini
[Container]
Image=docker.io/library/nginx:latest
```

**After (safe):**

```ini
[Container]
Image=docker.io/library/nginx@sha256:0a399eb16751829e1af26fea27b20c3ec28d7ab1fb72182879dcae1cca21206a   # 1.27.0
```

Source: https://github.com/containers/skopeo

## Version notes

- Quadlet shipped in Podman 4.4 (Feb 2023); rootless `.container` units under `~/.config/containers/systemd/` require Podman 4.4+. Older Podman uses `podman generate systemd`, which produces hand-editable unit files that drift from the running config.
- `UserNS=auto` requires sufficient subuid/subgid range in `/etc/subuid` and `/etc/subgid` for the user; default ranges (typically 65,536) are tight for multi-container deployments. Allocate at least `100000:200000` per workload-owner.
- Rootless Podman networking on Linux uses `pasta` by default since Podman 5.0 (replacing `slirp4netns`); pasta has stricter port-binding semantics — host-network `--net=host` is unavailable in rootless mode (this is a feature).
- `policy.json` evaluation runs at pull and at `podman start`; a Quadlet referencing a digest-pinned image with no matching signature in policy will fail to start with a clear error (`signature for image is not present`).

## Common false positives

- A Quadlet `.container` file under `examples/` or `docs/` in target — documentation, not deployed; downgrade to LOW.
- `User=root` on a `.container` that is itself a privileged management workload (firewall, monitoring agent) where the rootful requirement is documented in the unit's `Description=` — flag as MEDIUM not HIGH; the absence of `UserNS=auto` is still a finding.
- `Exec=/bin/sh` (which contains `--privileged` as a literal string in a comment) — regex matches but is not the flag; the parser must check `--privileged` is a separate token.
- Test fixtures named `*.container` that are intentionally insecure for benchmark/test purposes — downgrade if the file path matches `tests/fixtures/` or `e2e/`.
