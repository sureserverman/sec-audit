# Apple Containers — `container` CLI on macOS

## Source

- https://github.com/apple/container — Apple's `container` CLI (open-sourced June 2025)
- https://github.com/apple/containerization — `containerization` Swift framework (the lower-layer library)
- https://developer.apple.com/documentation/virtualization — Virtualization.framework reference
- https://developer.apple.com/documentation/security/hardened_runtime — Hardened Runtime (the macOS code-signing posture every guest helper inherits)
- https://github.com/opencontainers/distribution-spec — OCI Distribution spec (image-pull surface `container` consumes)
- https://github.com/opencontainers/runtime-spec — OCI Runtime spec
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190
- https://csrc.nist.gov/publications/detail/sp/800-125a/rev-1/final — NIST SP 800-125A r1 (Hypervisor Security)

## Scope

Covers Apple's `container` CLI on macOS (Apple silicon only — `arm64` host, Linux `arm64` guest), open-sourced under the `apple/container` GitHub org in June 2025. Each container runs in its own lightweight Linux VM via Virtualization.framework; per-container VMs replace the shared-kernel runtime model of Docker/Podman. In scope: `container.yaml` configuration files, image-pull trust patterns, the `vminitd` init binary in the guest, mounted host paths (Apple's `virtio-fs`-equivalent + Rosetta 2 binary translation passthrough), and `container system` daemon configuration. Out of scope: Linux guest internals (treat as a Linux VM — covered by `virt/libvirt-qemu.md` for the broader VMM patterns), Xcode-builder integration, `Container.app` GUI internals.

## Dangerous patterns (regex/AST hints)

### Image referenced by mutable tag instead of digest — CWE-829

- Why: Same supply-chain rationale as Docker/Podman. `container run docker.io/library/alpine:latest` resolves the tag at pull; a tag re-point silently propagates. The `apple/container` CLI accepts both `:tag` and `@sha256:` references via the same OCI Distribution code path (`container pull` uses the same protocol as `docker pull`). Pin by digest; document the human tag in a comment in `container.yaml`.
- Grep: `image:\s*[^@\n]+:[^@\n]+$` in `container.yaml` (no `@sha256:`); `container run\s+[^@\s]+:[^@\s]+\s` in shell scripts.
- File globs: `container.yaml`, `containers/*.yaml`, shell scripts
- Source: https://github.com/apple/container

### Disabling image-signature verification globally — CWE-345

- Why: `apple/container` integrates with cosign / sigstore for image-signature verification at pull. Disabling verification globally (via `container system config set verify-signatures=false`-equivalent or per-call `--insecure` flags) accepts any image; a registry MITM or typosquat lands a malicious image. The hardened pattern is to pin a list of trusted signers per registry (the OCI Distribution recipe; same shape as Podman's `policy.json` in `virt/podman.md`). At time of writing the trust-policy schema is evolving; check the upstream `container` docs for current syntax.
- Grep: `verify-signatures\s*[:=]\s*(false|0|no)` OR `--insecure` in `container` invocations.
- File globs: `container.yaml`, install scripts, CI workflows that drive `container`
- Source: https://github.com/apple/container

### Host-path mount writeable to guest with no `:ro` — CWE-732

- Why: `container` exposes host paths to the guest VM via Virtualization.framework's directory-share API (the macOS analog of Linux virtiofs). A read-write mount of `$HOME` or `/usr/local` lets a compromised guest write to host paths; combined with macOS launchd watch-paths or shell-rc files, this becomes a host-persistence primitive. The hardened pattern is `:ro` on every mount that does not strictly need write, and a guest-specific scratch volume for write workloads.
- Grep: `volumes:\s*-?\s*-\s*[^:\n]+:[^:\n]+\s*$` in `container.yaml` (no trailing `:ro`); `container run -v [^:\s]+:[^:\s]+(?!:ro)\b` in shell.
- File globs: `container.yaml`, shell scripts
- Source: https://developer.apple.com/documentation/virtualization

### Rosetta 2 binary translation passthrough enabled by default — CWE-693

- Why: Apple silicon hosts can pass Rosetta 2 binary translation into Linux guests via the Virtualization.framework Rosetta API (`VZLinuxRosettaDirectoryShare`). This lets `x86_64` Linux binaries run in `arm64` guests by translating syscalls. The hardening question is whether the guest workload actually needs `x86_64` binaries; if not, exposing Rosetta enlarges the guest's syscall surface (Rosetta has had its own CVEs — e.g. CVE-2023-32434 class issues in the translator) and opens a path to the host's Rosetta cache. Enable Rosetta only when the workload requires it.
- Grep: `rosetta:\s*true\b` OR `--rosetta` flag in `container` invocations whose images are documented as `arm64-only`.
- File globs: `container.yaml`, shell scripts
- Source: https://developer.apple.com/documentation/virtualization

### `container system` daemon socket exposed beyond user scope — CWE-269

- Why: The `container` daemon (a launchd-managed user agent) listens on a Unix socket under `~/Library/Containers/com.apple.container/`. Forwarding this socket to a remote host (e.g. via SSH) hands the remote full container-spawn capability on the local machine — equivalent to forwarding the Docker socket. macOS file ACLs prevent cross-user access by default; SSH `-L` socket forwarding bypasses that boundary. Restrict via SSH config and never forward by default.
- Grep: SSH-config files (`~/.ssh/config`, `Match` blocks) with `LocalForward` or `RemoteForward` referencing `container`-named sockets.
- File globs: `ssh_config`, `~/.ssh/config`, ansible playbooks
- Source: https://github.com/apple/container

### Privileged guest VM (kernel-mode access flags) — CWE-250

- Why: Virtualization.framework offers entitlements for guest VMs to access host kernel surfaces beyond the standard model: `com.apple.vm.networking`, `com.apple.vm.device-access`, and (on macOS hosts targeted as guests) the special `com.apple.private.virtualization.host-key` set. A `container.yaml` requesting these entitlements has the same threat model as Docker `--privileged`: the guest is no longer a normal isolated workload but a host-level component. Most application workloads do not need them; flag any non-system workload requesting them.
- Grep: `entitlements:` blocks listing any `com.apple.vm.*` keys in `container.yaml`.
- File globs: `container.yaml`
- Source: https://developer.apple.com/documentation/virtualization

## Secure patterns

Hardened `container.yaml` for an application service:

```yaml
# container.yaml
apiVersion: container.apple.com/v1
kind: Container
metadata:
  name: api
spec:
  image: ghcr.io/example/api@sha256:8b1f3a...   # v1.4.2
  user: 10001:10001
  read_only: root_filesystem
  no_new_privileges: true
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]
  rosetta: false                # arm64-only image; no x86_64 translation needed
  volumes:
    - source: /Users/dev/projects/api/data
      target: /data
      mode: ro
    - source: scratch
      target: /tmp
      mode: rw
  network:
    publish:
      - host: 127.0.0.1:8080
        container: 8080
  environment:
    DB_PASSWORD_FILE: /run/secrets/db_password
  secrets:
    - name: db_password
      target: /run/secrets/db_password
      mode: 0400
```

Source: https://github.com/apple/container

Image-trust policy (signed-images-only; vendor-pin per registry):

```yaml
# container.yaml — system-scope trust policy
trust:
  default: reject
  registries:
    ghcr.io/example:
      type: sigstoreSigned
      keyPath: /Users/Shared/container-keys/example.pub
    docker.io/library:
      type: signedBy
      keyType: GPGKeys
      keyPath: /Users/Shared/container-keys/dockerhub-official.pub
```

Source: https://github.com/apple/container

## Fix recipes

### Recipe: pin image by digest — addresses CWE-829

**Before (dangerous):**

```yaml
spec:
  image: docker.io/library/postgres:16
```

**After (safe):**

```yaml
spec:
  image: docker.io/library/postgres@sha256:d31fe4cf3ef94e51e2fbf7d29f70c8d9d19ddb8e9bf9eaab85d6a0ea4d2f2cfd   # 16.2
```

Source: https://github.com/apple/container

### Recipe: lock down host-path mount to read-only + scoped path — addresses CWE-732

**Before (dangerous):**

```yaml
volumes:
  - source: /Users/dev
    target: /home/dev
```

**After (safe):**

```yaml
volumes:
  - source: /Users/dev/projects/api/data
    target: /data
    mode: ro
  - source: scratch          # named ephemeral volume; not host-backed
    target: /tmp
    mode: rw
```

Source: https://developer.apple.com/documentation/virtualization

### Recipe: disable Rosetta passthrough on arm64-only workloads — addresses CWE-693

**Before (dangerous):**

```yaml
spec:
  rosetta: true                # default-on in some templates
```

**After (safe):**

```yaml
spec:
  rosetta: false               # arm64-native image; no translation needed
```

Source: https://developer.apple.com/documentation/virtualization

## Version notes

- `apple/container` was open-sourced under the Apache 2.0 licence in June 2025; the configuration schema is still evolving. Validate against the version of the CLI in use (`container --version`) and treat schema findings as advisory until the project tags `1.0`.
- Apple silicon only — there is no `apple/container` for Intel Macs. Findings against an Intel-Mac project root are non-applicable; the runner cleanly-skips when the host architecture is `x86_64` Mac (`arm64` Linux/Windows hosts are unsupported targets entirely).
- Virtualization.framework requires macOS 13+ for the directory-share API used by host-path mounts; `container` itself targets macOS 14+.
- The `vminitd` PID 1 binary in each guest VM is signed and notarized by Apple; image content above PID 1 inherits the trust posture configured in `container.yaml`'s `trust:` block.

## Common false positives

- `:latest` in a sample `container.yaml` under `examples/` or `docs/` — documentation, not deployed; downgrade.
- `mode: rw` on a named volume (not a host path) — named volumes are guest-scoped and do not write to host paths; flag only host-path mounts without `:ro`.
- A workload that genuinely needs `x86_64` translation (legacy build tooling, ARM-unfriendly dependencies) and explicitly documents `rosetta: true` with a justification comment — flag as INFO not MEDIUM.
- Test/dev workloads that bind-mount a project source directory rw for live-reload — common and intentional; downgrade unless the source path is `$HOME` or otherwise structurally over-broad.
