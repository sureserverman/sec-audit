# systemd Unit-File Hardening

## Source

- https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html — systemd.exec(5): execution environment directives, sandboxing, and capability controls
- https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html — systemd.service(5): service unit configuration and type-specific options
- https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html — systemd-analyze(1): the `security` subcommand scores unit hardening exposure
- https://man7.org/linux/man-pages/man7/capabilities.7.html — capabilities(7): Linux capability set semantics and per-capability descriptions
- https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html — systemd.resource-control(5): MemoryMax, CPUQuota, and cgroup-based resource limits

## Scope

In-scope: hardening directives in systemd `.service`, `.socket`, and `.timer` unit files — specifically sandboxing knobs (`ProtectSystem`, `PrivateTmp`, `ProtectHome`, `PrivateNetwork`), privilege controls (`NoNewPrivileges`, `CapabilityBoundingSet`, `AmbientCapabilities`, `User`), syscall filtering (`SystemCallFilter`, `SystemCallArchitectures`), path isolation (`ReadWritePaths`, `ReadOnlyPaths`, `InaccessiblePaths`), socket family restrictions (`RestrictAddressFamilies`), credential handling (`LoadCredential`, `SetCredential`), and output redirection (`StandardOutput`, `StandardError`). Out of scope: AppArmor, SELinux, Flatpak, and Snap confinement policies (covered by `linux-sandboxing.md`); Debian packaging scripts and `postinst`/`prerm` hooks (covered by `linux-packaging.md`); tool invocations such as `systemd-analyze`, `coredumpctl`, and `journalctl` usage patterns (covered by `linux-tools.md`).

## Dangerous patterns (regex/AST hints)

### `ProtectSystem=` absent or disabled — CWE-732

- Why: When `ProtectSystem=` is absent from a `[Service]` block, or explicitly set to `false` or `off`, the service process can write to `/usr`, `/boot`, and (under `strict`) `/etc` without restriction. Any process compromise can overwrite system binaries, configuration, or bootloader components.
- Grep: `^ProtectSystem\s*=\s*(false|off)\s*$` — AND absence of `^ProtectSystem\s*=` in the `[Service]` block entirely
- File globs: `**/*.service`, `**/*.socket`, `**/*.timer`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `PrivateTmp=` absent or `false` — CWE-377

- Why: Without `PrivateTmp=true`, the service shares the global `/tmp` and `/var/tmp` namespaces with all other processes. An attacker in another process can create symlinks or race-condition temporary files used by this service (a classic TOCTOU vector) or read files the service writes to a predictable path.
- Grep: `^PrivateTmp\s*=\s*false`
- File globs: `**/*.service`, `**/*.socket`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `NoNewPrivileges=` absent or `false` — CWE-250

- Why: When `NoNewPrivileges=` is absent or explicitly `false`, any setuid or setgid binary executed by the service's process tree can gain additional privileges, expanding the blast radius of a code-execution compromise. The `PR_SET_NO_NEW_PRIVS` prctl is the kernel mechanism this directive sets. Exception: a service that deliberately calls `setuid()` to drop to a less-privileged UID (e.g. a privilege-separation daemon) must keep this unset; that case requires a documented rationale comment — see the Secure patterns section.
- Grep: `^NoNewPrivileges\s*=\s*false`
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `CapabilityBoundingSet=` absent or broadly set — CWE-269

- Why: If `CapabilityBoundingSet=` is absent, the service inherits the full Linux capability set — including `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, and 37 others — regardless of which `User=` it runs as. A compromised service with these capabilities can remount filesystems, bypass DAC checks, load kernel modules, and reconfigure networking. Specifying an explicit minimal set (or `~CAP_SYS_ADMIN CAP_NET_ADMIN ...` to drop specific dangerous caps) enforces least-privilege at the capability level.
- Grep: absence of `^CapabilityBoundingSet\s*=` in the `[Service]` block; or `^CapabilityBoundingSet\s*=\s*$` (empty value retains nothing, which is safe, but an absent directive is the danger)
- File globs: `**/*.service`
- Source: https://man7.org/linux/man-pages/man7/capabilities.7.html

### `SystemCallFilter=` absent in a root/high-capability service — CWE-693

- Why: Without a syscall allowlist, the service can invoke any syscall the kernel supports, including `ptrace`, `process_vm_writev`, `keyctl`, `mount`, `init_module`, and others frequently exploited in container escapes and privilege escalation. `SystemCallFilter=@system-service` provides a curated positive list maintained by systemd that is appropriate for most daemons; absence means the service relies solely on capability checks and ProtectSystem/PrivateTmp for containment.
- Grep: absence of `^SystemCallFilter\s*=` in `[Service]` blocks that also contain `^User\s*=\s*root` or lack an explicit `^User=`
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `ReadWritePaths=` set to `/` or broad system paths — CWE-732

- Why: `ProtectSystem=strict` makes `/usr`, `/boot`, and `/etc` read-only, but `ReadWritePaths=` can surgically re-grant write access to listed paths. Setting `ReadWritePaths=/` or `ReadWritePaths=/etc` reintroduces the write surface that `ProtectSystem` was intended to remove, and is commonly introduced by maintainers seeking a quick fix for permission errors without narrowing the required path.
- Grep: `^ReadWritePaths\s*=\s*/\s*$` or `^ReadWritePaths\s*=\s*/etc`
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `User=root` without a restrictive `CapabilityBoundingSet` — CWE-250

- Why: Running as the root user while retaining the full capability bounding set is the maximally privileged process configuration on Linux. If a service unit specifies `User=root` (or omits `User=` entirely, which also defaults to root for system units), and `CapabilityBoundingSet=` is absent, the service can perform any operation on the system. The combination provides no defence-in-depth against a code execution vulnerability in the service.
- Grep: `^User\s*=\s*root` paired with absence of `^CapabilityBoundingSet\s*=` in the same `[Service]` block
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `RestrictAddressFamilies=` absent in a network-binding service — CWE-284

- Why: Without `RestrictAddressFamilies=`, the service can create sockets in any family the kernel supports: `AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_NETLINK`, `AF_PACKET`, `AF_BLUETOOTH`, and others. A compromised service can leverage `AF_NETLINK` to reconfigure routing tables or firewall rules, or `AF_PACKET` to perform raw packet capture, far beyond what its intended function requires.
- Grep: absence of `^RestrictAddressFamilies\s*=` in `[Service]` blocks that also contain `ListenStream=`, `ListenDatagram=`, or `ListenNetlink=` in a paired `.socket` unit
- File globs: `**/*.service`, `**/*.socket`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `SetCredential=` with a sensitive-looking key stored in plaintext — CWE-312

- Why: `SetCredential=` embeds a credential value directly in the unit file in plaintext. Unit files are world-readable by default under `/etc/systemd/system/`. If the key name contains `password`, `token`, `secret`, or `key`, it is almost certainly sensitive material that should instead use `LoadCredential=` to read from a path with tight permissions (mode 0400, owner root), or use `SetCredentialEncrypted=` (systemd 250+) for at-rest encryption tied to the machine's TPM.
- Grep: `^SetCredential\s*=\s*[^:]+:(password|token|secret|key|passwd|apikey|api_key|private)`
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### `StandardOutput=file:` or `StandardError=file:` redirecting outside journald — CWE-532

- Why: Redirecting output to an arbitrary file path (e.g. `StandardOutput=file:/var/log/myapp.log`) bypasses journald's access-control model. If the service logs sensitive information — authentication tokens, session data, stack traces — those secrets are written to a file whose permissions depend entirely on the directory ACL, are not subject to journald's log-rotation and tamper-evident storage, and may be readable to any process with access to the path. Services that must log to files should do so at the application layer with explicit `chmod 0600` and rotation policy.
- Grep: `^Standard(Output|Error)\s*=\s*file:`
- File globs: `**/*.service`
- Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html

## Secure patterns

### (a) Minimal hardened service unit

A network-facing daemon with a dedicated unprivileged user, filesystem isolation, no new privileges, a minimal capability set, and a syscall allowlist:

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Application Daemon
After=network.target

[Service]
Type=simple
User=myapp
Group=myapp
ExecStart=/usr/bin/myapp --config /etc/myapp/myapp.conf

# Filesystem isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
# Allow the service to write only to its own state and runtime directories
ReadWritePaths=/var/lib/myapp /run/myapp

# Privilege controls
NoNewPrivileges=true
# Drop everything except the ability to bind privileged ports if needed;
# omit CAP_NET_BIND_SERVICE if the service does not bind ports < 1024.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Syscall filtering: the @system-service set covers the vast majority of
# daemons; add specific extras only with documented justification.
SystemCallFilter=@system-service
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# Socket family restriction: only IPv4/IPv6 TCP/UDP; no AF_NETLINK or AF_PACKET.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Miscellaneous hardening
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### (b) Legitimate setuid-helper service with documented `NoNewPrivileges=false`

A privilege-separation daemon that starts as root and uses `setuid()` to drop to an unprivileged UID after binding a privileged resource. `NoNewPrivileges=true` cannot be set here because the process must call `setuid()` itself; however, the capability bounding set is still tightly scoped and all other hardening directives are applied.

```ini
# /etc/systemd/system/privsep-daemon.service
[Unit]
Description=Privilege-Separation Daemon (binds :443, then drops to daemon user)
After=network.target

[Service]
Type=simple
# Must start as root to call setuid(); will drop privileges in application code
# after binding the privileged port.  NoNewPrivileges cannot be set because the
# process itself calls setuid() — setting it would cause setuid() to fail with
# EPERM.  This is a conscious, documented exception; do not copy without the
# same design constraint.
User=root
NoNewPrivileges=false

ExecStart=/usr/bin/privsep-daemon --port 443 --drop-user daemon

# Restrict capabilities to only what the pre-drop phase needs.
# CAP_NET_BIND_SERVICE: bind port 443.
# CAP_SETUID / CAP_SETGID: call setuid()/setgid() to drop privileges.
# All other capabilities are stripped from the bounding set.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/privsep-daemon

SystemCallFilter=@system-service setuid setgid
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

## Fix recipes

### Recipe: Add baseline hardening stanza to an unhardened unit — addresses CWE-732 / CWE-377 / CWE-250 / CWE-269 / CWE-693

**Before (dangerous):**

```ini
[Unit]
Description=Legacy Application Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/legacyapp --config /etc/legacyapp.conf

[Install]
WantedBy=multi-user.target
```

**After (safe):**

```ini
[Unit]
Description=Legacy Application Daemon
After=network.target

[Service]
Type=simple
User=legacyapp
Group=legacyapp
ExecStart=/usr/bin/legacyapp --config /etc/legacyapp.conf

# --- Baseline hardening stanza ---
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/legacyapp

NoNewPrivileges=true
CapabilityBoundingSet=

SystemCallFilter=@system-service
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
# --- End hardening stanza ---

[Install]
WantedBy=multi-user.target
```

`CapabilityBoundingSet=` with an empty value drops all capabilities. If the service later fails to bind a port or perform a privileged operation, add back only the specific capability required. Run `systemd-analyze security legacyapp.service` after any change to see the updated exposure score.

Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### Recipe: Replace `ReadWritePaths=/` with specific required paths — addresses CWE-732

**Before (dangerous):**

```ini
[Service]
ProtectSystem=strict
# Blanket re-grant undoes ProtectSystem=strict entirely:
ReadWritePaths=/
```

**After (safe):**

```ini
[Service]
ProtectSystem=strict
# Grant write access only to the exact directories the service legitimately
# writes to.  Identify these by running the service under strace or by
# reviewing its source code.  Do not add paths speculatively.
ReadWritePaths=/var/lib/myapp /run/myapp /var/log/myapp
```

If the service writes to `/etc` at runtime (e.g. to update a config file), prefer using `StateDirectory=` and `ConfigurationDirectory=` systemd-managed paths under `/var/lib` and `/etc` respectively, which confine writes to a subdirectory named after the service rather than the entire `/etc` tree.

Source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

### Recipe: Narrow `CapabilityBoundingSet` from unset (all caps) to an explicit positive list — addresses CWE-269

**Before (dangerous):**

```ini
[Service]
# CapabilityBoundingSet= is absent; the process inherits all ~40 capabilities.
User=myapp
ExecStart=/usr/bin/myapp
```

**After (safe):**

```ini
[Service]
User=myapp
ExecStart=/usr/bin/myapp

# Positive list: grant only the capabilities the service actually needs.
# The tilde prefix (~) means "drop everything EXCEPT what follows"; use it when
# it is easier to name what to keep than to name everything to drop.
# Example below: service binds a port below 1024, nothing else privileged.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Ambient capabilities promote the bounding-set entry into the ambient set so
# an unprivileged User= can actually exercise the capability without file caps.
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

To determine which capabilities a service actually uses, run it under `capsh --print` or inspect `/proc/<pid>/status` fields `CapInh`/`CapPrm`/`CapEff`/`CapBnd` during normal operation. Reduce to the observed set. If the service needs no capabilities at all, set `CapabilityBoundingSet=` (empty) which drops the entire bounding set.

Source: https://man7.org/linux/man-pages/man7/capabilities.7.html

## Version notes

- `ProtectSystem=strict` (also protects `/etc`) was introduced in systemd 232 (2016). Older distributions shipping systemd < 232 only support `full` (protects `/usr` and `/boot`) and `true`/`yes` (same as `full`). Verify the systemd version with `systemctl --version` before relying on `strict`.
- `SetCredentialEncrypted=` (TPM-bound credential encryption) requires systemd 250+ and a TPM 2.0 device. On hosts without a TPM, fall back to `LoadCredential=` with a mode-0400 file owned by root.
- `MemoryDenyWriteExecute=true` breaks JIT-compiled runtimes (Java, Node.js, .NET, LuaJIT) that map anonymous executable pages. Do not set this directive for services that run such runtimes; document the omission.
- `SystemCallFilter=@system-service` covers the curated list as of the systemd version installed. The exact set of syscalls in each named group (e.g. `@system-service`, `@network-io`, `@file-system`) can be inspected with `systemd-analyze syscall-filter @system-service`.
- `RestrictNamespaces=true` blocks all namespace creation. Services that use `bubblewrap`, `firejail`, or internal sandboxing via `clone(CLONE_NEWUSER)` must either omit this or specify only the namespace types they need (e.g. `RestrictNamespaces=~user mnt`).
- `systemd-analyze security <unit>` was introduced in systemd 232 and provides a numeric exposure score (0 = least exposed, 10 = fully exposed). Scores above 7.0 indicate a unit with no meaningful sandboxing.

## Common false positives

- `ProtectSystem=` absent in a `.timer` unit — timer units do not run a process directly; hardening directives on the timer itself have no effect; the hardening must be on the paired `.service` unit.
- `NoNewPrivileges=false` (or absent) in a service that runs `su`, `sudo`, `newgrp`, or an application-level privilege-separation model — this is the documented exception; confirm the rationale is recorded in the unit file and that `CapabilityBoundingSet` is still restricted.
- `User=root` in a one-shot (`Type=oneshot`) unit that performs a privileged system initialisation task at boot (e.g. `ExecStart=/sbin/modprobe ...`) — flag for review but downgrade severity if the unit has `RemainAfterExit=no`, runs for a bounded duration, and applies `CapabilityBoundingSet` scoped to only the capabilities the task requires.
- `ReadWritePaths=/run/myapp` where `/run/myapp` is a `RuntimeDirectory=myapp`-managed path — this is redundant rather than dangerous; `RuntimeDirectory=` already creates the directory with mode 0755 owned by `User=`; the explicit `ReadWritePaths=` entry adds no new attack surface.
- `SystemCallFilter=` absent in a `.socket` unit — socket activation units do not execute a process; the filter applies to the `.service` unit that gets activated.
- `StandardOutput=file:/var/log/myapp/access.log` where the log directory is mode 0700 owned by the service's `User=` and the service does not log credential material — this is lower severity but still worth flagging for rotation and journald integration review.
