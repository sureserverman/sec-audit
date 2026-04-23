# Linux Desktop Sandboxing (AppArmor, SELinux, Flatpak, Snap)

## Source

- https://apparmor.net/ — AppArmor official documentation
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/index — Red Hat RHEL 9: Using SELinux
- https://docs.flatpak.org/en/latest/sandbox-permissions.html — Flatpak Sandbox Permissions reference
- https://snapcraft.io/docs/security-policies — Snapcraft security policies and confinement documentation
- https://man7.org/linux/man-pages/man7/capabilities.7.html — Linux capabilities(7) man page (cross-reference)

## Scope

In scope: Linux desktop sandboxing mechanisms — AppArmor mandatory access control profiles (profile syntax, enforcement vs. complain mode, `deny` rules), SELinux type-enforcement contexts for privileged services (`.te` and `.fc` policy files, `unconfined_t` assignment, `SELinuxContext=` in systemd units), Flatpak manifest sandbox permissions (`--share=`, `--socket=`, `--filesystem=`, `--talk-name=` flags in JSON manifests and YAML build files), and Snap confinement (`confinement:` field, `plugs:` declarations in `snapcraft.yaml`). Out of scope: systemd unit hardening directives such as `CapabilityBoundingSet=`, `PrivateTmp=`, and `NoNewPrivileges=` (covered by `linux-systemd.md`); Debian packaging scripts including `postinst` privilege transitions (covered by `linux-packaging.md`); kernel capabilities analysis in isolation (cross-referenced from the systemd pack via the capabilities(7) man page).

## Dangerous patterns (regex/AST hints)

### AppArmor profile absent for privilege-sensitive service — CWE-693

- Why: A binary that processes authentication, PAM, or password input and ships under `debian/` without a matching profile in `apparmor.d/` runs entirely unconfined. If the binary is exploited, the attacker inherits the full DAC permissions of the service account with no MAC boundary to contain lateral movement or file-system access.
- Grep: cross-check: `find debian/ -name '*.install' -o -name 'install'` lists installed binaries; absence of a matching filename under `**/apparmor.d/` for any binary that handles auth (contains strings such as `pam_`, `PAM`, `shadow`, `passwd`, `auth`) is the signal.
- File globs: `debian/**`, `**/apparmor.d/*`
- Source: https://apparmor.net/

### Flatpak manifest with `--filesystem=host` — CWE-732

- Why: `--filesystem=host` (or `--filesystem=host:rw`) grants the sandboxed application read-write access to the entire host filesystem visible to the user, defeating the primary isolation guarantee of the Flatpak sandbox. Combined with `--share=network` the application can exfiltrate any file reachable by the user's UID to a remote endpoint.
- Grep: `--filesystem=host`
- File globs: `**/*.flatpakref`, `**/*.flatpakrepo`, `**/manifest.json`, `**/manifest.yaml`, `**/manifest.yml`, `flatpak/**/*.json`, `flatpak/**/*.y*ml`
- Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

### Flatpak `--socket=x11` or `--socket=fallback-x11` — CWE-200

- Why: Granting the X11 socket gives the sandboxed application access to the shared X display. The X11 protocol provides no isolation between clients: any client can call `XQueryPointer`, `XGrabKeyboard`, or `XGetImage` to read keystrokes and screen content from every other X11 window, breaking the confidentiality of credentials and other sensitive input entered in any co-running application.
- Grep: `--socket=x11|--socket=fallback-x11`
- File globs: `**/*.flatpakref`, `**/manifest.json`, `**/manifest.yaml`, `**/manifest.yml`, `flatpak/**/*.json`, `flatpak/**/*.y*ml`
- Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

### Flatpak `--talk-name=*` or `--talk-name=org.freedesktop.DBus` — CWE-346

- Why: A wildcard `--talk-name=*` permission allows the sandboxed process to send messages to any service on the session bus, including services that manage secrets (e.g. `org.gnome.keyring`), network configuration (`org.freedesktop.NetworkManager`), or polkit (`org.freedesktop.PolicyKit1`). `--talk-name=org.freedesktop.DBus` itself grants the ability to enumerate all names on the bus. Either form bypasses the origin-isolation intent of the sandbox.
- Grep: `--talk-name=\*|--talk-name=org\.freedesktop\.DBus\b`
- File globs: `**/manifest.json`, `**/manifest.yaml`, `**/manifest.yml`, `flatpak/**/*.json`, `flatpak/**/*.y*ml`
- Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

### Snap `plugs: [home, removable-media]` without content-interface rationale — CWE-732

- Why: The `home` plug grants read-write access to the user's home directory (excluding dot-files by default but including `~/snap` and user documents). The `removable-media` plug extends that access to mounted external media under `/media` and `/mnt`. Granting both without a documented content-interface rationale means an exploited snap can silently read or overwrite user documents and external drives without any additional privilege prompt.
- Grep: `^\s*plugs:\s*\[.*(home|removable-media).*\]`
- File globs: `**/snapcraft.yaml`
- Source: https://snapcraft.io/docs/security-policies

### Snap `confinement: classic` — CWE-693

- Why: Classic confinement disables the snap sandbox entirely; the application runs with the same unrestricted access as a traditionally installed Debian/RPM package. This negates all security properties that snaps are expected to provide and should only be granted for tools that genuinely cannot operate within strict confinement (e.g. compilers that need to access arbitrary host paths). Its presence in a snap that handles network input or user data is a high-severity finding.
- Grep: `confinement:\s*classic`
- File globs: `**/snapcraft.yaml`
- Source: https://snapcraft.io/docs/security-policies

### SELinux `unconfined_t` context on a privileged service — CWE-693

- Why: Assigning `unconfined_t` to a service in a `.te` type-enforcement file, a `.fc` file-context file, or via `SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0` in a systemd unit means SELinux enforces no policy on that process. An exploited privileged service in `unconfined_t` can access any file, socket, or device that DAC permits, making SELinux enforcement meaningless for that service's threat surface.
- Grep: `unconfined_t`
- File globs: `**/*.te`, `**/*.fc`, `**/systemd/**/*.service`, `**/system.d/*.service`
- Source: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/index

### AppArmor profile in complain mode in production — CWE-693

- Why: A profile with `flags=(complain)` or declared via `complain /path/to/binary` logs policy violations but does not enforce them. In production this means the profile provides zero access-control protection; an exploited process can perform any operation the DAC layer allows, with only an audit log entry as evidence. Complain mode is correct only during profile development and testing.
- Grep: `flags=\(complain\)|^complain\s+`
- File globs: `**/apparmor.d/*`, `**/apparmor.d/**/*`
- Source: https://apparmor.net/

## Secure patterns

Minimal Flatpak manifest using scoped filesystem access, IPC sharing only, and portal-based file access instead of broad filesystem grants:

```json
{
  "app-id": "org.example.App",
  "runtime": "org.freedesktop.Platform",
  "runtime-version": "23.08",
  "sdk": "org.freedesktop.Sdk",
  "command": "example-app",
  "finish-args": [
    "--share=ipc",
    "--socket=wayland",
    "--socket=fallback-x11",
    "--filesystem=xdg-documents:ro",
    "--talk-name=org.freedesktop.portal.Desktop",
    "--talk-name=org.freedesktop.portal.FileChooser"
  ]
}
```

No `--share=network`, no `--filesystem=host`, and no `--filesystem=home`. File access beyond `xdg-documents:ro` is mediated through the `org.freedesktop.portal.FileChooser` portal, which requires explicit user consent per file or directory. `--share=ipc` is required for shared-memory X11 extensions (MIT-SHM) when `fallback-x11` is present.

Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

AppArmor profile stanza with explicit `deny` entries and safe `/proc` access:

```
#include <tunables/global>

profile example-daemon /usr/sbin/example-daemon {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Binary and libraries
  /usr/sbin/example-daemon mr,
  /usr/lib/** rm,

  # Required data paths (read-only)
  /etc/example-daemon/ r,
  /etc/example-daemon/*.conf r,

  # Runtime state
  /var/lib/example-daemon/ rw,
  /var/lib/example-daemon/** rw,
  /run/example-daemon.pid rw,

  # Yama ptrace scope (read the current level; never write)
  /proc/sys/kernel/yama/ptrace_scope r,

  # Deny writes to sensitive system paths
  deny /etc/passwd w,
  deny /etc/shadow rwklx,
  deny /etc/sudoers rwklx,
  deny /proc/sysrq-trigger rwklx,

  # Deny capability escalation paths
  deny /usr/bin/sudo x,
  deny /usr/bin/su x,
}
```

Profile runs in enforce mode (no `flags=(complain)`). All `deny` lines are hard denials — they override any `allow` rule and are logged by the kernel audit subsystem. `/proc/sys/kernel/yama/ptrace_scope r,` allows the service to read the current ptrace restriction level for self-diagnostics without granting write access.

Source: https://apparmor.net/

## Fix recipes

### Recipe: Remove `--filesystem=host` and replace with portal-based file access — addresses CWE-732

**Before (dangerous):**

```json
"finish-args": [
  "--share=network",
  "--share=ipc",
  "--socket=x11",
  "--filesystem=host"
]
```

**After (safe):**

```json
"finish-args": [
  "--share=network",
  "--share=ipc",
  "--socket=wayland",
  "--socket=fallback-x11",
  "--filesystem=xdg-documents:ro",
  "--talk-name=org.freedesktop.portal.Desktop",
  "--talk-name=org.freedesktop.portal.FileChooser"
]
```

Replace host-wide filesystem access with the narrowest path that satisfies the application's needs (`xdg-documents:ro` for read-only document access, or `xdg-download:rw` for a download manager). For user-selected file access use `org.freedesktop.portal.FileChooser` so each access requires an explicit user gesture. Remove `--filesystem=host` entirely — there is no safe subset of it that preserves meaningful sandboxing.

Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

### Recipe: Narrow `--socket=x11` to Wayland with X11 fallback — addresses CWE-200

**Before (dangerous):**

```json
"finish-args": [
  "--share=ipc",
  "--socket=x11"
]
```

**After (safe):**

```json
"finish-args": [
  "--share=ipc",
  "--socket=wayland",
  "--socket=fallback-x11"
]
```

`--socket=wayland` grants access to the Wayland compositor socket, which provides per-client isolation; one application cannot read another's input or pixels. `--socket=fallback-x11` is activated only when a Wayland compositor is not available, limiting X11 exposure to legacy environments. If the application is not yet Wayland-capable, retain `--socket=x11` temporarily and add an inline comment noting the tracker issue for Wayland porting; do not silently leave the X11 socket as the permanent configuration. Note: `--socket=fallback-x11` still carries the X11 keylogging risk whenever it activates — treat migration to Wayland as a required follow-up, not an optional improvement.

Source: https://docs.flatpak.org/en/latest/sandbox-permissions.html

### Recipe: Replace Snap `confinement: classic` with `confinement: strict` — addresses CWE-693

**Before (dangerous):**

```yaml
name: example-app
version: "1.0"
summary: Example application
description: An example snap application.
confinement: classic
grade: stable

apps:
  example-app:
    command: bin/example-app
```

**After (safe):**

```yaml
name: example-app
version: "1.0"
summary: Example application
description: An example snap application.
confinement: strict
grade: stable

apps:
  example-app:
    command: bin/example-app
    plugs:
      - network
      - home
      - desktop
      - desktop-legacy
      - wayland
      - x11

plugs:
  network: {}
  home: {}
  desktop: {}
  desktop-legacy: {}
  wayland: {}
  x11: {}
```

Enumerate only the plugs the application actually requires. Remove `home` if the application uses XDG portal APIs for file access instead of direct home-directory reads. Remove `x11` if the application supports Wayland natively. Each plug must have a documented rationale in the snap's store submission — the Snap Store reviewers require justification for `home`, `removable-media`, and any device-access plugs when requesting manual review.

Source: https://snapcraft.io/docs/security-policies

## Version notes

- AppArmor profile syntax version 2 (the `abi <abi/4.0>` header) is required for fine-grained network rule support introduced in AppArmor 4.x (Ubuntu 24.04+). Profiles without an explicit ABI declaration default to version 1 compatibility mode — `deny network` rules may not behave as expected on kernel 6.7+ without the header.
- Flatpak's XDG portal integration requires `xdg-desktop-portal` ≥ 1.14 for the `org.freedesktop.portal.FileChooser` version 3 API; distributions shipping an older portal (e.g. Ubuntu 22.04 LTS ships 1.14.x) may not support all `--talk-name=org.freedesktop.portal.*` capabilities — verify the portal version in CI.
- SELinux `unconfined_t` findings should be corroborated by `sestatus` output or the active policy source; on systems where SELinux is in `permissive` mode globally, individual `unconfined_t` contexts are still policy gaps but the runtime risk is lower than on `enforcing` systems.
- Snap `confinement: classic` snaps must be approved by Canonical's Snap Store review team before publication; the presence of `classic` in a `snapcraft.yaml` in a repository does not mean it has been approved or that the snap is published with that confinement. Verify the published listing before treating it as a confirmed finding in production systems.
- The `--socket=fallback-x11` flag was introduced in Flatpak 1.3.2. On systems with older Flatpak runtimes (e.g. RHEL 8 base), `fallback-x11` is not recognized and the manifest will fail to parse — use `--socket=x11` with a version guard comment.

## Common false positives

- `--filesystem=host` in a Flatpak manifest under `tests/` or `ci/` directories — test harnesses commonly mount the host filesystem for integration testing; confirm the manifest is not the production application manifest before flagging.
- `confinement: classic` in `snapcraft.yaml` — expected and required for developer tools (compilers, debuggers, IDEs) that must access arbitrary host paths; verify the snap's stated purpose and whether it has received Store approval before escalating.
- `unconfined_t` in `.te` files — often appears as a source domain in `allow unconfined_t <target_t>:...` rules granting confined domains permission to be entered from an unconfined context; verify whether the type is the subject (source) or an object in the rule before treating it as a finding.
- `flags=(complain)` in `apparmor.d/` — expected in `/etc/apparmor.d/disable/` symlink targets or in profile files that are explicitly not yet enforced by design (e.g. a profile shipped for user opt-in); check whether the profile is active via `aa-status` output rather than treating the flag as a standalone finding.
- `--socket=fallback-x11` without `--socket=wayland` — this pattern may appear in legacy applications that list both sockets in separate `finish-args` entries rather than as a combined directive; parse the full `finish-args` array before concluding that Wayland support is absent.
- `--talk-name=org.freedesktop.portal.*` names — portal bus names are the safe, recommended alternative to direct filesystem and device access; a `--talk-name=` entry matching the `org.freedesktop.portal.*` namespace is a secure pattern, not a broad D-Bus exposure finding.
