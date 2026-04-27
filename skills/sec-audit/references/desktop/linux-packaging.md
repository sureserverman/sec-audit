# Debian/RPM Packaging Metadata and Maintainer Scripts

## Source

- https://lintian.debian.org/tags/maintainer-script-without-set-e.html — Lintian: maintainer-script-without-set-e tag reference
- https://lintian.debian.org/tags/setuid-binary.html — Lintian: setuid-binary tag reference
- https://lintian.debian.org/tags/no-homepage-field.html — Lintian: no-homepage-field tag reference
- https://lintian.debian.org/tags/missing-vcs-browser-field.html — Lintian: missing-vcs-browser-field tag reference
- https://lintian.debian.org/tags/shell-script-fails-syntax-check.html — Lintian: shell-script-fails-syntax-check tag reference
- https://lintian.debian.org/tags/non-standard-file-perm.html — Lintian: non-standard-file-perm tag reference
- https://lintian.debian.org/manual/ — Lintian User's Manual: tag severities, overrides, and profile system
- https://man7.org/linux/man-pages/man7/capabilities.7.html — capabilities(7): Linux capability set semantics, per-capability descriptions, and setuid interaction
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security Cheat Sheet

## Scope

In-scope: Debian and RPM packaging metadata and maintainer scripts — `debian/control`, `debian/rules`, `debian/postinst`, `debian/preinst`, `debian/postrm`, `debian/prerm`, and `.spec` file `%pre`/`%post`/`%preun`/`%postun`/`%files` sections. Out of scope: systemd unit-file hardening such as `ProtectSystem=`, `NoNewPrivileges=`, and capability bounding sets (covered by `linux-systemd.md`); kernel and container sandboxing mechanisms such as AppArmor, SELinux, Flatpak, and Snap confinement (covered by `linux-sandboxing.md`); supply-chain recommendations beyond packaging hygiene such as SLSA provenance attestation, Sigstore signing, and SBOM generation.

## Dangerous patterns (regex/AST hints)

### Maintainer script missing `set -e` — CWE-390

- Why: A maintainer script (`postinst`, `preinst`, `postrm`, `prerm`) that does not begin with `set -e` continues executing silently after any failing command. A failed `adduser`, `chown`, or database migration leaves the system in a partially-installed, undefined state that is invisible to dpkg. CWE-390 (Detection of Error Condition Without Action) applies because the script swallows the error signal and reports success to dpkg regardless.
- Grep: `^#!/bin/(sh|bash)` in the file, AND the first non-shebang non-comment non-blank line does NOT match `^set -e`
- File globs: `debian/postinst`, `debian/preinst`, `debian/postrm`, `debian/prerm`
- Source: https://lintian.debian.org/tags/maintainer-script-without-set-e.html

### `postinst` setting the setuid bit with `chmod 4xxx` — CWE-250

- Why: A `chmod 4755` (or any octal mask with the high quartet set to 4 or higher) inside `postinst` grants the setuid bit to the target binary, causing it to execute as its owner (typically root) for any user who invokes it. Unless the package has an explicit, documented rationale for privilege separation (e.g. `ping`, `sudo`), setting the setuid bit post-install is an unwarranted privilege escalation surface. Lintian raises `setuid-binary` at `error` severity for installed setuid files that are not explicitly overridden.
- Grep: `chmod\s+[0-7]*4[0-7]{3}`
- File globs: `debian/postinst`, `debian/preinst`, `debian/postrm`, `debian/prerm`
- Source: https://lintian.debian.org/tags/setuid-binary.html

### `postinst` downloading over cleartext HTTP or with an unpinned URL — CWE-494

- Why: A maintainer script that executes `curl http://...` or `wget http://...` fetches content over an unencrypted channel where any network intermediary can substitute the payload. When the download is piped directly to a shell interpreter (`curl ... | bash`, `wget -O- ... | sh`) the substituted payload executes immediately with the elevated privileges of the installer. CWE-494 (Download of Code Without Integrity Check) applies; OWASP Supply Chain guidance explicitly prohibits unauthenticated, integrity-unverified fetches in install hooks.
- Grep: `(curl|wget)[^\n]*http://[^ ]+` and `(curl|wget)[^\n]*\|[^\n]*(bash|sh)`
- File globs: `debian/postinst`, `debian/preinst`, `debian/postrm`, `debian/prerm`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### RPM `%post` with `curl | bash` or `wget | sh` — CWE-829

- Why: An RPM `%post` scriptlet that pipes a remote URL directly into a shell interpreter (`curl https://... | bash`, `wget -O- https://... | sh`) introduces an untrusted remote code execution path at package installation time. Even an HTTPS URL is vulnerable if the server is compromised or the URL is hijacked via DNS; without a hash check and signature verification against a trusted key there is no integrity guarantee. CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) applies.
- Grep: `(curl|wget)[^\n]*\|[^\n]*(bash|sh)` in `%post`, `%pre`, `%preun`, `%postun` sections
- File globs: `**/*.spec`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### `debian/rules` overriding `dh_auto_test` to skip tests without a rationale comment — CWE-1295

- Why: A `debian/rules` file that overrides `dh_auto_test` with only `true`, `:`, or a bare `echo` silently drops the upstream test suite from every build, meaning regressions that would have been caught at package-build time are shipped to users. This is operational hygiene (nearest formal classification is CWE-1295, Debug Messages Revealing Unnecessary Information, though the real risk is the inverse — suppression without disclosure). Lintian does not currently raise an error for this pattern, so it requires manual reviewer triage: the intent behind the override must be documented in a comment immediately above or within the override target.
- Grep: `^override_dh_auto_test:` followed within two lines by only `^\s*(true|:|echo[^\n]*)$` with no comment line (`^\s*#`) in between
- File globs: `debian/rules`
- Source: https://lintian.debian.org/manual/

### `debian/control` missing `Homepage:` or `Vcs-Git:` — supply-chain provenance gap

- Why: A source package without `Homepage:` and `Vcs-Git:` (or `Vcs-Browser:`) fields gives downstream users and auditors no canonical pointer to the upstream project or to the packaging repository. This makes it impossible to verify whether the packaged tarball matches upstream, to check for patches applied silently during packaging, or to identify the authoritative issue tracker for security disclosure. Lintian raises `no-homepage-field` and `missing-vcs-browser-field` at `warning` severity. OWASP Supply Chain guidance requires provenance metadata to be traceable to a canonical source.
- Grep: absence of `^Homepage:` or absence of `^Vcs-Git:` in the `Source:` stanza
- File globs: `debian/control`
- Source: https://lintian.debian.org/tags/no-homepage-field.html

### `postinst` writing to `/etc/cron.d/` or `/etc/sudoers.d/` without matching removal in `postrm` — CWE-459

- Why: A `postinst` that creates a file under `/etc/cron.d/` or `/etc/sudoers.d/` but has no corresponding removal in `postrm` leaves a privileged artefact on the system after the package is purged. An orphaned cron job continues running as root; an orphaned sudoers fragment continues granting elevated access — both persist invisibly after `apt purge`. CWE-459 (Incomplete Cleanup) covers artefacts that survive the intended removal of the component that created them.
- Grep: `(cron\.d|sudoers\.d)` appears in `debian/postinst` but does not appear in `debian/postrm`
- File globs: `debian/postinst`, `debian/postrm`
- Source: https://lintian.debian.org/tags/maintainer-script-without-set-e.html

### RPM `%files` granting `%attr(0755,root,root)` to data or configuration scripts — CWE-732

- Why: An RPM `%files` directive that assigns `%attr(0755, root, root)` to shell scripts, configuration generators, or data files that should be read-only (`0644`) grants world-execute permission unnecessarily. Any user on the system can execute those files directly, and if they are later modified by a privileged installer step they become a TOCTOU injection surface. The execute bit should be set only on binaries that are explicitly intended to be invoked directly by users or by other programs. Lintian's equivalent is `non-standard-file-perm`; CWE-732 (Incorrect Permission Assignment for Critical Resource) applies.
- Grep: `%attr\(0?755\s*,\s*root\s*,\s*root\)` on lines that reference `.sh`, `.conf`, `.cfg`, `.d/`, `.yaml`, or `.json` files
- File globs: `**/*.spec`
- Source: https://lintian.debian.org/tags/non-standard-file-perm.html

## Secure patterns

Minimal `debian/postinst` with `set -e`, a `#DEBHELPER#` token, and explicit rollback logic on failure:

```sh
#!/bin/sh
set -e

case "$1" in
    configure)
        # Create the service account if it does not already exist.
        if ! getent passwd myapp > /dev/null 2>&1; then
            adduser --system --group --no-create-home --shell /usr/sbin/nologin myapp
        fi

        # Set ownership of the application state directory.
        if [ -d /var/lib/myapp ]; then
            chown myapp:myapp /var/lib/myapp
            chmod 0750 /var/lib/myapp
        fi
        ;;

    abort-upgrade|abort-remove|abort-deconfigure)
        # dpkg calls this script with these arguments when a previous
        # upgrade or removal failed; no additional rollback is required
        # beyond what dpkg itself handles.
        ;;

    *)
        echo "postinst called with unknown argument '$1'" >&2
        exit 1
        ;;
esac

# Let debhelper handle service activation, trigger processing, and ldconfig.
#DEBHELPER#

exit 0
```

The `set -e` on the second line ensures dpkg sees any non-zero exit immediately. The `#DEBHELPER#` token is expanded by `dh_installdeb` at build time to inject generated helper fragments (service activation, ldconfig, etc.); omitting it causes Lintian to raise `missing-debhelper-token`. The `case` fall-through for `abort-*` arguments is required by Debian Policy §6.5 to allow rollback calls to succeed.

Source: https://lintian.debian.org/tags/maintainer-script-without-set-e.html

RPM `.spec` `%post` scriptlet that uses only system-provided binaries, performs no network fetches, and emits a clear failure message:

```spec
%post
set -e

# Reload systemd if it is running (PID 1 is systemd in most modern distros).
if [ $1 -eq 1 ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Enable and start the service on first install only.
if [ $1 -eq 1 ]; then
    systemctl enable --now myapp.service || {
        echo "ERROR: Failed to enable myapp.service. Check 'systemctl status myapp.service'." >&2
        exit 1
    }
fi
```

No network calls, no piped interpreters. The `|| { echo ...; exit 1; }` pattern emits a human-readable error message and propagates failure to rpm. The `$1 -eq 1` guard restricts the enable-and-start logic to first-time installs; upgrades (`$1 -ge 2`) leave the running service to be restarted by the package manager's own restart hook.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

## Fix recipes

### Recipe: Add `set -e` and `#DEBHELPER#` to a bare `postinst` — addresses CWE-390

**Before (dangerous):**

```sh
#!/bin/sh

adduser --system --group myapp
chown myapp:myapp /var/lib/myapp
```

**After (safe):**

```sh
#!/bin/sh
set -e

case "$1" in
    configure)
        adduser --system --group --no-create-home myapp
        chown myapp:myapp /var/lib/myapp
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        echo "postinst called with unknown argument '$1'" >&2
        exit 1
        ;;
esac

#DEBHELPER#

exit 0
```

Three changes are required together: (1) `set -e` immediately after the shebang so any failing command aborts the script and dpkg sees a non-zero exit; (2) a `case` block that dispatches on `$1` so the script handles all dpkg-defined argument values correctly (Policy §6.5); (3) the `#DEBHELPER#` token so debhelper-generated fragments — service activation, trigger processing, `ldconfig` calls — are injected at build time rather than silently absent.

Source: https://lintian.debian.org/tags/maintainer-script-without-set-e.html

### Recipe: Replace `curl | bash` with a hash-verified local installation — addresses CWE-494

**Before (dangerous):**

```sh
#!/bin/sh
set -e

# Fetch and run a remote bootstrap script.
curl -fsSL https://install.example.com/bootstrap.sh | bash
```

**After (safe):**

```sh
#!/bin/sh
set -e

# The bootstrap helper is shipped as a package dependency and installed
# under /usr/lib/myapp/ at known path with a fixed version.
BOOTSTRAP=/usr/lib/myapp/bootstrap.sh
EXPECTED_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

if [ ! -f "$BOOTSTRAP" ]; then
    echo "ERROR: $BOOTSTRAP not found. Ensure myapp-helpers is installed." >&2
    exit 1
fi

actual=$(sha256sum "$BOOTSTRAP" | awk '{print $1}')
if [ "$actual" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: Integrity check failed for $BOOTSTRAP (got $actual)." >&2
    exit 1
fi

sh "$BOOTSTRAP"
```

The correct fix is to ship the helper as a declared `Depends:` package entry (or as a file inside the same package) so it arrives via the signed apt/rpm transport rather than an uncontrolled HTTP fetch. The integrity check shown above is a belt-and-suspenders guard; the primary protection is the signed package transport itself. Never pipe a fetched resource directly to an interpreter regardless of whether the URL is HTTP or HTTPS.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### Recipe: Add `Vcs-Git`, `Vcs-Browser`, and `Homepage` fields to `debian/control` — addresses supply-chain provenance gap

**Before (dangerous):**

```
Source: myapp
Section: utils
Priority: optional
Maintainer: Example Maintainer <maintainer@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: myapp
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: My application
 A short description of the application.
```

**After (safe):**

```
Source: myapp
Section: utils
Priority: optional
Maintainer: Example Maintainer <maintainer@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://github.com/example/myapp
Vcs-Git: https://salsa.debian.org/example-team/myapp.git
Vcs-Browser: https://salsa.debian.org/example-team/myapp

Package: myapp
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: My application
 A short description of the application.
```

`Homepage:` points to the upstream project release page. `Vcs-Git:` and `Vcs-Browser:` point to the Debian packaging repository (typically on Salsa), not the upstream repository; this is the repository that contains `debian/` and from which the source package is built. Both fields belong in the `Source:` stanza, not in binary package stanzas. Lintian raises `no-homepage-field` and `missing-vcs-browser-field` (both at `warning` severity) when these fields are absent.

Source: https://lintian.debian.org/tags/no-homepage-field.html

## Version notes

- The `#DEBHELPER#` token in maintainer scripts requires `debhelper-compat (= 9)` or later; with compat level 13 (current recommended level as of Debian bookworm) `dh_installdeb` auto-generates the token insertion. If the compat level is below 9 the token must be present but debhelper may not inject any content into it — check the compat level in `debian/debhelper-compat` or `debian/compat`.
- RPM `%post` scriptlets using `set -e` require RPM 4.14 or later (Fedora 26+, RHEL 8+, SLES 15+). On older RPM versions `set -e` is silently honoured by the system shell but the exit-code propagation to rpm may differ; test on the minimum target RPM version.
- Lintian tag names and severities are versioned; tags listed here are current against Lintian 2.117.x (Debian bookworm). Tag names may change in future Lintian releases — use `lintian --list-tags` against the target Debian version to confirm current tag names.
- The `Vcs-Git:` field URI scheme should be `https://` to avoid Lintian raising `vcs-field-uses-insecure-uri`; `git://` and `svn://` URIs trigger that warning.

## Common false positives

- `chmod\s+[0-7]*4[0-7]{3}` matching a `chmod 0755` (where the leading digit is `0`, not `4`) — octal literals with a leading zero are permissions only; the setuid bit is the octal digit `4` in the thousands position (`04755`), not a leading zero. Confirm the match is truly `4xxx` before flagging.
- `(curl|wget).*http://` inside a comment line or an `echo` statement — grep matches inside comments or printed strings do not indicate live network fetches; triage by confirming the line is executable and not prefixed with `#` or part of a heredoc example.
- `override_dh_auto_test:` in `debian/rules` when followed by a comment explaining a legitimate reason (cross-compilation target, test suite requires a running daemon, upstream tests are broken on the build architecture) — this is acceptable if the rationale is documented; flag only when the override body is a bare `true` or `:` with no comment.
- `(cron\.d|sudoers\.d)` appearing in `debian/postinst` when the file is created via `dh_installcron` or `dh_installsudo` debhelper commands in `debian/rules` — in that case `dh_installcron` and `dh_installsudo` automatically generate the paired `postrm` removal logic; check `debian/rules` for these helper invocations before raising CWE-459.
- `%attr(0755, root, root)` on files whose extension is `.sh` but which serve as compiled wrapper launchers (generated by build systems like Libtool) — these are intentionally executable; check whether the file is a genuine shell script or a libtool wrapper before flagging.
