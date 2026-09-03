#!/usr/bin/env bash
# make-deb.sh — rebuild build/vulnerableapp_0.1.0_all.deb from this fixture.
# lintian analyses BUILT packages only (it cannot open a source tree), so the
# linux lane's lintian coverage needs a real .deb in the fixture. This builds
# one with dpkg-deb from the fixture's own postinst; the defects lintian is
# meant to catch are deliberate (setuid binary, postinst without set -e,
# cron.d file not a conffile, files under /usr/local, no copyright/changelog).
# Permissions are normalised first so the report shows the intentional
# defects rather than the builder's umask.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fx="$(cd "$here/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pkg/DEBIAN" "$tmp/pkg/usr/local/bin" "$tmp/pkg/etc/cron.d"
cat > "$tmp/pkg/DEBIAN/control" <<'CTL'
Package: vulnerableapp
Version: 0.1.0
Architecture: all
Maintainer: Fixture Author <fixture@example.com>
Section: misc
Priority: optional
Description: Intentionally vulnerable fixture package
 Exists solely to exercise the sec-audit Linux lane.
CTL
cp "$fx/debian/postinst" "$tmp/pkg/DEBIAN/postinst"
printf '#!/bin/sh\necho vulnerableapp\n' > "$tmp/pkg/usr/local/bin/vulnerableapp"
printf '0 * * * * root /usr/local/bin/vulnerableapp --cron\n' > "$tmp/pkg/etc/cron.d/vulnerableapp"
find "$tmp/pkg" -type d -exec chmod 0755 {} +
find "$tmp/pkg" -type f -exec chmod 0644 {} +
chmod 0755 "$tmp/pkg/DEBIAN/postinst"
chmod 4755 "$tmp/pkg/usr/local/bin/vulnerableapp"     # CWE-250: setuid
dpkg-deb --root-owner-group --build "$tmp/pkg" "$here/vulnerableapp_0.1.0_all.deb"
