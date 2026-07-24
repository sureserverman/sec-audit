#!/usr/bin/env bash
# script-depinv.sh — verifies depinv.py (lockfile-first package extraction across
# every supported ecosystem) and programs.py (base images, OS pins, CI actions,
# toolchains), including the two honesty rules: a range is never resolved into a
# version, and a floating tag is never reported as one.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
F=tests/fixtures/depinv
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

pkgs() {  # fixture dir -> "eco|name|version|resolution" lines
python3 scripts/secaudit/depinv.py "$F/$1" 2>/dev/null | python3 -c "
import json,sys
for e in json.load(sys.stdin)['ecosystems']:
    for p in e['packages']:
        print('%s|%s|%s|%s' % (e['ecosystem'], p['name'], p['version'], p['resolution']))
"
}
has() { grep -qx "$2" <<<"$1" || { echo "FAIL: expected [$2] in:"; echo "$1"; exit 1; }; }

echo "=== PyPI: poetry.lock wins over the requirements.txt beside it ==="
o=$(pkgs pypi)
has "$o" 'PyPI|django|2.2.0|lockfile'
has "$o" 'PyPI|urllib3|2.2.3|lockfile'
grep -q 'django|>=2.0' <<<"$o" && { echo "FAIL: declared range preferred over lockfile"; exit 1; }
echo "  lockfile precedence: OK"

echo "=== PyPI requirements: == is exact (pinned), a RANGE is kept verbatim ==="
o=$(pkgs pypi-req)
has "$o" 'PyPI|requests|2.31.0|pinned'
has "$o" 'PyPI|flask|>=2.0,<3.0|declared'      # range preserved, NOT resolved
has "$o" 'PyPI|bare-package|None|declared'
has "$o" 'PyPI|package|1.2.3|pinned'           # extras stripped from the name
has "$o" 'PyPI|conditional|4.0|pinned'         # env marker stripped
echo "  pins vs ranges: OK"

echo "=== npm: lockfile v3, incl. a transitive marked non-direct ==="
o=$(pkgs npm)
has "$o" 'npm|lodash|4.17.20|lockfile'
has "$o" 'npm|express|4.18.2|lockfile'
has "$o" 'npm|debug|2.6.9|lockfile'
python3 scripts/secaudit/depinv.py "$F/npm" 2>/dev/null | python3 -c "
import json,sys
pk = {p['name']: p for e in json.load(sys.stdin)['ecosystems'] for p in e['packages']}
assert pk['debug']['direct'] is False, 'nested dep should not be direct'
assert pk['lodash']['direct'] is True
print('  transitive detection: OK')
"

echo "=== npm: yarn (classic) and pnpm forms, incl. @scope packages ==="
o=$(pkgs npm-yarn);  has "$o" 'npm|lodash|4.17.21|lockfile'; has "$o" 'npm|@scope/pkg|1.2.3|lockfile'
o=$(pkgs npm-pnpm);  has "$o" 'npm|lodash|4.17.21|lockfile'; has "$o" 'npm|@scope/pkg|1.2.3|lockfile'
echo "  yarn + pnpm: OK"

echo "=== remaining ecosystems ==="
o=$(pkgs cargo);     has "$o" 'crates.io|serde|1.0.197|lockfile'; has "$o" 'crates.io|time|0.1.44|lockfile'
o=$(pkgs go);        has "$o" 'Go|github.com/gin-gonic/gin|v1.9.0|lockfile'; has "$o" 'Go|golang.org/x/net|v0.7.0|lockfile'
o=$(pkgs ruby);      has "$o" 'RubyGems|rails|7.0.4|lockfile'; has "$o" 'RubyGems|nokogiri|1.13.9|lockfile'
o=$(pkgs php);       has "$o" 'Packagist|monolog/monolog|2.8.0|lockfile'
o=$(pkgs maven);     has "$o" 'Maven|com.squareup.okhttp3:okhttp|4.9.0|lockfile'
o=$(pkgs nuget);     has "$o" 'NuGet|Newtonsoft.Json|13.0.1|lockfile'
o=$(pkgs cocoapods); has "$o" 'CocoaPods|Alamofire|5.6.4|lockfile'
o=$(pkgs swiftpm);   has "$o" 'SwiftPM|swift-nio|2.40.0|lockfile'
echo "  cargo/go/ruby/php/maven/nuget/cocoapods/swiftpm: OK"

echo "=== go.sum dedupes the /go.mod twin rather than double-counting ==="
[ "$(pkgs go | grep -c 'gin-gonic')" = 1 ] || { echo "FAIL: go.sum duplicate"; exit 1; }
echo "  go.sum dedupe: OK"

echo "=== Gemfile.lock: 6-space dependency CONSTRAINTS are not versions ==="
pkgs ruby | grep -q 'actionpack' && { echo "FAIL: a nested constraint was read as a package"; exit 1; }
echo "  nested constraints excluded: OK"

echo "=== a malformed lockfile degrades to unparsed, never aborts ==="
mkdir -p "$scratch/broken"; printf '{"packages": [ THIS IS NOT JSON\n' > "$scratch/broken/composer.lock"
out=$(python3 scripts/secaudit/depinv.py "$scratch/broken" 2>/dev/null)
echo "$out" | python3 -c "
import json,sys
d = json.load(sys.stdin)
eco = [e for e in d['ecosystems'] if e['ecosystem'] == 'Packagist']
assert eco and eco[0].get('resolution') == 'unparsed', d
assert any('unparsed' in n for n in d['notes']), d['notes']
print('  malformed lockfile: reported as unparsed, run continues OK')
"

echo "=== an empty tree yields an empty inventory, not an error ==="
mkdir -p "$scratch/empty"
python3 scripts/secaudit/depinv.py "$scratch/empty" >/dev/null 2>&1 || { echo "FAIL: empty tree errored"; exit 1; }
echo "  empty tree: OK"

# ---------------------------------------------------------------- programs --
prog() { python3 scripts/secaudit/programs.py "$F/programs" 2>/dev/null; }

echo "=== base images: a pinned tag is a version, a FLOATING tag is not ==="
prog | python3 -c "
import json,sys
p = {e['name']: e for e in json.load(sys.stdin)['programs'] if e['kind'] == 'base-image'}
assert p['nginx']['version'] == '1.25.2' and p['nginx']['pinned'], p['nginx']
n = p['node']
assert n['version'] is None and n['pinned'] is False, n
assert 'floating tag' in n['note'], n
d = p['debian']
assert d['version'] is None and d['ecosystem'] == 'Debian', d
a = p['alpine']
assert a['pinned'] is True and 'digest-pinned' in a['note'], a
assert a['version'] is None, 'a digest-pinned image with no tag must not invent \"latest\": %r' % a
print('  pinned vs floating vs digest: OK')
"

echo "=== OS package pins map to Debian / Alpine ecosystems ==="
prog | python3 -c "
import json,sys
p = {e['name']: e for e in json.load(sys.stdin)['programs'] if e['kind'] == 'os-package'}
assert p['curl']['version'] == '7.88.1-10+deb12u5' and p['curl']['ecosystem'] == 'Debian', p
assert p['openssl']['version'] == '3.1.4-r5' and p['openssl']['ecosystem'] == 'Alpine', p
assert 'git' not in p, 'an unpinned apt package must not be reported as a version'
print('  apt/apk pins: OK')
"

echo "=== CI actions: SHA pin vs moving tag ==="
prog | python3 -c "
import json,sys
p = {e['name']: e for e in json.load(sys.stdin)['programs'] if e['kind'] == 'ci-action'}
assert p['actions/checkout']['pinned'] and 'SHA-pinned' in p['actions/checkout']['note'], p
mv = p['actions/setup-node']
assert mv['version'] is None and mv['pinned'] is False and 'repointed' in mv['note'], mv
assert p['docker/build-push-action']['version'] == '6.5.0', p
print('  action pinning: OK')
"

echo "=== toolchains: .nvmrc / .tool-versions / rust-toolchain / go directive ==="
prog | python3 -c "
import json,sys
t = {(e['name'], e['source']): e for e in json.load(sys.stdin)['programs'] if e['kind'] == 'toolchain'}
got = {k[0]: v['version'] for k, v in t.items()}
for name, ver in (('node','18.17.1'), ('nodejs','20.11.0'), ('python','3.12.1'),
                  ('rust','1.76.0'), ('go','1.21.5')):
    assert got.get(name) == ver, (name, got)
# no OSV ecosystem for a bare toolchain pin -> must be null so it renders UNKNOWN
assert all(v['ecosystem'] is None for v in t.values()), t
print('  toolchains: OK (ecosystem null -> renders UNKNOWN, never implied safe)')
"

echo "=== depinv embeds programs in its output ==="
python3 scripts/secaudit/depinv.py "$F/programs" 2>/dev/null | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert d['programs'], 'depinv did not embed programs'
print('  depinv -> programs wiring: OK')
"

echo ""
echo "script-depinv: OK"
