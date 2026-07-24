#!/usr/bin/env bash
# script-versions.sh — verifies versions.py against the primary sources it cites:
# PEP 440 ordering, SemVer §11 precedence, dpkg §5.6.12 (incl. the tilde rule),
# the OSV event algorithm (introduced/fixed/last_affected/limit, versions[] OR
# ranges[], GIT unevaluable), min-safe computation, and the honesty guards that
# make UNKNOWN — never SAFE — the answer when we cannot actually check.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

python3 - <<'PY'
import sys
sys.path.insert(0, "scripts")
from secaudit.versions import (compare, package_status, min_safe_version,
                               is_affected, included_in_range, describe_ranges)

fails = []
def check(cond, label):
    print(("  OK   " if cond else "  FAIL ") + label)
    if not cond:
        fails.append(label)

def ordered(seq, scheme, label):
    ok = True
    for a, b in zip(seq, seq[1:]):
        c, exact = compare(a, b, scheme)
        if c != -1 or not exact:
            ok = False
            print("        %r vs %r -> %r exact=%s" % (a, b, c, exact))
    check(ok, "%s: %s" % (label, " < ".join(seq)))

print("=== PEP 440 (packaging.python.org) ===")
ordered(["1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.1"],
        "pep440", "dev < a < b < rc < final < post")
ordered(["1!0.1", "1!1.0", "2!0.1"], "pep440", "epoch dominates")
ordered(["1.9", "1.10", "1.100"], "pep440", "release segments compare numerically")
check(compare("v1.0", "1.0", "pep440") == (0, True), "leading 'v' normalized away")
check(compare("1.0", "1.0.0", "pep440") == (0, True), "trailing zeros insignificant")
check(compare("1.0-1", "1.0.post1", "pep440")[0] == 0, "implicit post-release form")
check(compare("1.0ALPHA1", "1.0a1", "pep440")[0] == 0, "case + spelling normalization")

print("=== SemVer 2.0.0 §11 (semver.org) ===")
ordered(["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
         "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"],
        "semver", "pre-release precedence chain")
ordered(["1.0.0", "2.0.0", "2.1.0", "2.1.1"], "semver", "core numeric")
check(compare("1.0.0+build1", "1.0.0+build2", "semver") == (0, True),
      "build metadata ignored in precedence")
check(compare("1.0.0-alpha.1", "1.0.0-alpha", "semver")[0] == 1,
      "larger field set wins when preceding identifiers equal")
check(compare("1.0.0-1", "1.0.0-alpha", "semver")[0] == -1,
      "numeric identifiers rank below alphanumeric")

print("=== Go / RubyGems / Maven ===")
ordered(["v1.9.0", "v1.10.0"], "gosemver", "go module versions")
check(compare("v2.0.0+incompatible", "v2.0.0", "gosemver")[0] == 0,
      "+incompatible stripped")
ordered(["v0.0.0-20230124172434-306776ec8161", "v0.1.0"], "gosemver", "pseudo-version")
ordered(["1.0.0.pre", "1.0.0"], "rubygems", "rubygems letter segment is a pre-release")
ordered(["1.0-alpha", "1.0-beta", "1.0-rc", "1.0"], "maven", "maven qualifiers")

print("=== Debian §5.6.12 (incl. the tilde rule) ===")
ordered(["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"], "debian",
        "'a tilde sorts before anything, even the end of a part'")
ordered(["1:1.0", "1:2.0", "2:0.1"], "debian", "epoch compared numerically first")
ordered(["7.88.1-10", "7.88.1-10+deb12u5"], "debian", "revision comparison")
ordered(["1.0-1", "1.0-2", "1.1-1"], "debian", "upstream before revision")
check(compare("3.1.4-r5", "3.1.4-r6", "apk")[0] == -1, "apk release suffix")

print("=== OSV events: introduced / fixed / last_affected / limit ===")
rng = {"type": "ECOSYSTEM", "events": [{"introduced": "2.2"}, {"fixed": "2.2.28"}]}
check(included_in_range("2.2.0", rng, "pep440") == (True, True), "inside [2.2, 2.2.28)")
check(included_in_range("2.1.9", rng, "pep440")[0] is False, "below introduced")
check(included_in_range("2.2.28", rng, "pep440")[0] is False, "at fixed -> not affected")
r0 = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.19"}]}
check(included_in_range("0.1", r0, "pep440")[0] is True, "introduced:'0' sorts before all")
la = {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.9"}]}
check(included_in_range("1.9", la, "pep440")[0] is True, "at last_affected -> affected")
check(included_in_range("1.10", la, "pep440")[0] is False, "above last_affected -> clear")
lim = {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"limit": "2.0"}]}
check(included_in_range("2.5", lim, "pep440")[0] is False, "limit bounds the range")
unsorted_rng = {"type": "ECOSYSTEM", "events": [{"fixed": "2.2.28"}, {"introduced": "2.2"}]}
check(included_in_range("2.2.0", unsorted_rng, "pep440")[0] is True,
      "events sorted by the scheme, not by input order")

print("=== OSV: a version is affected if in versions[] OR IncludedInRanges ===")
adv_v = [{"id": "Y", "affected": [{"versions": ["1.2.3"]}]}]
check(package_status("1.2.3", adv_v, "PyPI")["status"] == "VULNERABLE",
      "enumerated versions[] match")
check(package_status("1.2.4", adv_v, "PyPI")["status"] == "SAFE",
      "not enumerated, no ranges -> clear")
both = [{"id": "Z", "affected": [{"versions": ["9.9.9"],
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}]}]}]}]
check(package_status("9.9.9", both, "PyPI")["status"] == "VULNERABLE",
      "versions[] hit even when outside every range (OR, not precedence)")
check(package_status("1.2", both, "PyPI")["status"] == "VULNERABLE", "range hit")

print("=== GIT ranges are not evaluable -> UNKNOWN, never SAFE ===")
git = [{"id": "G", "affected": [{"ranges": [{"type": "GIT",
        "events": [{"introduced": "abc123"}]}]}]}]
check(package_status("1.0.0", git, "PyPI")["status"] == "UNKNOWN",
      "commit-hash ordering needs the repo -> no safety claim")

print("=== minimum safe version ===")
django = [
 {"id": "CVE-A", "affected": [{"ranges": [
    {"type": "ECOSYSTEM", "events": [{"introduced": "2.2"}, {"fixed": "2.2.28"}]},
    {"type": "ECOSYSTEM", "events": [{"introduced": "3.2"}, {"fixed": "3.2.13"}]}]}]},
 {"id": "CVE-B", "affected": [{"ranges": [
    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.19"}]}]}]},
]
st = package_status("2.2.0", django, "PyPI")
check(st["status"] == "VULNERABLE", "django 2.2.0 vulnerable")
check(st["min_safe"] == "3.2.19",
      "min_safe clears EVERY advisory (2.2.28 would still be hit by CVE-B)")
check(st["min_safe_same_major"] is None,
      "no in-major fix exists -> null, not a fabricated one")
check(sorted(st["fixed_versions"]) == ["2.2.28", "3.2.13", "3.2.19"], "fixed versions listed")
check(any(">=2.2" in r for r in st["ranges"]), "ranges rendered")
st2 = package_status("3.2.13", django, "PyPI")
check(st2["min_safe_same_major"] == "3.2.19", "in-major upgrade offered when one exists")
check(package_status("3.2.19", django, "PyPI")["status"] == "SAFE", "fixed version is clear")
check(package_status("4.0", django, "PyPI")["status"] == "SAFE", "later major is clear")

ms, _, _ = min_safe_version("1.0", [{"id": "N", "affected": [{"ranges": [
    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "9.9"}]}]}]}], "PyPI")
check(ms is None, "no advisory-named fix -> min_safe is null, never invented")

print("=== honesty guards: UNKNOWN, never SAFE ===")
check(package_status(">=2.0", django, "PyPI", resolution="declared")["status"] == "UNKNOWN",
      "a declared RANGE cannot be evaluated")
check(package_status("1.0", [], "PyPI", resolution="unparsed")["status"] == "UNKNOWN",
      "an unparsed manifest cannot be evaluated")
check(package_status("2.2.0", [], "PyPI", feeds_ok=False)["status"] == "UNKNOWN",
      "feeds offline")
check(package_status("1.0", [], "TotallyUnknownEcosystem")["status"] == "UNKNOWN",
      "no exact comparator for the ecosystem")
st_ok = package_status("5.0", django, "PyPI")
check(st_ok["status"] == "SAFE" and "consulted feeds" in st_ok["reason"],
      "a SAFE verdict is qualified by 'the consulted feeds', not absolute")
check(package_status("1.0", [], "PyPI")["status"] == "SAFE",
      "zero advisories on an exact version is a legitimate SAFE")

print()
if fails:
    print("script-versions: FAILED (%d)" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("script-versions: OK")
PY
