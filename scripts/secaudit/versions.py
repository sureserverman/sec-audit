#!/usr/bin/env python3
"""Version comparison + OSV range evaluation + minimum-safe-version (§4/§6).

This is where a wrong answer becomes a false "your version is safe", so every
rule below comes from a primary source, and anything the implementation cannot
decide exactly is reported UNKNOWN rather than guessed.

Sources consulted (2026-07-24):
  * OSV schema — ossf.github.io/osv-schema. Event types `introduced` / `fixed` /
    `last_affected` / `limit`, exactly one per event object; `introduced: "0"`
    "sorts before any other version"; an absent `limit` implies `{"limit": "*"}`;
    an entry may carry `last_affected` OR `fixed`, "but not both". A version is
    affected if it is in `versions[]` **OR** IncludedInRanges — the two are ORed,
    neither takes precedence. Range types: SEMVER (semver ordering), ECOSYSTEM
    (strings interpreted by the ecosystem's own rules), GIT (commit hashes,
    orderable only with the repo — so NOT evaluable here).
  * PEP 440 — packaging.python.org. epoch!release[pre][post][dev][+local];
    ordering .devN < aN < bN < rcN < final < .postN; numeric segments compare
    numerically; normalization lowercases, strips a leading `v`, drops leading
    zeros, and maps alpha/beta/c/pre/preview → a/b/rc.
  * SemVer 2.0.0 §11 — semver.org. Core compared numerically; a pre-release has
    LOWER precedence than its normal version; identifiers compared left to right,
    numeric numerically, alphanumeric in ASCII order, numeric < non-numeric, and
    a larger set of fields wins when all preceding are equal. Build metadata is
    ignored entirely.
  * Debian Policy §5.6.12 — debian.org. `[epoch:]upstream[-revision]`; epoch
    numeric; upstream/revision compared in alternating non-digit/digit chunks,
    where letters sort before non-letters and "a tilde sorts before anything,
    even the end of a part"; an empty digit chunk counts as zero.

Exactness is tracked, not assumed: `compare()` returns (ordering, exact) and any
comparison routed through the `generic` fallback is exact=False. A package whose
comparison is inexact can never be reported SAFE — only UNKNOWN.
"""
import re

# ---------------------------------------------------------------- schemes --
ECOSYSTEM_SCHEME = {
    "PyPI": "pep440",
    "npm": "semver",
    "crates.io": "semver",
    "Go": "gosemver",
    "RubyGems": "rubygems",
    "Packagist": "semver",
    "Maven": "maven",
    "NuGet": "semver",
    "CocoaPods": "semver",
    "SwiftPM": "semver",
    "GitHub Actions": "semver",
    "Debian": "debian",
    "Ubuntu": "debian",
    "Alpine": "apk",
}
EXACT_SCHEMES = {"pep440", "semver", "gosemver", "rubygems", "maven", "debian", "apk"}


def scheme_for(ecosystem, range_type=None):
    if range_type == "SEMVER":
        return "semver"
    return ECOSYSTEM_SCHEME.get(ecosystem or "", "generic")


# ----------------------------------------------------------------- PEP 440 --
_PEP440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|c|pre|preview|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?P<post>(?:-(?P<post_n1>\d+))|(?:[-_.]?(?:post|rev|r)[-_.]?(?P<post_n>\d+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE)
_PRE_MAP = {"alpha": "a", "a": "a", "beta": "b", "b": "b",
            "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}
_PRE_ORDER = {"a": 0, "b": 1, "rc": 2}


def parse_pep440(v):
    m = _PEP440.match(str(v or ""))
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = tuple(int(x) for x in m.group("release").split("."))
    if m.group("pre_l"):
        pre = (_PRE_ORDER[_PRE_MAP[m.group("pre_l").lower()]], int(m.group("pre_n") or 0))
    else:
        pre = None
    post = None
    if m.group("post"):
        post = int(m.group("post_n1") or m.group("post_n") or 0)
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None
    local = m.group("local")
    return epoch, release, pre, post, dev, local


def _pep440_key(p):
    epoch, release, pre, post, dev, local = p
    # Trailing zeros are insignificant: 1.0 == 1.0.0
    rel = list(release)
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    # Ordering: .devN < aN < bN < rcN < final < .postN
    if pre is not None:
        stage = (0, pre[0], pre[1])
    elif dev is not None and post is None:
        stage = (-1, 0, dev)          # a pure .devN precedes any pre-release
    elif post is not None:
        stage = (2, post, dev if dev is not None else -1)
    else:
        stage = (1, 0, 0)
    if pre is not None and dev is not None:
        stage = (0, pre[0], pre[1] - 0.5)   # 1.0a1.dev1 < 1.0a1
    local_key = ()
    if local:
        local_key = tuple((1, int(s)) if s.isdigit() else (0, s.lower())
                          for s in re.split(r"[-_.]", local))
    return (epoch, tuple(rel), stage, local_key)


# ------------------------------------------------------------------ SemVer --
_SEMVER = re.compile(r"^\s*v?(?P<core>\d+(?:\.\d+){0,2})"
                     r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?"
                     r"(?:\+(?P<build>[0-9A-Za-z.\-]+))?\s*$")


def parse_semver(v):
    m = _SEMVER.match(str(v or ""))
    if not m:
        return None
    core = [int(x) for x in m.group("core").split(".")]
    while len(core) < 3:
        core.append(0)
    return tuple(core), m.group("pre")


def _semver_key(p):
    core, pre = p
    if pre is None:
        # "a pre-release version has lower precedence than a normal version"
        return (core, (1,), ())
    ids = []
    for part in pre.split("."):
        if part.isdigit():
            ids.append((0, int(part), ""))       # numeric < non-numeric
        else:
            ids.append((1, 0, part))             # ASCII order
    # Build metadata is ignored entirely (§11).
    return (core, (0,), tuple(ids))


# ----------------------------------------------------- Go / RubyGems / Maven --
def parse_gosemver(v):
    s = str(v or "").strip()
    s = re.sub(r"\+incompatible$", "", s)
    # A pseudo-version (v0.0.0-20230124172434-306776ec8161) is still semver-shaped.
    return parse_semver(s)


def parse_rubygems(v):
    s = str(v or "").strip()
    if not s or not re.match(r"^\d", s):
        return None
    segs = []
    for part in re.split(r"[.\-]", s):
        if part.isdigit():
            segs.append((1, int(part), ""))
        elif part:
            segs.append((0, 0, part.lower()))    # a letter segment is a pre-release
    return tuple(segs)


def parse_maven(v):
    s = str(v or "").strip().lower()
    if not s:
        return None
    segs = []
    for part in re.split(r"[.\-_]", s):
        if part.isdigit():
            segs.append((1, int(part), ""))
        elif part:
            qual = {"alpha": -3, "beta": -2, "milestone": -2, "rc": -1, "cr": -1,
                    "snapshot": -1, "ga": 0, "final": 0, "sp": 1}.get(part)
            segs.append((0, qual if qual is not None else 0, part))
    return tuple(segs)


# ------------------------------------------------------------- Debian / apk --
def _dpkg_order(ch):
    """Letters before non-letters; '~' before everything, even end of part."""
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _dpkg_cmp_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit run
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
            if first_diff > 10000:
                break
            first_diff += 1
        # digit run — an empty digit chunk counts as zero
        si, sj = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        na = int(a[si:i] or 0)
        nb = int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def parse_debian(v):
    s = str(v or "").strip()
    if not s:
        return None
    epoch = 0
    if ":" in s:
        head, _, rest = s.partition(":")
        if head.isdigit():
            epoch, s = int(head), rest
    if "-" in s:
        upstream, _, revision = s.rpartition("-")
    else:
        upstream, revision = s, ""
    return epoch, upstream, revision


def _cmp_debian(a, b):
    ea, ua, ra = a
    eb, ub, rb = b
    if ea != eb:
        return -1 if ea < eb else 1
    c = _dpkg_cmp_part(ua, ub)
    if c:
        return c
    return _dpkg_cmp_part(ra, rb)


def parse_apk(v):
    # apk versions are close enough to the dpkg chunking for ordering purposes
    # (numeric runs separated by non-numeric); the `-rN` release suffix behaves
    # like a Debian revision.
    return parse_debian(v)


# ----------------------------------------------------------------- generic --
def parse_generic(v):
    s = str(v or "").strip()
    if not s:
        return None
    return tuple((1, int(p), "") if p.isdigit() else (0, 0, p.lower())
                 for p in re.split(r"[.\-_+~]", s) if p != "")


PARSERS = {
    "pep440": (parse_pep440, _pep440_key),
    "semver": (parse_semver, _semver_key),
    "gosemver": (parse_gosemver, _semver_key),
    "rubygems": (parse_rubygems, lambda p: p),
    "maven": (parse_maven, lambda p: p),
    "generic": (parse_generic, lambda p: p),
}

# Schemes whose key is a flat tuple of (kind, number, text) segments. These need
# PADDED comparison, not plain tuple comparison: Python makes a prefix sort
# before its extension, so `1.0.0` would come out BELOW `1.0.0.pre` — backwards,
# since a trailing qualifier segment marks a pre-release. Padding the shorter
# side with a numeric-zero segment makes the qualifier (kind 0) lose to the
# implied zero (kind 1), which is the ordering both RubyGems and Maven specify.
_SEGMENT_SCHEMES = {"rubygems", "maven", "generic"}
_PAD = (1, 0, "")


def _padded_cmp(ka, kb):
    n = max(len(ka), len(kb))
    for i in range(n):
        a = ka[i] if i < len(ka) else _PAD
        b = kb[i] if i < len(kb) else _PAD
        if a == b:
            continue
        return -1 if a < b else 1
    return 0


def compare(a, b, scheme):
    """Return (ordering, exact): ordering is -1/0/1, or None if uncomparable.

    `exact` is False whenever the answer came from the generic fallback — the
    caller must never turn an inexact comparison into a SAFE verdict."""
    if a is None or b is None:
        return None, False
    if scheme in ("debian", "apk"):
        pa, pb = parse_debian(a), parse_debian(b)
        if pa is None or pb is None:
            return None, False
        return _cmp_debian(pa, pb), True
    parser, keyer = PARSERS.get(scheme, PARSERS["generic"])
    pa, pb = parser(a), parser(b)
    exact = scheme in EXACT_SCHEMES
    if pa is None or pb is None:
        # Fall back to generic so an odd version string still orders somehow,
        # but the result is explicitly inexact.
        pa, pb = parse_generic(a), parse_generic(b)
        if pa is None or pb is None:
            return None, False
        ka, kb = pa, pb
        return (0 if ka == kb else (-1 if ka < kb else 1)), False
    ka, kb = keyer(pa), keyer(pb)
    try:
        if scheme in _SEGMENT_SCHEMES:
            return _padded_cmp(ka, kb), exact
        return (0 if ka == kb else (-1 if ka < kb else 1)), exact
    except TypeError:
        return None, False


# --------------------------------------------------- OSV range evaluation --
def _event_version(evt):
    for k in ("introduced", "fixed", "last_affected", "limit"):
        if k in evt:
            return k, evt[k]
    return None, None


def included_in_range(version, rng, scheme):
    """OSV IncludedInRange. Returns (affected, exact).

    Events are applied in sorted order; `introduced: "0"` sorts before every
    version, and an absent `limit` is an implicit `*` (no upper bound)."""
    # `or "ECOSYSTEM"` rather than a .get() default: a range carrying an explicit
    # null type (OSV entries in the wild omit it, and our own projection writes
    # the key unconditionally) must fall back too, not crash.
    rtype = ((rng or {}).get("type") or "ECOSYSTEM").upper()
    if rtype == "GIT":
        # Commit-hash ordering needs the repository; not evaluable here.
        return False, False
    sch = "semver" if rtype == "SEMVER" else scheme
    events = list((rng or {}).get("events") or [])
    if not events:
        return False, True

    def sort_key(evt):
        kind, val = _event_version(evt)
        if kind == "introduced" and val == "0":
            return (-1, 0)
        if val in (None, "*"):
            return (2, 0)
        c, _ = compare(val, version, sch)
        return (0, 0 if c is None else c)

    # Sort by the event's own version so out-of-order events still evaluate
    # correctly (the spec says events SHOULD be sorted, not MUST).
    def evt_cmp_key(evt):
        kind, val = _event_version(evt)
        if kind == "introduced" and val == "0":
            return (0, "")
        if val == "*":
            return (2, "")
        return (1, val or "")

    exact = True
    affected = False
    ordered = sorted(events, key=evt_cmp_key)
    # A stable sort on raw strings is not a version sort; re-sort pairwise with
    # the scheme comparator so 1.10 follows 1.9.
    for i in range(len(ordered)):
        for j in range(len(ordered) - 1 - i):
            _, va = _event_version(ordered[j])
            _, vb = _event_version(ordered[j + 1])
            if va == "0" or vb == "*":
                continue
            if vb == "0" or va == "*":
                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]
                continue
            c, ok = compare(va, vb, sch)
            if c is not None and c > 0:
                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]

    for evt in ordered:
        kind, val = _event_version(evt)
        if kind is None:
            continue
        if kind == "introduced":
            if val == "0":
                affected = True
                continue
            c, ok = compare(version, val, sch)
            exact = exact and ok
            if c is None:
                return False, False
            if c >= 0:
                affected = True
        elif kind == "fixed":
            c, ok = compare(version, val, sch)
            exact = exact and ok
            if c is None:
                return False, False
            if c >= 0:
                affected = False
        elif kind == "last_affected":
            c, ok = compare(version, val, sch)
            exact = exact and ok
            if c is None:
                return False, False
            if c > 0:
                affected = False
        elif kind == "limit":
            if val == "*":
                continue
            c, ok = compare(version, val, sch)
            exact = exact and ok
            if c is None:
                return False, False
            if c >= 0:
                affected = False
    return affected, exact


def is_affected(version, affected_entry, ecosystem):
    """OSV: affected if the version is in `versions[]` OR IncludedInRanges.

    Per the schema these are ORed — neither takes precedence over the other."""
    scheme = scheme_for(ecosystem)
    versions = (affected_entry or {}).get("versions") or []
    if version in versions:
        return True, True                      # an exact string match is exact
    ranges = (affected_entry or {}).get("ranges") or []
    # A GIT range is orderable only with the repository, so it is skipped rather
    # than evaluated. Skipping does NOT make the entry inexact when a sibling
    # ECOSYSTEM/SEMVER range exists: OSV ranges are ORed, and PYSEC/GHSA
    # routinely attach a commit-hash range beside the version range for the same
    # vulnerability. Letting the GIT range taint exactness would make almost
    # every real package permanently UNKNOWN — the feature would answer nothing.
    evaluable = [r for r in ranges if ((r or {}).get("type") or "ECOSYSTEM").upper() != "GIT"]
    exact = True
    for rng in evaluable:
        hit, ok = included_in_range(version, rng, scheme)
        exact = exact and ok
        if hit:
            return True, exact
    if not versions and not evaluable:
        # GIT-only (or empty): genuinely nothing to evaluate -> never claim safe.
        return False, False
    return False, exact


def entries_for(affected_entries, ecosystem=None, name=None):
    """Keep only the `affected[]` entries describing THIS package.

    A single advisory routinely covers several packages — GHSA-6c3j-c64m-qhgq
    lists jQuery, jquery-rails, org.webjars.npm:jquery *and* Django. Without
    this filter, jquery-rails' fixed version (4.3.4) gets proposed as Django's
    safe upgrade: a real version, of the wrong package, presented as a security
    instruction. Entries carrying no package block are kept — an
    advisory-shaped-but-unlabelled entry is more likely ours than not, and
    keeping it errs toward reporting rather than clearing.
    """
    if not affected_entries:
        return []
    if name is None:
        return list(affected_entries)
    out = []
    for aff in affected_entries:
        # Two shapes reach here: raw OSV (`affected[].package.{name,ecosystem}`)
        # and cve_enricher's projection, which flattens those to the entry's own
        # `name`/`ecosystem`. Reading only one of them silently disables the
        # filter for the other — which is how a co-listed package's version got
        # proposed as a safe upgrade in the first place.
        pkg = (aff or {}).get("package") or {}
        pname = pkg.get("name") if pkg.get("name") is not None else (aff or {}).get("name")
        peco = pkg.get("ecosystem") if pkg.get("ecosystem") is not None \
            else (aff or {}).get("ecosystem")
        if pname is None:
            out.append(aff)
            continue
        if pname.lower() != str(name).lower():
            continue
        if ecosystem and peco and peco.lower() != str(ecosystem).lower():
            continue
        out.append(aff)
    return out


def fixed_versions(affected_entries):
    out = []
    for aff in affected_entries or []:
        for rng in aff.get("ranges") or []:
            for evt in rng.get("events") or []:
                if "fixed" in evt and evt["fixed"] not in out:
                    out.append(evt["fixed"])
    return out


def describe_ranges(affected_entries, ecosystem=None):
    """Human-readable vulnerable ranges, e.g. '>=2.2, <2.2.28'."""
    parts = []
    for aff in affected_entries or []:
        for rng in aff.get("ranges") or []:
            if (rng.get("type") or "").upper() == "GIT":
                continue
            intro = fixed = last = None
            for evt in rng.get("events") or []:
                if "introduced" in evt:
                    intro = evt["introduced"]
                elif "fixed" in evt:
                    fixed = evt["fixed"]
                elif "last_affected" in evt:
                    last = evt["last_affected"]
            seg = []
            if intro and intro != "0":
                seg.append(f">={intro}")
            if fixed:
                seg.append(f"<{fixed}")
            elif last:
                seg.append(f"<={last}")
            if not seg and intro == "0":
                seg.append("all versions")
            if seg:
                s = ", ".join(seg)
                if s not in parts:
                    parts.append(s)
    return parts


def min_safe_version(installed, advisories, ecosystem, name=None):
    """Smallest advisory-named fixed version that clears EVERY advisory.

    Only versions the advisories themselves name as fixed for THIS package are
    ever proposed: an invented string could name a release that does not exist,
    and a version harvested from a co-listed package (see entries_for) would
    name a real release of the wrong project. Returns
    (min_safe, min_safe_same_major, exact)."""
    scheme = scheme_for(ecosystem)
    candidates = []
    for adv in advisories or []:
        entries = entries_for(adv.get("affected") or [], ecosystem, name)
        for v in fixed_versions(entries):
            if v not in candidates:
                candidates.append(v)
    if not candidates:
        return None, None, True

    exact_all = True

    def clears_all(cand):
        nonlocal exact_all
        for adv in advisories or []:
            for aff in entries_for(adv.get("affected") or [], ecosystem, name):
                hit, ok = is_affected(cand, aff, ecosystem)
                exact_all = exact_all and ok
                if hit:
                    return False
        return True

    viable = [c for c in candidates if clears_all(c)]
    if not viable:
        return None, None, exact_all

    def sort_cmp(v):
        return v
    # selection sort using the scheme comparator (no functools.cmp_to_key
    # dependency on parse failures)
    ordered = list(viable)
    for i in range(len(ordered)):
        for j in range(len(ordered) - 1 - i):
            c, _ = compare(ordered[j], ordered[j + 1], scheme)
            if c is not None and c > 0:
                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]

    # smallest overall that is also >= installed (upgrading, not downgrading)
    min_safe = None
    for v in ordered:
        c, ok = compare(v, installed, scheme)
        exact_all = exact_all and ok
        if c is None or c >= 0:
            min_safe = v
            break
    min_safe = min_safe or ordered[0]

    same_major = None
    inst_major = _major(installed, scheme)
    if inst_major is not None:
        for v in ordered:
            if _major(v, scheme) == inst_major:
                c, _ = compare(v, installed, scheme)
                if c is None or c >= 0:
                    same_major = v
                    break
    return min_safe, same_major, exact_all


def _major(v, scheme):
    if scheme in ("debian", "apk"):
        p = parse_debian(v)
        if not p:
            return None
        m = re.match(r"^(\d+)", p[1])
        return int(m.group(1)) if m else None
    m = re.match(r"^v?(\d+)", str(v or ""))
    return int(m.group(1)) if m else None


def package_status(installed, advisories, ecosystem, *, resolution="lockfile",
                   feeds_ok=True, name=None):
    """VULNERABLE / SAFE / UNKNOWN for one package, with the reason.

    UNKNOWN is returned — never SAFE — whenever a feed was offline, the
    installed version is a declared RANGE rather than an exact version, the
    ecosystem has no exact comparator, or any comparison fell back to the
    generic scheme. "We could not check" must never render as "clear"."""
    scheme = scheme_for(ecosystem)
    if not feeds_ok:
        return {"status": "UNKNOWN", "reason": "CVE feeds offline this run — "
                "no advisory data to evaluate against"}
    if resolution in ("declared", "unparsed") or not installed:
        return {"status": "UNKNOWN",
                "reason": f"no exact installed version ({resolution}) — a range "
                          "cannot be evaluated against advisory ranges"}
    if scheme == "generic":
        return {"status": "UNKNOWN",
                "reason": f"no exact version comparator for ecosystem "
                          f"{ecosystem!r} — refusing to claim safety from an "
                          "approximate comparison"}

    matched, exact = [], True
    for adv in advisories or []:
        for aff in entries_for(adv.get("affected") or [], ecosystem, name):
            hit, ok = is_affected(installed, aff, ecosystem)
            exact = exact and ok
            if hit:
                matched.append(adv)
                break
    if matched:
        min_safe, same_major, _ = min_safe_version(installed, matched, ecosystem, name)
        mine = [aff for a in matched
                for aff in entries_for(a.get("affected") or [], ecosystem, name)]
        return {"status": "VULNERABLE",
                "advisories": [a.get("id") for a in matched],
                "ranges": describe_ranges(mine, ecosystem),
                "fixed_versions": fixed_versions(mine),
                "min_safe": min_safe,
                "min_safe_same_major": same_major,
                "exact": exact}
    if not exact:
        return {"status": "UNKNOWN",
                "reason": "version comparison was approximate — not claiming safety"}
    return {"status": "SAFE",
            "checked": len(advisories or []),
            "reason": "no advisory in the consulted feeds affects this exact version"}
