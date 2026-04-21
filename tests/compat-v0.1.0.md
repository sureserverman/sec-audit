# sec-review v0.1.0 → v0.2.0 backward-compat contract

This doc freezes the shape of the v0.1.0 `/sec-review` output that v0.2.0 must
continue to produce. Any v0.2.0 run against `tests/fixtures/sample-stack/` must
still satisfy every assertion below; Stage 4 enforces this.

## Required report-file properties

- Filename pattern: `<target>/sec-review-report-YYYYMMDD-HHMM.md` (UTC).
- Non-empty markdown file.

## Required header block fields

Each produced report must include a metadata block with at least these labels:

- `Date:` (UTC timestamp)
- `Scope:` (target path reviewed)
- `Inventory:` (language/framework/dep/infra summary)
- `CVE feeds:` (OSV / NVD / GHSA, with fetched_at or offline marker)
- `Findings:` (counts by severity — CRITICAL / HIGH / MEDIUM / LOW)

## Required finding-set assertions (sample-stack fixture)

At minimum, the v0.2.0 report on `sample-stack` must contain:

- ≥ 1 finding at severity **CRITICAL** or **HIGH**.
- ≥ 1 reference to a live CVE identifier matching `CVE-YYYY-NNNN+` (e.g. `CVE-2022-28346`).
  - When all three CVE feeds are offline the banner `⚠ CVE enrichment offline`
    must be present INSTEAD; that is the only acceptable substitute.
- ≥ 1 TLS-related finding surfaced from `nginx/nginx.conf` (weak protocols,
  missing HSTS, or similar).
- ≥ 1 container-related finding surfaced from `Dockerfile` (root USER, missing
  USER directive, or similar).
- ≥ 1 framework finding surfaced from the Django app (SQLi, XSS, mass-assign,
  or similar from the Django reference pack).

## Required section headings

The report must contain the section headings from SKILL.md section 6, notably:

- `## Dependency CVE summary`
- `## Review metadata`
- Per-severity buckets in descending order (`## CRITICAL`, `## HIGH`, etc. — or
  the template's equivalent).

## Negative assertions (MUST NOT)

- MUST NOT contain a CVE identifier that does not appear in the live feed
  response captured during the run (no fabrication).
- MUST NOT omit a finding that the pipeline surfaced — triager annotates, does
  not drop; report-writer renders everything it receives.
- MUST NOT modify the `fix_recipe` string from the reference pack; fixes are
  quoted verbatim.

## Enforcement

The Stage 4 gate runs:

```sh
report=$(ls -t tests/fixtures/sample-stack/sec-review-report-*.md | head -1)
grep -qE "CRITICAL|HIGH"  "$report"  || { echo "FAIL: no CRITICAL/HIGH"; exit 1; }
grep -qE "CVE-[0-9]{4}-[0-9]{4,}" "$report" \
  || grep -q "CVE enrichment offline" "$report" \
  || { echo "FAIL: no live CVE and no offline banner"; exit 1; }
grep -qi "TLS"        "$report" || { echo "FAIL: no TLS finding"; exit 1; }
grep -qi "container"  "$report" || { echo "FAIL: no container finding"; exit 1; }
grep -qi "Django"     "$report" || { echo "FAIL: no Django finding"; exit 1; }
echo "compat-v0.1.0: OK"
```

That script is the single source of truth for "did we break the v0.1.0 contract?"
