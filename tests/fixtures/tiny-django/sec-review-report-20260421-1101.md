# Security Review — tiny-django

**Date (UTC):** 2026-04-21 11:01
**Scope:** `/home/user/dev/sec-audit/tests/fixtures/tiny-django/` (entire tree; single-app Django fixture)
**Excluded:** none (no vendored deps, no `node_modules/`, no `.venv/`)
**Inventory:** Django 2.2.0 web app (single view + single template), `requests` 2.19.0 declared, PyPI ecosystem, no Dockerfile, no webserver config, no auth code.
**CVE feeds:** OSV (ok), NVD (not queried — OSV covered PyPI), GHSA (not queried — OSV surfaced GHSA IDs)
**Findings:** 1 CRITICAL, 4 HIGH, 4 MEDIUM, 0 LOW

---

## CRITICAL

### Django 2.2.0 — SQL injection via `QuerySet.annotate()/aggregate()/extra()` (CVE-2022-28346)
- **File:** `requirements.txt:1` (dep); reachable sink at `app/views/search.py:9`
- **CWE:** CWE-89
- **CVE(s):** CVE-2022-28346 (CVSS 9.8, source: OSV via GHSA-2gwj-7jmv-h26r, fetched 2026-04-21T11:01Z)
- **Score:** 90 / 100 (CVSS 40 + Exposure 25 unauth HTTP path + Exploit 10 public PoC + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  django==2.2.0
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])

  Upgrade `django` to a fixed version (≥ 2.2.28, ≥ 3.2.13, ≥ 4.0.4) and replace the concatenated SQL at `app/views/search.py:9` with parameter substitution.
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection
  - https://github.com/advisories/GHSA-2gwj-7jmv-h26r
  - https://www.djangoproject.com/weblog/2022/apr/11/security-releases/

---

## HIGH

### Hardcoded Django `SECRET_KEY` in settings.py
- **File:** `app/settings.py:2`
- **CWE:** CWE-321
- **CVE(s):** none (code finding)
- **Score:** 86 / 100 (Severity 36 CRITICAL + Exposure 25 unauth + Exploit 10 public PoC + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  SECRET_KEY = "hardcoded-dev-secret-do-not-use"
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
- **Sources:**
  - https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

### SQL injection via string concatenation in `search` view
- **File:** `app/views/search.py:9`
- **CWE:** CWE-89
- **CVE(s):** none directly (code finding; amplified by CVE-2022-28346 above)
- **Score:** 78 / 100 (Severity 28 HIGH + Exposure 25 unauth + Exploit 10 public PoC (sqlmap) + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  cursor.execute("SELECT id, name FROM users WHERE name = '" + q + "'")
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Reflected XSS via `{{ q|safe }}` in template
- **File:** `app/templates/search_results.html:7`
- **CWE:** CWE-79
- **CVE(s):** none (code finding)
- **Score:** 78 / 100 (Severity 28 HIGH + Exposure 25 unauth + Exploit 10 public PoC + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <div class="query">{{ q|safe }}</div>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
  > \# Or use format_html for structured HTML construction
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### Django 2.2.0 — SQL injection via StringAgg(delimiter) (CVE-2020-7471)
- **File:** `requirements.txt:1`
- **CWE:** CWE-89
- **CVE(s):** CVE-2020-7471 (CVSS 9.8, source: OSV via GHSA-hmr4-m2h5-33qx, fetched 2026-04-21T11:01Z)
- **Score:** 73 / 100 (CVSS 40 + Exposure 15 auth-gated contrib.postgres usage + Exploit 10 PoC + Auth 8, confidence: medium)
- **Evidence:**
  ```
  django==2.2.0
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])

  Upgrade `django` to ≥ 2.2.10, ≥ 3.0.3.
- **Sources:**
  - https://github.com/advisories/GHSA-hmr4-m2h5-33qx
  - https://www.djangoproject.com/weblog/2020/feb/03/security-releases/

---

## MEDIUM

### `DEBUG = True` combined with wildcard ALLOWED_HOSTS exposes stack traces
- **File:** `app/settings.py:1`
- **CWE:** CWE-200
- **CVE(s):** none
- **Score:** 68 / 100 (Severity 28 HIGH + Exposure 25 unauth + Exploit 0 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  DEBUG = True
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

  (Same environment-driven config pattern: set `DEBUG = os.environ.get("DJANGO_DEBUG") == "1"` and default to `False`.)
- **Sources:**
  - https://docs.djangoproject.com/en/stable/ref/settings/#debug

### Stored XSS through `{{ row.1|safe }}` fed by the SQLi sink
- **File:** `app/templates/search_results.html:10`
- **CWE:** CWE-79
- **CVE(s):** none
- **Score:** 56 / 100 (Severity 16 MEDIUM + Exposure 25 unauth + Exploit 0 + NoAuth 15, confidence: medium)
- **Evidence:**
  ```
  <li>{{ row.1|safe }}</li>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### `ALLOWED_HOSTS = ["*"]` — accepts any Host header
- **File:** `app/settings.py:3`
- **CWE:** CWE-200
- **CVE(s):** none
- **Score:** 56 / 100 (Severity 16 MEDIUM + Exposure 25 unauth + Exploit 0 + NoAuth 15, confidence: medium)
- **Evidence:**
  ```
  ALLOWED_HOSTS = ["*"]
  ```
- **Recommended fix:** no verbatim recipe in `references/frameworks/django.md` for this pattern; set `ALLOWED_HOSTS = ["your.real.host"]` and load from env.
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#host-headers-virtual-hosting

### requests 2.19.0 — `Authorization` header leaked on cross-origin redirect (CVE-2018-18074)
- **File:** `requirements.txt:2`
- **CWE:** CWE-522
- **CVE(s):** CVE-2018-18074 (CVSS 9.8, source: OSV via GHSA-x84v-xcm2-53pg, fetched 2026-04-21T11:01Z)
- **Score:** 57 / 100 (CVSS 40 + Exposure 5 internal/no visible caller + Exploit 10 public PoC + Auth 2 admin-only, confidence: medium)
- **Evidence:**
  ```
  requests==2.19.0
  ```
- **Recommended fix:** upgrade `requests` to ≥ 2.20.0. No verbatim Django-file recipe; apply dependency bump.
- **Sources:**
  - https://github.com/advisories/GHSA-x84v-xcm2-53pg
  - https://github.com/psf/requests/pull/4718

---

## Dependency CVE summary

| Package  | Version | CVEs (OSV total) | Top-3 CVEs                                   | Max CVSS | Fixed in        |
|----------|---------|------------------|----------------------------------------------|----------|-----------------|
| django   | 2.2.0   | 63               | CVE-2022-28346, CVE-2020-7471, CVE-2019-14234 | 9.8      | 2.2.28 / 3.2.13 / 4.0.4 (varies per CVE); upgrade to latest 4.2 LTS |
| requests | 2.19.0  | 7                | CVE-2018-18074, CVE-2023-32681, CVE-2024-47081 | 9.8      | ≥ 2.20.0 (18074), ≥ 2.31.0 (32681), ≥ 2.32.4 (47081) |

## Review metadata

- Plugin version: `sec-audit 0.1.0`
- Reference packs loaded: `frameworks/django.md`
- sec-expert runs: 1 (inline, single stack)
- Total CVE lookups: 2 (OSV.dev PyPI: django, requests)
- Limits hit: none (well below 500-lookup cap)
- Feeds consulted: OSV.dev (primary, ok). NVD + GHSA not queried — OSV already surfaced GHSA advisory IDs and CVSS vectors; fallback path was unnecessary.
