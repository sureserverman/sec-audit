# Security Review — sample-stack

**Date (UTC):** 2026-04-21 11:35
**Scope:** tests/fixtures/sample-stack/ (Dockerfile, nginx/nginx.conf, requirements.txt, app/)
**Excluded:** .pipeline/, prior sec-audit-report-*.md
**Inventory:** Django 2.2.0 web app (PyPI: django 2.2.0, requests 2.19.0, pyyaml 5.3), nginx TLS terminator, Docker container image (python:3.11 base), no k8s manifests present.
**CVE feeds:** OSV (ok, fetched 2026-04-21T11:35Z), NVD (not queried — OSV sufficient), GHSA (aliased via OSV)
**Findings:** 2 CRITICAL, 6 HIGH, 4 MEDIUM, 0 LOW

---

## CRITICAL

### Django raw SQL string concatenation — SQL injection
- **File:** `app/views/search.py:9`
- **CWE:** CWE-89
- **CVE(s):** n/a (code-pattern finding)
- **Score:** 96 / 100 (CVSS 36 + Exposure 25 + Exploit 20 + NoAuth 15, confidence: high)
  - CVSS: sec-expert severity CRITICAL → 36
  - Exposure: +25 (reachable on unauthenticated GET /search)
  - Exploit: +20 (trivial, public PoC class — standard SQLi payloads)
  - NoAuth: +15 (no authentication required)
- **Evidence:**
  ```
  cursor.execute("SELECT id, name FROM users WHERE name = '" + q + "'")
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

### Dependency: Django 2.2.0 — multiple CRITICAL CVEs (SQLi, account takeover)
- **File:** `requirements.txt:1`
- **CWE:** CWE-1104 (use of unmaintained / outdated component)
- **CVE(s):** CVE-2020-7471 (CVSS 9.8, PotentiallySQLInjection in StringAgg delimiter — OSV, fetched 2026-04-21T11:35Z); CVE-2019-19844 (account-takeover via password-reset — OSV); CVE-2021-44420 (URL auth-bypass — OSV); CVE-2020-13254, CVE-2020-13596, CVE-2020-24583, CVE-2020-24584, CVE-2020-9402, CVE-2019-12308, CVE-2019-14232, CVE-2019-14233, CVE-2019-14234, CVE-2019-14235, CVE-2019-19118, CVE-2019-12781 (all OSV-sourced, fetched 2026-04-21T11:35Z)
- **Score:** 92 / 100 (CVSS 40 + Exposure 25 + Exploit 12 + NoAuth 15, confidence: high)
  - CVSS: 9.8 → min(40, 9.8*4) = 40
  - Exposure: +25 (Django is the unauthenticated request surface)
  - Exploit: +12 (multiple public advisories and PoCs; not all flagged as CISA KEV)
  - NoAuth: +15 (SQLi and password-reset CVEs are pre-auth)
- **Evidence:**
  ```
  django==2.2.0
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

  (Note: the reference-pack fix-recipe library does not contain a dedicated "upgrade Django" entry; the operational remedy is to upgrade past the fixed-in versions listed in the Dependency CVE summary below — 2.2.25 or later for the 2.2 series, or current 4.2 LTS / 5.x.)
- **Sources:**
  - https://osv.dev/vulnerability/PYSEC-2020-33 (CVE-2020-7471)
  - https://osv.dev/vulnerability/PYSEC-2019-13 (CVE-2019-19844)
  - https://osv.dev/vulnerability/PYSEC-2021-439 (CVE-2021-44420)
  - https://www.djangoproject.com/weblog/

## HIGH

### Django template |safe on user input — reflected XSS
- **File:** `app/templates/search_results.html:6`
- **CWE:** CWE-79
- **CVE(s):** n/a (code-pattern finding)
- **Score:** 88 / 100 (CVSS 28 + Exposure 25 + Exploit 20 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <div>{{ q|safe }}</div>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
  > # Or use format_html for structured HTML construction
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### Django template |safe on user-influenced row data — stored/reflected XSS
- **File:** `app/templates/search_results.html:7`
- **CWE:** CWE-79
- **CVE(s):** n/a (code-pattern finding)
- **Score:** 83 / 100 (CVSS 28 + Exposure 25 + Exploit 15 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <ul>{% for r in rows %}<li>{{ r.1|safe }}</li>{% endfor %}</ul>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
  > # Or use format_html for structured HTML construction
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### Django hardcoded SECRET_KEY
- **File:** `app/settings.py:2`
- **CWE:** CWE-321
- **CVE(s):** n/a (code-pattern finding)
- **Score:** 81 / 100 (CVSS 28 + Exposure 25 + Exploit 13 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  SECRET_KEY = "hardcoded-dev-secret-do-not-use"
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
- **Sources:**
  - https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

### Django DEBUG=True in settings
- **File:** `app/settings.py:1`
- **CWE:** CWE-200
- **CVE(s):** n/a (code-pattern finding)
- **Score:** 78 / 100 (CVSS 28 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  DEBUG = True
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
- **Sources:**
  - https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

### nginx weak TLS protocols (TLSv1 and TLSv1.1 enabled) — TLS hardening
- **File:** `nginx/nginx.conf:6`
- **CWE:** CWE-326
- **CVE(s):** n/a (configuration finding)
- **Score:** 76 / 100 (CVSS 28 + Exposure 25 + Exploit 8 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ```
- **Recommended fix** (quoted from `references/tls/tls-bcp.md`):
  > ssl_protocols TLSv1.2 TLSv1.3;
- **Sources:**
  - https://datatracker.ietf.org/doc/html/rfc9325#section-4
  - https://ssl-config.mozilla.org/

### Dockerfile runs as root — missing USER directive (container hardening)
- **File:** `Dockerfile:10`
- **CWE:** CWE-250
- **CVE(s):** n/a (container configuration finding)
- **Score:** 73 / 100 (CVSS 28 + Exposure 25 + Exploit 5 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
  ```
- **Recommended fix** (quoted from `references/containers/dockerfile-hardening.md`):
  > FROM node:20.12.2-alpine3.19@sha256:<digest>
  > WORKDIR /app
  > RUN addgroup -S appgroup && adduser -S appuser -G appgroup
  > COPY --chown=appuser:appgroup package*.json ./
  > RUN npm ci --omit=dev
  > COPY --chown=appuser:appgroup . .
  > USER appuser
  > CMD ["node", "server.js"]
- **Sources:**
  - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

## MEDIUM

### nginx server_tokens on — version disclosure (TLS/HTTP hardening)
- **File:** `nginx/nginx.conf:10`
- **CWE:** CWE-200
- **CVE(s):** n/a (configuration finding)
- **Score:** 56 / 100 (CVSS 16 + Exposure 25 + Exploit 0 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  server_tokens on;
  ```
- **Recommended fix** (quoted from `references/webservers/nginx.md`):
  > http {
  >     server_tokens off;
  >     add_header X-Content-Type-Options "nosniff" always;
  >     add_header X-Frame-Options "DENY" always;
  >     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  >     server {
  >         listen 443 ssl;
  >     }
  > }
- **Sources:**
  - https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

### nginx missing HSTS header on TLS server block
- **File:** `nginx/nginx.conf:1`
- **CWE:** CWE-319
- **CVE(s):** n/a (configuration finding)
- **Score:** 56 / 100 (CVSS 16 + Exposure 25 + Exploit 0 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  server { listen 443 ssl; ... (no add_header Strict-Transport-Security)
  ```
- **Recommended fix** (quoted from `references/webservers/nginx.md`):
  > http {
  >     server_tokens off;
  >     add_header X-Content-Type-Options "nosniff" always;
  >     add_header X-Frame-Options "DENY" always;
  >     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  >     server {
  >         listen 443 ssl;
  >     }
  > }
- **Sources:**
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  - https://datatracker.ietf.org/doc/html/rfc6797

### Django ALLOWED_HOSTS wildcard
- **File:** `app/settings.py:3`
- **CWE:** CWE-16
- **CVE(s):** n/a (configuration finding)
- **Score:** 49 / 100 (CVSS 16 + Exposure 25 + Exploit 0 + NoAuth 15 − 7 confidence medium, confidence: medium)
- **Evidence:**
  ```
  ALLOWED_HOSTS = ["*"]
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#ssl-https

### Dockerfile base image not pinned to digest (container supply-chain)
- **File:** `Dockerfile:1`
- **CWE:** CWE-829
- **CVE(s):** n/a (container configuration finding)
- **Score:** 41 / 100 (CVSS 16 + Exposure 25 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  FROM python:3.11
  ```
- **Recommended fix** (quoted from `references/containers/dockerfile-hardening.md`):
  > FROM python:3.12.3-slim-bookworm@sha256:<digest>
- **Sources:**
  - https://csrc.nist.gov/publications/detail/sp/800-190/final
  - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

## LOW

(none)

---

## Dependency CVE summary

| Package  | Version | CVEs | Max CVSS | Fixed in                |
|----------|---------|------|----------|-------------------------|
| django   | 2.2.0   | 15   | 9.8      | 2.2.25 (series) / 3.2.10 / 4.2 LTS+ |
| requests | 2.19.0  | 3    | 6.1      | 2.20.0 / 2.31.0 / 2.32.0 |
| pyyaml   | 5.3     | 2    | 9.8      | 5.3.1 / 5.4             |

Notable CVE IDs (all from OSV, fetched 2026-04-21T11:35Z):

- **django 2.2.0**: CVE-2019-12781, CVE-2019-14232, CVE-2019-14233, CVE-2019-14234, CVE-2019-14235, CVE-2019-19118, CVE-2019-19844, CVE-2019-12308, CVE-2020-13254, CVE-2020-13596, CVE-2020-24583, CVE-2020-24584, CVE-2020-7471, CVE-2020-9402, CVE-2021-44420
- **requests 2.19.0**: CVE-2018-18074, CVE-2023-32681, CVE-2024-35195
- **pyyaml 5.3**: CVE-2020-1747, CVE-2020-14343

## Review metadata

- Plugin version: `sec-audit 0.2.0`
- Reference packs loaded: `frameworks/django.md`, `webservers/nginx.md`, `containers/docker.md`, `containers/dockerfile-hardening.md`, `frontend/xss.md`, `tls/tls-bcp.md`
- sec-expert runs: 1
- finding-triager runs: 1
- cve-enricher runs: 1 (OSV querybatch: 1 call; OSV vuln detail fetches: 23 calls)
- Total CVE lookups: 24
- Limits hit: none
- CVE feed status: OSV ok; NVD/GHSA not queried (OSV covered all 3 PyPI packages)
