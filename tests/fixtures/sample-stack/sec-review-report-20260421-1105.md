# Security Review — sample-stack

**Date (UTC):** 2026-04-21 11:05
**Scope:** `/home/user/dev/sec-review/tests/fixtures/sample-stack/` (app/, nginx/, Dockerfile, requirements.txt)
**Excluded:** `k8s/` (empty), no `.venv/` or vendored deps present
**Inventory:** Django (Python), nginx reverse proxy, Docker container, PyPI ecosystem (django 2.2.0, requests 2.19.0, pyyaml 5.3)
**CVE feeds:** OSV (ok), NVD (not queried — OSV sufficient), GHSA (ok via OSV aliases)
**Findings:** 1 CRITICAL, 6 HIGH, 4 MEDIUM, 1 LOW

---

## CRITICAL

### Django SQL Injection via request-controlled concatenation (CVE-2022-28346)
- **File:** `requirements.txt:1` (django==2.2.0)
- **CWE:** CWE-89
- **CVE(s):** CVE-2022-28346 / GHSA-2gwj-7jmv-h26r (CVSS 9.8, source: OSV, fetched 2026-04-21T11:05Z)
- **Score:** 90 / 100 (CVSS 40 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  django==2.2.0
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > query = f"SELECT * FROM orders WHERE user_id = {user_id}"
  > cursor.execute(query)
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
  > ```
  >
  > Source: https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

  Upgrade path: Django 2.2.28+, 3.2.13+, or 4.0.4+ fixes CVE-2022-28346.
- **Sources:**
  - https://nvd.nist.gov/vuln/detail/CVE-2022-28346
  - https://github.com/django/django/commit/2044dac5c6968441be6f534c4139bcf48c5c7e48
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

---

## HIGH

### Raw SQL string concatenation of user input in search view
- **File:** `app/views/search.py:9`
- **CWE:** CWE-89
- **CVE(s):** none (application-level defect)
- **Score:** 78 / 100 (Severity 28 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  cursor.execute("SELECT id, name FROM users WHERE name = '" + q + "'")
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > query = f"SELECT * FROM orders WHERE user_id = {user_id}"
  > cursor.execute(query)
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
  > ```
  >
  > Source: https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection
  - https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html

### Template XSS via `|safe` on request-controlled variable
- **File:** `app/templates/search_results.html:6`
- **CWE:** CWE-79
- **CVE(s):** none (application-level defect)
- **Score:** 78 / 100 (Severity 28 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <div>{{ q|safe }}</div>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > from django.utils.safestring import mark_safe
  > comment = mark_safe(request.POST["comment"])
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
  > # Or use format_html for structured HTML construction
  > ```
  >
  > Source: https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

  In the template: remove the `|safe` filter from `{{ q|safe }}` and `{{ r.1|safe }}` so Django's auto-escaping applies.
- **Sources:**
  - https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### Weak TLS protocols (TLSv1 / TLSv1.1 enabled) in nginx
- **File:** `nginx/nginx.conf:6`
- **CWE:** CWE-326
- **CVE(s):** none (protocol-level configuration defect; BEAST/POODLE/Lucky13 class)
- **Score:** 78 / 100 (Severity 28 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ```
- **Recommended fix** (quoted from `references/webservers/nginx.md`):
  > **Before (dangerous):**
  >
  > ```nginx
  > ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
  > ssl_ciphers HIGH:!aNULL:!MD5;
  > ```
  >
  > **After (safe):**
  >
  > ```nginx
  > ssl_protocols TLSv1.2 TLSv1.3;
  > ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
  > ssl_prefer_server_ciphers off;
  > ssl_session_tickets off;
  > ```
  >
  > Source: https://ssl-config.mozilla.org/
- **Sources:**
  - https://datatracker.ietf.org/doc/html/rfc9325
  - https://ssl-config.mozilla.org/

### Hardcoded `SECRET_KEY` and `DEBUG=True` in Django settings
- **File:** `app/settings.py:1-2`
- **CWE:** CWE-321 (hardcoded cryptographic key), CWE-200 (debug info disclosure)
- **CVE(s):** none (configuration defect)
- **Score:** 76 / 100 (Severity 36 + Exposure 25 + Exploit 0 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  DEBUG = True
  SECRET_KEY = "hardcoded-dev-secret-do-not-use"
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > SECRET_KEY = "django-insecure-abc123hardcoded"
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > import os
  > SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
  > ```
  >
  > Source: https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

  Additionally set `DEBUG = False` in production and restrict `ALLOWED_HOSTS` from `["*"]` to the concrete hostname(s).
- **Sources:**
  - https://docs.djangoproject.com/en/stable/ref/settings/#secret-key
  - https://docs.djangoproject.com/en/stable/topics/security/#ssl-https

### PyYAML arbitrary code execution via yaml.load / FullLoader (CVE-2020-1747)
- **File:** `requirements.txt:3` (pyyaml==5.3)
- **CWE:** CWE-20 / CWE-502
- **CVE(s):** CVE-2020-1747 / GHSA-6757-jp84-gxfx (CVSS 9.8, source: OSV, fetched 2026-04-21T11:05Z)
- **Score:** 70 / 100 (CVSS 40 + Exposure 5 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  pyyaml==5.3
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > import yaml
  > config = yaml.load(user_data)
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > import yaml
  > config = yaml.safe_load(user_data)
  > ```
  >
  > Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

  Upgrade path: pyyaml 5.3.1+ fixes CVE-2020-1747; 5.4+ additionally fixes CVE-2020-14343.
- **Sources:**
  - https://nvd.nist.gov/vuln/detail/CVE-2020-1747
  - https://github.com/yaml/pyyaml/pull/386

### PyYAML FullLoader RCE bypass (CVE-2020-14343)
- **File:** `requirements.txt:3` (pyyaml==5.3)
- **CWE:** CWE-20
- **CVE(s):** CVE-2020-14343 / GHSA-8q59-q68h-6hv4 (CVSS 9.8, source: OSV, fetched 2026-04-21T11:05Z)
- **Score:** 70 / 100 (CVSS 40 + Exposure 5 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  pyyaml==5.3
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > import yaml
  > config = yaml.load(user_data)
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > import yaml
  > config = yaml.safe_load(user_data)
  > ```
  >
  > Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

  Upgrade path: pyyaml 5.4+.
- **Sources:**
  - https://nvd.nist.gov/vuln/detail/CVE-2020-14343
  - https://github.com/yaml/pyyaml/issues/420

---

## MEDIUM

### Django reflected XSS in admin autocomplete (CVE-2020-13596)
- **File:** `requirements.txt:1` (django==2.2.0)
- **CWE:** CWE-79
- **CVE(s):** CVE-2020-13596 / GHSA-2m34-jcjv-45xf (CVSS 6.1, source: OSV, fetched 2026-04-21T11:05Z)
- **Score:** 74 / 100 (CVSS 24.4 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
  Note: Score places in upper MEDIUM; included here to separate CVE-driven finding from the HIGH source-level XSS finding.
- **Evidence:**
  ```
  django==2.2.0
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > **Before (dangerous):**
  >
  > ```python
  > from django.utils.safestring import mark_safe
  > comment = mark_safe(request.POST["comment"])
  > ```
  >
  > **After (safe):**
  >
  > ```python
  > from django.utils.html import format_html, escape
  > comment = escape(request.POST["comment"])
  > # Or use format_html for structured HTML construction
  > ```
  >
  > Source: https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

  Upgrade path: Django 2.2.13+, 3.0.7+.
- **Sources:**
  - https://nvd.nist.gov/vuln/detail/CVE-2020-13596

### Missing HSTS header on HTTPS listener
- **File:** `nginx/nginx.conf:12`
- **CWE:** CWE-319
- **CVE(s):** none (configuration defect)
- **Score:** 56 / 100 (Severity 16 + Exposure 25 + Exploit 0 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  # Missing HSTS header (CWE-319)
  ```
- **Recommended fix** (quoted from `references/webservers/nginx.md`):
  > **Before (dangerous):**
  >
  > ```nginx
  > http {
  >     # server_tokens not set — defaults to on
  >     server {
  >         listen 443 ssl;
  >     }
  > }
  > ```
  >
  > **After (safe):**
  >
  > ```nginx
  > http {
  >     server_tokens off;
  >     add_header X-Content-Type-Options "nosniff" always;
  >     add_header X-Frame-Options "DENY" always;
  >     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  >     server {
  >         listen 443 ssl;
  >     }
  > }
  > ```
  >
  > Source: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
- **Sources:**
  - https://datatracker.ietf.org/doc/html/rfc6797
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### Container runs as root (no `USER` directive in Dockerfile)
- **File:** `Dockerfile:1-10`
- **CWE:** CWE-250
- **CVE(s):** none (configuration defect; amplifier)
- **Score:** 45 / 100 (Severity 28 + Exposure 15 + Exploit 0 + Auth 2, confidence: high)
- **Evidence:**
  ```
  # No USER directive; container runs as root.
  CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
  ```
- **Recommended fix** (quoted from `references/containers/dockerfile-hardening.md`):
  > **Before (dangerous):**
  >
  > ```dockerfile
  > FROM node:20-alpine
  > WORKDIR /app
  > COPY package*.json ./
  > RUN npm ci --omit=dev
  > COPY . .
  > CMD ["node", "server.js"]
  > ```
  >
  > **After (safe):**
  >
  > ```dockerfile
  > FROM node:20.12.2-alpine3.19@sha256:<digest>
  > WORKDIR /app
  > RUN addgroup -S appgroup && adduser -S appuser -G appgroup
  > COPY --chown=appuser:appgroup package*.json ./
  > RUN npm ci --omit=dev
  > COPY --chown=appuser:appgroup . .
  > USER appuser
  > CMD ["node", "server.js"]
  > ```
  >
  > Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

  Note: The image also uses `python manage.py runserver`, which is a development server and must not be exposed in production — front with gunicorn/uvicorn behind nginx.
- **Sources:**
  - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
  - https://csrc.nist.gov/publications/detail/sp/800-190/final

### requests `.netrc` credential leak via malicious URL (CVE-2024-47081)
- **File:** `requirements.txt:2` (requests==2.19.0)
- **CWE:** CWE-522
- **CVE(s):** CVE-2024-47081 / GHSA-9hjg-9r4m-mvj7 (CVSS 5.3, source: OSV, fetched 2026-04-21T11:05Z)
- **Score:** 41 / 100 (CVSS 21 + Exposure 5 + Exploit 0 + NoAuth 15, confidence: medium)
- **Evidence:**
  ```
  requests==2.19.0
  ```
- **Recommended fix:** Upgrade `requests` to ≥ 2.32.4. No `fix_recipe` entry for this CWE in the loaded reference packs — follow the upstream advisory.
- **Sources:**
  - https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47081

---

## LOW

### `server_tokens on` — nginx version disclosed in response headers
- **File:** `nginx/nginx.conf:10`
- **CWE:** CWE-200
- **CVE(s):** none
- **Score:** 46 / 100 (Severity 6 + Exposure 25 + Exploit 0 + NoAuth 15, confidence: high)
  Note: rubric score crosses into MEDIUM band; kept in LOW here because the underlying severity class is information disclosure only.
- **Evidence:**
  ```
  server_tokens on;
  ```
- **Recommended fix** (quoted from `references/webservers/nginx.md`):
  > **Before (dangerous):**
  >
  > ```nginx
  > http {
  >     # server_tokens not set — defaults to on
  >     server {
  >         listen 443 ssl;
  >     }
  > }
  > ```
  >
  > **After (safe):**
  >
  > ```nginx
  > http {
  >     server_tokens off;
  >     add_header X-Content-Type-Options "nosniff" always;
  >     add_header X-Frame-Options "DENY" always;
  >     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  >     server {
  >         listen 443 ssl;
  >     }
  > }
  > ```
  >
  > Source: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
- **Sources:**
  - https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

---

## Dependency CVE summary

| Package  | Version | CVEs (OSV) | Top 2 CVE IDs                      | Max CVSS | Fixed in          |
|----------|---------|------------|------------------------------------|----------|-------------------|
| django   | 2.2.0   | 63         | CVE-2022-28346, CVE-2020-13596     | 9.8      | 2.2.28 / 3.2.13 / 4.0.4 |
| requests | 2.19.0  | 7          | CVE-2024-47081, CVE-2024-35195     | 5.6      | 2.32.4            |
| pyyaml   | 5.3     | 4          | CVE-2020-1747,  CVE-2020-14343     | 9.8      | 5.4               |

All three pinned deps are end-of-life and should be upgraded to current supported releases: Django 4.2 LTS or 5.x, requests ≥ 2.32.4, pyyaml ≥ 6.0.1.

## Review metadata

- Plugin version: `sec-review 0.1.0`
- Reference packs loaded: `frameworks/django.md`, `webservers/nginx.md`, `containers/dockerfile-hardening.md`
- sec-expert runs: 1 (single Django + nginx + Docker stack)
- Total CVE lookups: 3 (OSV.dev; 1 POST per pinned package)
- Limits hit: none
- CVE feed status: OSV ok; NVD and GHSA not directly queried (OSV returned GHSA IDs and NVD CVE aliases inline)
