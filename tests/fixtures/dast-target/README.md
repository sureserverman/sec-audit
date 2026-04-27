# DAST target test fixture

Synthetic OWASP ZAP baseline scan output used by sec-audit DAST lane tests. This is NOT a captured real scan — the alerts were hand-authored to exercise the `dast-runner` contract without waiting on a multi-minute live scan against a running target.

Shape conforms to the OWASP ZAP JSON report schema (`@version`, `@generated`, `site[].alerts[]` with `pluginid`, `alertRef`, `riskcode`, `confidence`, `instances`, `cweid`, `wascid`, etc.).

Consumed by:

- `tests/dast-drill.sh` — feeds the fixture through the parser to assert alerts are classified by risk.
- `tests/contract-check.sh` — validates the `dast-runner` output contract against a known-good payload.

Alerts (one per risk level):

- HIGH — SQL Injection (pluginid `40018`, CWE-89) on `GET /search?q=test`
- MEDIUM — X-Frame-Options Header Not Set (pluginid `10020`, CWE-1021) on `GET /`
- LOW — X-Content-Type-Options Header Missing (pluginid `10021`, CWE-693) on `GET /api/items`
- INFORMATIONAL — Server Leaks Version Info via Server Header (pluginid `10036`) on `GET /`

Do NOT use this file as a reference for a real application's security posture.
