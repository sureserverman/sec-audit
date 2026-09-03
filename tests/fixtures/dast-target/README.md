# dast-target fixture

The DAST lane's fixture: a deliberately weak static page and the real OWASP
ZAP baseline report for it.

- `site/index.html` — one page with a form, an admin link and a cross-origin
  script with no SRI. Served by `python3 -m http.server`, which adds no
  security headers at all, so ZAP's passive rules fire (CSP, anti-clickjacking,
  X-Content-Type-Options, COOP/COEP/CORP, Permissions-Policy, SRI, server
  version leak, cacheable content).
- `zap-baseline.json` — the **real** report from
  `zap-baseline.py -t http://127.0.0.1:8099 -J report.json -I` run through the
  official image `ghcr.io/zaproxy/zaproxy:stable` (ZAP 2.16, 2026-09-03): 11
  alerts, one site. It replaces a hand-authored file that had four invented
  alerts (including a SQL injection a static page cannot exhibit).
- `.pipeline/dast.jsonl` — the engine's output for that run: 11 findings and
  `__dast_status__: "ok"`.

The same report lives in `tests/fixtures/raw-tool-output/dast/` for the
parity test. `tests/lane-live-gate.sh` re-runs the whole thing live where
docker (or a local `zap-baseline.py`) is available: it serves `site/` on a
loopback port and passes `--url` to the engine.

Regenerate:

```bash
(cd tests/fixtures/dast-target/site && python3 -m http.server 8099 --bind 127.0.0.1 &)
python3 scripts/secaudit/runner.py dast tests/fixtures/dast-target --url http://127.0.0.1:8099 \
  > tests/fixtures/dast-target/.pipeline/dast.jsonl
```
