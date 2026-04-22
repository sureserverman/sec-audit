# vulnerable-webext fixture

Minimal Manifest V3 browser extension used by the sec-review webext lane's
E2E assertions (Stage 2 Task 2.4 of v0.6.0).

## Intentional findings

- `manifest.json`: broad `host_permissions: ["*://*/*"]` (CWE-732),
  `content_security_policy.extension_pages` with `'unsafe-eval'` (CWE-95),
  `externally_connectable.matches` with `*://*/*` (CWE-346),
  `web_accessible_resources.matches: ["<all_urls>"]` (CWE-200).
- `background/sw.js`: blocking `chrome.webRequest.onBeforeRequest`
  (removed from MV3 for non-enterprise), `eval(msg.script)` with no
  sender validation (CWE-95 + CWE-346), `new Function(code)` over
  remote-fetched text (CWE-829).
- `content/inject.js`: `innerHTML` assignment from `event.data.html`
  with no origin check (CWE-79 + CWE-346), API key stored in
  `chrome.storage.local` (CWE-312).
- `lib/jquery-1.12.4.min.js`: placeholder for a known-vulnerable library
  version — retire.js would flag CVE-2015-9251 and CVE-2019-11358.

## `.pipeline/`

- `addons-linter-report.json` — synthetic canonical output of
  `addons-linter --output json`, covering errors / warnings.
- `retire-report.json` — synthetic canonical output of `retire --path .
  --outputformat json` for the bundled jQuery 1.12.4.
- `webext.jsonl` — the JSONL the webext-runner agent should emit after
  consuming both upstream reports per the mapping in `webext-tools.md`.
  Ends with a `__webext_status__: "ok"` summary line.

All `.pipeline/*.json` files are synthetic fixtures, not output from a
live tool run, so the contract tests run without npm or node installed.
`--live` modes (if added later) would overwrite these with real tool
output for local verification.
