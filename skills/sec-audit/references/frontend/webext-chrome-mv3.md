# Chrome Extension — Manifest V3

## Source

- https://developer.chrome.com/docs/extensions/reference/manifest — Chrome Extensions Manifest reference
- https://developer.chrome.com/docs/extensions/mv3/intro/mv3-overview — MV3 overview (migration rationale, removed APIs)
- https://developer.chrome.com/docs/webstore/program-policies — Chrome Web Store Program Policies
- https://developer.chrome.com/docs/extensions/mv3/xhr/ — Remote code and CSP guidance for MV3 extensions
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — OWASP DOM-based XSS Prevention Cheat Sheet
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy — MDN CSP Header reference

## Scope

In-scope: Chrome Manifest V3 extensions targeting Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi). Covers `manifest.json` declarations, service-worker background scripts, content scripts, popup/options pages, and the `content_security_policy` manifest key. Out of scope: MV2 extensions (deprecated on Chrome stable June 2024 per developer.chrome.com — treat MV2 findings as end-of-life issues, not security mitigations); Firefox-specific manifest keys such as `browser_specific_settings` (covered by `webext-firefox-amo.md`); cross-browser WebExtension patterns common to both Chrome and Firefox (covered by `webext-shared-patterns.md`).

## Dangerous patterns (regex/AST hints)

### MV2 leftover — manifest_version: 2  — CWE-1104

- Why: MV2 is deprecated and will be removed from Chrome stable; extensions running on MV2 lack MV3 security defaults (stricter CSP, no remote code execution) and will stop working.
- Grep: `"manifest_version"\s*:\s*2`
- File globs: `**/manifest.json`
- Source: https://developer.chrome.com/docs/extensions/mv3/intro/mv3-overview

### Broad host_permissions — CWE-732

- Why: Permissions like `"<all_urls>"`, `"*://*/*"`, or `"http://*/*"` grant the extension access to every page the user visits; a compromise or malicious update can silently exfiltrate all web traffic.
- Grep: `"(?:\*://\*/\*|<all_urls>|https?://\*/\*)"`
- File globs: `**/manifest.json`
- Source: https://developer.chrome.com/docs/extensions/reference/manifest

### CSP extension_pages permissive (unsafe-eval / unsafe-inline) — CWE-94

- Why: MV3 enforces a strict default CSP for extension pages; explicitly allowing `unsafe-eval` or `unsafe-inline` in `content_security_policy.extension_pages` re-enables dynamic code execution banned by the platform.
- Grep: `unsafe-eval|unsafe-inline`
- File globs: `**/manifest.json`
- Source: https://developer.chrome.com/docs/extensions/mv3/xhr/

### externally_connectable wildcard in matches — CWE-346

- Why: A wildcard (`"*"` or `"*://*/*"`) in `externally_connectable.matches` allows any origin on the internet to send messages to the extension via `chrome.runtime.sendMessage`, bypassing same-origin checks.
- Grep: `"externally_connectable"[\s\S]{0,200}"matches"[\s\S]{0,100}"\*"`
- File globs: `**/manifest.json`
- Source: https://developer.chrome.com/docs/extensions/reference/manifest

### Remote code execution — script src / import() of remote URL — CWE-829

- Why: MV3 prohibits executing remotely hosted code; a `<script src="https://…">` in an extension page or a dynamic `import()` / `fetch()+eval()` of a remote URL violates Chrome Web Store policy and allows a CDN or network attacker to inject arbitrary logic into the extension's privileged context.
- Grep: `<script[^>]+src=["']https?://|import\s*\(\s*["']https?://|fetch\s*\([^)]*\)\s*\.then[^}]*eval\s*\(`
- File globs: `**/*.html`, `**/*.js`, `**/*.ts`
- Source: https://developer.chrome.com/docs/extensions/mv3/xhr/

### Blocking webRequest in service-worker background — CWE-1104

- Why: MV3 removed `chrome.webRequest` blocking mode for non-enterprise extensions; code that passes `["blocking"]` to `onBeforeRequest` or related events silently fails or is rejected at review time, indicating the extension was ported from MV2 without auditing the network interception logic.
- Grep: `webRequest\.on\w+\.addListener\s*\([^)]*\[\s*["']blocking["']\s*\]`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://developer.chrome.com/docs/extensions/mv3/intro/mv3-overview

## Secure patterns

Minimal safe MV3 `manifest.json` with narrow `host_permissions` and strict CSP:

```json
{
  "manifest_version": 3,
  "name": "My Extension",
  "version": "1.0.0",
  "description": "Does one thing, narrowly scoped.",

  "permissions": ["storage"],
  "host_permissions": ["https://api.example.com/*"],

  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; object-src 'none';"
  },

  "background": {
    "service_worker": "background.js"
  },

  "action": {
    "default_popup": "popup.html"
  }
}
```

- `manifest_version: 3` is required for all new and updated Chrome extensions.
- `host_permissions` is restricted to a single HTTPS origin; no wildcards.
- `content_security_policy.extension_pages` omits `unsafe-eval` and `unsafe-inline`.
- `object-src 'none'` prevents plugin-based code execution.

Source: https://developer.chrome.com/docs/extensions/reference/manifest

Minimal service-worker background script that declares only the APIs it uses:

```js
// background.js — MV3 service worker
// Only import local modules bundled with the extension.
import { handleMessage } from './message-handler.js';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Validate sender to reject messages from unexpected origins.
  if (!sender.tab || sender.tab.url.startsWith('chrome-extension://')) {
    handleMessage(message, sendResponse);
    return true; // keep channel open for async response
  }
});

// Use declarativeNetRequest instead of blocking webRequest.
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [
    {
      id: 1,
      priority: 1,
      action: { type: 'block' },
      condition: { urlFilter: '||ads.example.com', resourceTypes: ['script'] }
    }
  ],
  removeRuleIds: []
});
```

- No remote `import()` or `fetch()+eval()` calls.
- Uses `chrome.declarativeNetRequest` (MV3 replacement for blocking webRequest).
- Sender origin is validated before processing messages.

Source: https://developer.chrome.com/docs/extensions/mv3/intro/mv3-overview

## Fix recipes

### Recipe: Tighten broad host_permissions to specific origins — addresses CWE-732

**Before (dangerous):**

```json
{
  "manifest_version": 3,
  "host_permissions": ["<all_urls>"]
}
```

**After (safe):**

```json
{
  "manifest_version": 3,
  "host_permissions": [
    "https://api.example.com/*",
    "https://login.example.com/*"
  ]
}
```

Enumerate only the origins the extension genuinely needs. If the set of origins is user-configurable, request `activeTab` permission at the time of user action instead of broad `host_permissions`.

Source: https://developer.chrome.com/docs/extensions/reference/manifest

### Recipe: Replace unsafe-eval CSP with strict CSP — addresses CWE-94

**Before (dangerous):**

```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'unsafe-eval'; object-src 'self';"
  }
}
```

**After (safe):**

```json
{
  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; object-src 'none';"
  }
}
```

Replace any use of `eval()`, `new Function()`, or `setTimeout(string, …)` in extension pages with equivalent static code paths. Bundlers (esbuild, webpack) eliminate the need for runtime `eval` in virtually all production use cases.

Source: https://developer.chrome.com/docs/extensions/mv3/xhr/

### Recipe: Replace remote CDN script with bundled local asset — addresses CWE-829

**Before (dangerous):**

```html
<!-- popup.html — fetches library from a remote CDN at runtime -->
<script src="https://cdn.jsdelivr.net/npm/some-library@3/dist/lib.min.js"></script>
```

**After (safe):**

```html
<!-- popup.html — uses a locally bundled copy -->
<script src="vendor/some-library.min.js"></script>
```

Download and vendor the library into the extension package at build time (e.g. via `npm run build` with a bundler). Pin the version in `package.json` and verify the file hash in your CI pipeline. This satisfies the Chrome Web Store prohibition on remotely hosted code and eliminates CDN supply-chain risk.

Source: https://developer.chrome.com/docs/extensions/mv3/xhr/

## Version notes

- MV2 extensions were phased out from the Chrome Web Store starting June 2024; existing MV2 extensions stop working in Chrome enterprise/managed environments on a separate timeline announced at developer.chrome.com. Treat any `manifest_version: 2` finding as a mandatory migration, not just a security advisory.
- `chrome.webRequest` blocking mode is available only to extensions force-installed via enterprise policy (`POLICY_INSTALLED`); all other MV3 extensions must use `chrome.declarativeNetRequest`.
- The `content_security_policy` manifest key in MV3 takes an object with `extension_pages` (and optionally `sandbox`) sub-keys, not a bare string as in MV2.
- `externally_connectable` was introduced in MV2 and carries over to MV3; its `matches` array should always be scoped to the minimum set of web origins that legitimately need to message the extension.

## Common false positives

- `"*://*/*"` in `host_permissions` — not a false positive; always flag. The exception is extensions explicitly designed as universal request interceptors (e.g. privacy proxies) where the broad permission is intentional, but even then it warrants documentation and review.
- `unsafe-eval` grep in `manifest.json` — can match string values in unrelated fields (e.g. a description mentioning the word); confirm the match is inside the `content_security_policy.extension_pages` value.
- `webRequest.onBeforeRequest` without `["blocking"]` — safe; only the `["blocking"]` extra-info string triggers the removed API. Passive listeners (e.g. for logging) are still supported in MV3.
- Remote `fetch()` calls in `background.js` — fetching data from an API endpoint is fine; the prohibition is on fetching and then executing the response as code (`eval`, `new Function`, dynamic `<script>` injection). Flag only when `fetch` result flows into an execution sink.
