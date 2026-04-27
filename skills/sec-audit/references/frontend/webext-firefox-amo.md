# Firefox WebExtensions — AMO Distribution

## Source

- https://extensionworkshop.com/documentation/publish/add-on-policies/ — Firefox Add-on Policies (AMO)
- https://extensionworkshop.com/documentation/develop/build-a-secure-extension/ — Build a Secure Extension (Extension Workshop)
- https://extensionworkshop.com/documentation/develop/manifest-v3-migration-guide/ — MV3 Migration Guide (Extension Workshop)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json — WebExtensions manifest.json (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings — manifest.json/browser_specific_settings (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_security_policy — manifest.json/content_security_policy (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/web_accessible_resources — manifest.json/web_accessible_resources (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions — manifest.json/permissions (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/host_permissions — manifest.json/host_permissions (MDN)
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/optional_permissions — manifest.json/optional_permissions (MDN)

## Scope

Covers WebExtensions targeting Firefox (desktop and Android) for distribution through addons.mozilla.org (AMO), including both MV2 extensions (still accepted by Firefox) and MV3 extensions. In scope: manifest.json field validation, content script permissions, background script patterns, content security policy enforcement, and AMO reviewer-facing policy requirements such as remote code execution prohibition, obfuscation rejection, and data-collection consent rules. Out of scope: Chrome MV3 specifics (covered by `webext-chrome-mv3.md`) and cross-browser compatibility patterns (covered by `webext-shared-patterns.md`).

## Dangerous patterns (regex/AST hints)

### Missing gecko.id in browser_specific_settings  — CWE-1104 / AMO policy

- Why: AMO requires a stable `browser_specific_settings.gecko.id` for all listed add-ons. Without it, AMO cannot associate the submitted XPI with an existing listing, and updates will be rejected at review time.
- Grep: `"browser_specific_settings"` absent entirely, or present without a nested `"id"` key — check with `grep -L "gecko" manifest.json` or `grep -A5 "gecko" manifest.json | grep -v "id"`
- File globs: `manifest.json`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings

### Remote script loading / remote code execution  — CWE-829

- Why: AMO policy explicitly prohibits extensions from loading or executing code from remote locations. This includes `<script src="https://...">` in extension HTML pages, `eval()`, `new Function(...)`, bare `Function(...)` calls with dynamic arguments, and dynamic `import('https://...')` calls. Any such pattern is an automatic rejection at AMO review.
- Grep: `<script[^>]+src=["']https?://|eval\s*\(|new\s+Function\s*\(|[^.]\bFunction\s*\(|import\s*\(\s*["']https?://`
- File globs: `**/*.js`, `**/*.ts`, `**/*.html`, `**/*.htm`
- Source: https://extensionworkshop.com/documentation/publish/add-on-policies/

### Obfuscated code  — AMO policy (CWE-506 adjacent)

- Why: AMO policy prohibits intentionally obfuscated code. Reviewers flag bundles using `javascript-obfuscator` (identifiable by the `_0x` hex-identifier pattern in bulk, or by the tool's own header comment), as well as any code where meaningful symbol names have been replaced with hex-encoded or random short names making the extension's intent unverifiable.
- Grep: `_0x[0-9a-fA-F]{4,}\b` (bulk hex identifiers) or `javascript-obfuscator` in any source comment or `package.json` script
- File globs: `**/*.js`, `**/*.ts`, `package.json`
- Source: https://extensionworkshop.com/documentation/publish/add-on-policies/

### Permissions overreach  — CWE-250

- Why: Requesting `"<all_urls>"`, `"tabs"`, or `"cookies"` in the static `permissions` array without documented justification violates least-privilege. AMO reviewers scrutinize broad permissions; prefer `"activeTab"` for single-page interaction and move non-essential permissions to `optional_permissions` with a runtime prompt.
- Grep: `"<all_urls>"|"tabs"|"cookies"|"webRequest"|"history"|"bookmarks"` inside a `"permissions"` array
- File globs: `manifest.json`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions

### web_accessible_resources exposing internals to any origin  — CWE-200 / CWE-732

- Why: Listing extension-internal pages or scripts under `web_accessible_resources` with `"matches": ["<all_urls>"]` (MV3) or with no origin restriction (MV2) allows any web page to embed or probe those resources, leaking implementation details and enabling extension fingerprinting or UI-redressing attacks.
- Grep: `"<all_urls>"` inside a `web_accessible_resources` block, or a top-level `web_accessible_resources` array (MV2) with no accompanying origin check
- File globs: `manifest.json`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/web_accessible_resources

### MV3 CSP with unsafe-eval / unsafe-inline / wasm-unsafe-eval  — CWE-94

- Why: Firefox MV3 enforces a strict default CSP for extension pages (`default-src 'self'`). Explicitly setting `content_security_policy.extension_pages` to include `'unsafe-eval'`, `'unsafe-inline'`, or `'wasm-unsafe-eval'` weakens that default and is flagged by AMO reviewers. `'unsafe-eval'` in particular re-enables the `eval`-family sinks that the default CSP blocks.
- Grep: `unsafe-eval|unsafe-inline|wasm-unsafe-eval` inside a `content_security_policy` value
- File globs: `manifest.json`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_security_policy

### Data collection without user consent  — CWE-359 / AMO policy

- Why: AMO policy requires that extensions collecting personal data do so only with explicit, informed, prior user consent presented in the extension's own UI (not buried in a remote privacy policy URL). Network calls to analytics or telemetry endpoints that fire before any consent prompt are a policy violation and a rejection reason.
- Grep: `fetch\s*\(|XMLHttpRequest|navigator\.sendBeacon\s*\(` combined with analytics/telemetry hostnames such as `google-analytics\.com|analytics\.|telemetry\.|mixpanel\.|segment\.io`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://extensionworkshop.com/documentation/publish/add-on-policies/

## Secure patterns

Minimal AMO-conformant MV3 `manifest.json` with a stable gecko ID, narrow permissions, strict CSP, and origin-restricted web-accessible resources:

```json
{
  "manifest_version": 3,
  "name": "My Extension",
  "version": "1.0.0",
  "browser_specific_settings": {
    "gecko": {
      "id": "my-extension@example.com",
      "strict_min_version": "109.0"
    }
  },
  "permissions": ["activeTab", "storage"],
  "optional_permissions": ["tabs"],
  "host_permissions": [],
  "background": {
    "scripts": ["background.js"]
  },
  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; object-src 'none'"
  },
  "web_accessible_resources": [
    {
      "resources": ["icons/icon48.png"],
      "matches": ["https://example.com/*"]
    }
  ]
}
```

Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings

Consent prompt pattern — gate any analytics call behind an explicit opt-in stored in `browser.storage.sync` before any network call fires:

```js
// background.js — check consent before sending telemetry
async function maybeSendTelemetry(event) {
  const { analyticsConsent } = await browser.storage.sync.get("analyticsConsent");
  if (analyticsConsent !== true) {
    return; // no data sent until user opts in
  }
  // only reached after explicit user opt-in
  await fetch("https://telemetry.example.com/event", {
    method: "POST",
    body: JSON.stringify(event),
  });
}

// Called from the options page after user ticks the consent checkbox:
// await browser.storage.sync.set({ analyticsConsent: true });
```

Source: https://extensionworkshop.com/documentation/publish/add-on-policies/

## Fix recipes

### Recipe: Add browser_specific_settings.gecko.id  — addresses AMO policy / CWE-1104

**Before (dangerous):**

```json
{
  "manifest_version": 2,
  "name": "My Extension",
  "version": "1.0.0",
  "permissions": ["activeTab"]
}
```

**After (safe):**

```json
{
  "manifest_version": 2,
  "name": "My Extension",
  "version": "1.0.0",
  "browser_specific_settings": {
    "gecko": {
      "id": "my-extension@example.com",
      "strict_min_version": "91.0"
    }
  },
  "permissions": ["activeTab"]
}
```

Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings

### Recipe: Replace remote script with bundled local asset  — addresses CWE-829

**Before (dangerous):**

```html
<!-- popup.html — loads a third-party library from a CDN -->
<!DOCTYPE html>
<html>
  <head>
    <script src="https://cdn.example.com/lib/jquery-3.7.1.min.js"></script>
  </head>
  <body>
    <script src="popup.js"></script>
  </body>
</html>
```

**After (safe):**

```html
<!-- popup.html — library vendored into the extension package -->
<!DOCTYPE html>
<html>
  <head>
    <!-- jquery-3.7.1.min.js copied into vendor/ at build time -->
    <script src="vendor/jquery-3.7.1.min.js"></script>
  </head>
  <body>
    <script src="popup.js"></script>
  </body>
</html>
```

All third-party scripts must be included in the submitted ZIP/XPI. The `content_security_policy` must not add any remote `script-src` origin.

Source: https://extensionworkshop.com/documentation/publish/add-on-policies/

### Recipe: Move broad permission to optional_permissions with runtime request  — addresses CWE-250

**Before (dangerous):**

```json
// manifest.json — "tabs" granted at install time for all users
{
  "manifest_version": 3,
  "permissions": ["activeTab", "tabs", "storage"]
}
```

**After (safe):**

```json
// manifest.json — "tabs" moved to optional; only requested when needed
{
  "manifest_version": 3,
  "permissions": ["activeTab", "storage"],
  "optional_permissions": ["tabs"]
}
```

```js
// In the feature that actually needs "tabs" — request at point of use
async function getTabList() {
  const granted = await browser.permissions.request({ permissions: ["tabs"] });
  if (!granted) {
    // surface a user-facing message explaining why the feature is unavailable
    return [];
  }
  return browser.tabs.query({});
}
```

Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/optional_permissions

## Version notes

- MV2 remains accepted by Firefox (desktop and Android) as of 2026; AMO continues to list MV2 extensions. Firefox has no announced removal date for MV2 support. The MV3 migration guide is advisory, not mandatory, for existing listings.
- In MV3, `"host_permissions"` is a separate top-level key from `"permissions"`; combining host patterns inside `"permissions"` is a MV2 pattern and is silently accepted by Firefox MV3 but generates a warning in AMO's linter (`addons-linter`).
- The `content_security_policy` key changed shape between MV2 and MV3: MV2 accepts a plain string value; MV3 requires an object with sub-keys `extension_pages` and optionally `sandbox`. A plain string value in a MV3 manifest is ignored by Firefox, leaving the strict default in effect (which is safe but may surprise developers expecting a relaxed policy).
- `web_accessible_resources` in MV3 is an array of objects each with `"resources"` and `"matches"` keys; the MV2 format (a flat array of glob strings) has no per-resource origin restriction and should be migrated to the MV3 format even in MV2 extensions where possible, to reduce exposure.

## Common false positives

- `eval` in a vendored, unmodified third-party library (e.g. a minified polyfill under `vendor/`) — flag the presence for review, but the risk is in the library's own provenance, not the extension author's code; confirm the library version is not known-vulnerable.
- `_0x` hex identifiers produced by a tree-shaking bundler (e.g. Terser with `mangle: true`) on the developer's own code — Terser mangling is not the same as intentional obfuscation; AMO reviewers distinguish these when source maps and unminified sources are provided in the review package.
- `"tabs"` in `permissions` when the extension is a developer tool or tab-manager whose core feature inherently requires enumeration of all tabs — reviewers will accept this with a clear description; flag for human confirmation rather than auto-reject.
- `fetch()` calls to first-party endpoints (same domain as the extension publisher) that do not transmit personally identifiable user data — these are not data-collection violations; only flag when the destination is a known analytics/telemetry domain or when user browsing data (URLs, form content) is in the payload.
- `<script src="...">` where the `src` is a relative path (e.g. `src="popup.js"`) — the dangerous pattern targets `http://` or `https://` absolute URLs only; local relative paths are safe.
