# WebExtension Shared Security Patterns (Chrome MV3 / Firefox MV2+MV3)

## Source

- https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage — MDN postMessage API
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts — MDN WebExtensions Content Scripts
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage — MDN WebExtensions Storage API
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/sendMessage — MDN runtime.sendMessage
- https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity — MDN Subresource Integrity
- https://developer.chrome.com/docs/extensions/mv3/content_scripts/ — Chrome MV3 Content Scripts
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — OWASP DOM-based XSS Prevention Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — OWASP XSS Prevention Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html — OWASP HTML5 Security Cheat Sheet

## Scope

In scope: cross-browser WebExtension patterns — messaging, storage, content-script DOM interaction, dynamic code execution, and remote resource loading — that apply equally to Chrome MV3 and Firefox MV2/MV3. Out of scope: Chrome-specific manifest keys such as `action`, `declarativeNetRequest`, or `service_worker` (covered by `webext-chrome-mv3.md`); Firefox AMO-specific policies, review criteria, and `browser_specific_settings` requirements (covered by `webext-firefox-amo.md`).

## Dangerous patterns (regex/AST hints)

### Content-script DOM XSS via innerHTML / outerHTML / document.write — CWE-79

- Why: Assigning page-origin data (e.g. `document.title`, DOM text nodes, injected variables) to `innerHTML`, `outerHTML`, or `document.write` in a content script parses and executes embedded HTML/JS with extension privileges in the page context.
- Grep: `\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(`
- File globs: `**/content_scripts/**/*.{js,ts}`, `**/*content*.{js,ts}`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Secret leakage in chrome.storage.local / browser.storage.local — CWE-312

- Why: `storage.local` is persisted to disk in plaintext and readable by any code running in the extension origin; storing tokens, API keys, or passwords there exposes them if the profile directory is compromised or the extension is inspected.
- Grep: `storage\.local\.set\s*\(\s*\{\s*(token|api[_-]?key|secret|password)`
- File globs: `**/*.{js,ts}`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage

### postMessage without origin check — CWE-346

- Why: A `message` event listener that does not validate `event.origin` will process messages from any frame or window, including attacker-controlled pages, allowing cross-origin command injection into the extension's content script.
- Grep: `addEventListener\s*\(\s*['"\`]message['"\`]`
- File globs: `**/*.{js,ts}`
- Source: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

### runtime.sendMessage / runtime.onMessage without sender validation — CWE-346

- Why: An `onMessage` handler that does not check `sender.id` or `sender.url` will accept messages from any extension or web page that can call `runtime.sendMessage`, enabling privilege escalation from a compromised tab or a third-party extension.
- Grep: `runtime\.onMessage\.addListener`
- File globs: `**/*.{js,ts}`
- Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/sendMessage

### eval / new Function / Function — dynamic code execution — CWE-95

- Why: Executing dynamically constructed strings as code is prohibited by MV3's default CSP (`script-src 'self'`), violates AMO policy, and creates arbitrary code execution sinks if any input is attacker-influenced.
- Grep: `\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(`
- File globs: `**/*.{js,ts}`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Remote script loading via <script src="https?://"> or dynamic import — CWE-829

- Why: Loading scripts from remote origins at runtime bypasses the extension's bundled integrity guarantees, introduces a live dependency on an external server, and violates MV3's CSP which disallows remotely hosted code.
- Grep: `<script\s[^>]*src=["']https?://|import\s*\(\s*['"\`]https?://`
- File globs: `**/*.{js,ts}`, `**/*.html`
- Source: https://developer.chrome.com/docs/extensions/mv3/content_scripts/

### Bundled libs loaded remotely without Subresource Integrity — CWE-494

- Why: When an extension page loads a third-party library via a `blob:` URL or a `<script src>` pointing to a CDN rather than checking it into the bundle, there is no integrity guarantee; a CDN compromise silently delivers malicious code. Low severity when code is fully bundled; flag only when loading is demonstrably remote.
- Grep: `<script\s[^>]*src=["']https?://[^"']+["'][^>]*>(?![^<]*integrity)`
- File globs: `**/*.html`
- Source: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

### Overly broad permissions at install — CWE-250

- Why: Declaring all permissions in `permissions` (required at install) rather than in `optional_permissions` with `permissions.request()` at point-of-need grants unnecessary access for the lifetime of the extension, increasing blast radius if the extension is compromised.
- Grep: `"permissions"\s*:\s*\[`
- File globs: `**/manifest.json`
- Source: https://developer.chrome.com/docs/extensions/mv3/content_scripts/

## Secure patterns

Safe DOM insertion in content scripts — use `textContent` for plain strings or a DOMPurify wrapper for HTML fragments:

```js
// Safe: textContent never parses HTML
function setLabel(element, userText) {
  element.textContent = userText;
}

// Safe: DOMPurify sanitizes before insertion when HTML is genuinely required
import DOMPurify from 'dompurify';
function setRichContent(element, htmlFragment) {
  element.innerHTML = DOMPurify.sanitize(htmlFragment, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

postMessage handler with explicit origin allowlist:

```js
const ALLOWED_ORIGINS = new Set(['https://example.com', 'https://app.example.com']);

window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.has(event.origin)) {
    return; // silently ignore unexpected origins
  }
  // safe to process event.data
  handleMessage(event.data);
});
```

Source: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

runtime.onMessage handler that validates the sender is this extension:

```js
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Accept only messages originating from this extension's own pages/content scripts
  if (sender.id !== browser.runtime.id) {
    return false; // reject external senders
  }
  // safe to dispatch message
  dispatch(message);
});
```

Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/sendMessage

## Fix recipes

### Recipe: Replace innerHTML with textContent / sanitize — addresses CWE-79

**Before (dangerous):**

```js
// content_scripts/inject.js
const label = document.createElement('div');
label.innerHTML = document.title;        // page controls document.title
document.body.appendChild(label);
```

**After (safe):**

```js
// content_scripts/inject.js
const label = document.createElement('div');
label.textContent = document.title;      // no HTML parsing; entities rendered literally
document.body.appendChild(label);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Recipe: Add origin check to postMessage handler — addresses CWE-346

**Before (dangerous):**

```js
window.addEventListener('message', (event) => {
  // No origin check — processes messages from any window
  if (event.data.type === 'LOAD_CONFIG') {
    applyConfig(event.data.payload);
  }
});
```

**After (safe):**

```js
const ALLOWED_ORIGINS = new Set(['https://example.com']);

window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.has(event.origin)) {
    return;
  }
  if (event.data.type === 'LOAD_CONFIG') {
    applyConfig(event.data.payload);
  }
});
```

Source: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

### Recipe: Move secret from storage.local to in-memory session state via OAuth — addresses CWE-312

**Before (dangerous):**

```js
// Persists token to disk in plaintext
chrome.storage.local.set({ token: oauthToken });

// Later retrieval also from disk
chrome.storage.local.get('token', ({ token }) => makeApiCall(token));
```

**After (safe):**

```js
// Keep token only in memory for the lifetime of the service worker / background page.
// Use chrome.identity / browser.identity to obtain tokens on demand via OAuth;
// the browser manages secure token caching internally.
let sessionToken = null;

async function getToken() {
  if (sessionToken) return sessionToken;
  // chrome.identity.getAuthToken handles secure storage; token is not written to disk by the extension
  sessionToken = await new Promise((resolve, reject) =>
    chrome.identity.getAuthToken({ interactive: true }, (token) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(token)
    )
  );
  return sessionToken;
}

// On extension unload / user sign-out, revoke and clear the in-memory reference
function clearSession() {
  if (sessionToken) chrome.identity.removeCachedAuthToken({ token: sessionToken });
  sessionToken = null;
}
```

Source: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage

## Version notes

- Chrome MV3 enforces `script-src 'self'` in extension pages by default; `eval` and `new Function` are blocked at the browser level regardless of code review findings. Flag them anyway because Firefox MV2 extensions do not share this restriction.
- Firefox MV2 extensions may still use a relaxed `content_security_policy` key; check the manifest before downgrading eval findings.
- `browser.storage.session` (available in Chrome 102+ and Firefox 115+) provides an in-memory storage area that is cleared on browser restart and is not persisted to disk — prefer it over `storage.local` for transient auth state when the `identity` API is unavailable.
- The `optional_permissions` + `permissions.request()` pattern is supported in both Chrome MV3 and Firefox MV2/MV3 and should be preferred for sensitive host permissions.

## Common false positives

- `storage.local.set` with `{ token: ... }` — lower risk if the value is a non-sensitive session identifier (e.g. a random nonce) rather than a bearer token or password; review what is actually stored.
- `runtime.onMessage.addListener` without an explicit `sender.id` check — acceptable when the handler only responds to internal content-script messages and the extension has no externally connectable origins declared in the manifest.
- `addEventListener('message', ...)` — reduced risk when the listener is in a background service worker (which has no `window`) and the code path is reached only via `chrome.runtime` internals; verify the execution context.
- `new Function(...)` — flag for review regardless; the MV3 CSP blocks it in Chrome extension pages, but the pattern may still execute in content scripts running in the page's world.
- `"permissions": [` — the presence of the key is not itself a finding; triage by examining the listed permissions for overly broad host patterns (`<all_urls>`, `*://*/*`) or sensitive APIs (`tabs`, `webRequest`, `cookies`, `nativeMessaging`).
