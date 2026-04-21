# Content Security Policy (CSP)

## Source

- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP — MDN Content Security Policy
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy — MDN CSP Header reference
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html — OWASP CSP Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A05:2021 Security Misconfiguration)

## Scope

Covers the `Content-Security-Policy` HTTP response header and the `<meta http-equiv>` equivalent for web applications. Applies to CSP Level 2 and CSP Level 3 directives. Does not cover Trusted Types (covered separately) or feature policy / permissions policy.

## Dangerous patterns (regex/AST hints)

### unsafe-inline in script-src — CWE-693

- Why: Allows execution of all inline scripts; negates XSS protection entirely.
- Grep: `script-src[^;'"]*'unsafe-inline'`
- File globs: `**/*.conf`, `**/*.nginx`, `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.java`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### unsafe-eval in script-src — CWE-693

- Why: Permits `eval()`, `Function()`, `setTimeout(string)`, etc.; undermines script execution control.
- Grep: `script-src[^;'"]*'unsafe-eval'`
- File globs: `**/*.conf`, `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### CSP delivered via meta tag only — CWE-693

- Why: `<meta>` CSP does not support `frame-ancestors`, `report-uri`, or sandboxing; provides weaker protection than the HTTP header.
- Grep: `http-equiv=.Content-Security-Policy`
- File globs: `**/*.html`, `**/*.htm`, `**/*.jsx`, `**/*.tsx`
- Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

### Wildcard (*) in script-src or default-src — CWE-693

- Why: A bare wildcard allows scripts from any origin; equivalent to having no policy.
- Grep: `(?:script-src|default-src)\s+[^;]*\*`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.js`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### Missing report-uri / report-to directive — CWE-693

- Why: Without a reporting endpoint, CSP violations are silently discarded; no visibility into policy bypasses.
- Grep: `Content-Security-Policy` (absence check — grep for header lines lacking `report`)
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

## Secure patterns

Strict CSP using nonces (CSP Level 3, preferred for dynamic pages):

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random128bit}' 'strict-dynamic';
  style-src 'nonce-{random128bit}';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  report-to csp-endpoint;
```

- Nonce must be cryptographically random (>=128 bits), unique per response.
- `strict-dynamic` propagates trust to dynamically added scripts; no host allowlists needed.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

Hash-based CSP for fully static pages:

```
Content-Security-Policy:
  script-src 'sha256-<base64-hash-of-script-content>';
  ...
```

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

Reporting endpoint configuration (CSP Level 3 `report-to`):

```
Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"
Content-Security-Policy: ...; report-to csp-endpoint
```

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

## Fix recipes

### Recipe: Replace unsafe-inline with nonces — addresses CWE-693

**Before (dangerous):**

```
Content-Security-Policy: script-src 'self' 'unsafe-inline';
```

**After (safe):**

```
# Per-request: generate a cryptographically random nonce
Content-Security-Policy: script-src 'nonce-RANDOM128' 'strict-dynamic'; base-uri 'none';

# All inline scripts must carry the matching nonce attribute:
<script nonce="RANDOM128">/* inline script */</script>
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### Recipe: Replace wildcard default-src — addresses CWE-693

**Before (dangerous):**

```
Content-Security-Policy: default-src *;
```

**After (safe):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-RANDOM128' 'strict-dynamic';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### Recipe: Move CSP from meta tag to HTTP header — addresses CWE-693

**Before (weaker):**

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

**After (safe):**

```
# Deliver via server response header (nginx example):
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;
```

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

## Version notes

- `report-uri` is deprecated in CSP Level 3 in favor of `report-to`; include both during transition for browser compatibility.
- `strict-dynamic` is CSP Level 3; browsers that do not support it fall back to the allowlist. Include `'self'` as a fallback for Level 2 browsers.
- `frame-ancestors` in a `<meta>` tag is ignored by all browsers; it must be in the HTTP header.

## Common false positives

- `'unsafe-inline'` — lower risk when a nonce or hash is also present in the same directive; CSP Level 3 browsers ignore `'unsafe-inline'` when a valid nonce/hash is present.
- `'unsafe-eval'` — sometimes required by bundler tooling (e.g. webpack dev server, some Angular JIT compilation modes); flag in production configs only.
- Wildcard `*` in `img-src` or `media-src` — generally acceptable; images do not execute code.
