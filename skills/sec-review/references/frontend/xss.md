# Cross-Site Scripting (XSS)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — OWASP XSS Prevention Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — OWASP DOM-based XSS Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection)
- https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#cross-site_scripting_xss — MDN XSS

## Scope

Covers stored, reflected, and DOM-based XSS in web applications. Applies to raw HTML generation in server-side templates, client-side JavaScript sinks, and frontend frameworks (React, Vue, Angular, jQuery). Does not cover server-side template injection (SSTI) or mutation XSS (mXSS) in legacy browsers.

## Dangerous patterns (regex/AST hints)

### innerHTML assignment — CWE-79

- Why: Assigning attacker-controlled data to `innerHTML` parses and executes embedded HTML/JS.
- Grep: `\.innerHTML\s*=`
- File globs: `**/*.js`, `**/*.ts`, `**/*.jsx`, `**/*.tsx`, `**/*.html`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### document.write with dynamic data — CWE-79

- Why: `document.write` with non-literal arguments injects raw HTML into the document parser.
- Grep: `document\.write\s*\(`
- File globs: `**/*.js`, `**/*.ts`, `**/*.html`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### eval / Function constructor with dynamic input — CWE-79

- Why: Executing attacker-controlled strings as code enables arbitrary script execution.
- Grep: `\beval\s*\(|new\s+Function\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### React dangerouslySetInnerHTML — CWE-79

- Why: Opt-in HTML injection bypass in React; safe only when content is sanitized by a trusted library.
- Grep: `dangerouslySetInnerHTML`
- File globs: `**/*.jsx`, `**/*.tsx`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### Vue v-html directive — CWE-79

- Why: Renders raw HTML; equivalent to `innerHTML` injection if the bound value is user-controlled.
- Grep: `v-html`
- File globs: `**/*.vue`, `**/*.html`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### Angular bypassSecurityTrust* — CWE-79

- Why: Disables Angular's built-in sanitization; use only with sanitized, static content.
- Grep: `bypassSecurityTrust`
- File globs: `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Secure patterns

Output encoding must be context-aware. Apply the correct encoder for the output context:

```
// HTML body context — encode for HTML entities
element.textContent = userInput;           // safe: no HTML parsing

// HTML attribute context
element.setAttribute('title', userInput);  // safe via DOM API

// JavaScript string context — use JSON.stringify or a trusted encoder
const json = JSON.stringify(userInput);    // safe for embedding in <script>

// URL context — encode with encodeURIComponent
const url = '/search?q=' + encodeURIComponent(userInput);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

```
// React — use JSX expression syntax, NOT dangerouslySetInnerHTML
function UserComment({ text }) {
  return <p>{text}</p>;   // React auto-escapes text nodes
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

```
// Server-side: use template engines with auto-escaping enabled
// Example: Jinja2 (Python) — auto-escape on by default for .html templates
render_template('page.html', username=username)
// Nunjucks: autoescape: true in environment config
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace innerHTML with textContent — addresses CWE-79

**Before (dangerous):**

```js
// Attacker-controlled `comment` renders embedded HTML
div.innerHTML = comment;
```

**After (safe):**

```js
// textContent never parses HTML; entities are displayed literally
div.textContent = comment;
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Recipe: Remove dangerouslySetInnerHTML — addresses CWE-79

**Before (dangerous):**

```jsx
<div dangerouslySetInnerHTML={{ __html: userBio }} />
```

**After (safe):**

```jsx
// If rich text is required, sanitize first with a maintained library
// (DOMPurify) then set via ref — never trust raw user input here.
<div>{userBio}</div>
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### Recipe: Replace eval with safe alternative — addresses CWE-79

**Before (dangerous):**

```js
const result = eval(userExpression);
```

**After (safe):**

```js
// Parse and validate as structured data; never eval user strings
const result = JSON.parse(userExpression);  // only if expecting JSON
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Recipe: Replace jQuery .html() with .text() — addresses CWE-79

**Before (dangerous):**

```js
$('#output').html(userInput);
```

**After (safe):**

```js
$('#output').text(userInput);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Version notes

- Angular versions >= 2 have built-in sanitization; `bypassSecurityTrust*` is only dangerous when called with user data.
- React 18+ still requires developers to opt out of auto-escaping via `dangerouslySetInnerHTML`; no change in behavior from React 16/17.
- Vue 3 `v-html` is equally dangerous as Vue 2; no sanitization was added.
- jQuery >= 3.5.0 changed `.html()` parsing to mitigate some mXSS vectors, but the API still executes `<script>` tags.

## Common false positives

- `innerHTML` — usually safe when the assigned value is a hard-coded string literal with no variable interpolation.
- `dangerouslySetInnerHTML` — reduced risk when the value is the output of a pinned, audited sanitizer (e.g. DOMPurify with a restrictive allowlist) and the sanitizer output is not further mutated.
- `eval` — usually safe when called with a compile-time constant string (e.g. `eval('(' + JSON_LITERAL + ')')` in pre-ES5 compatibility shims), but still flag for manual review.
- `document.write` — usually safe when called only during initial page load with a static string (e.g. legacy `<script>` loaders), but any dynamic data warrants review.
