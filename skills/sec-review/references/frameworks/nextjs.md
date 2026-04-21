# Next.js

## Source

- https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
- https://nextjs.org/docs/pages/building-your-application/data-fetching/get-server-side-props
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Next.js 13+ (App Router and Pages Router), including Server Actions,
API Routes, `fetch()` in server components, and the `next/image` component.
Does not cover Vercel-specific edge middleware beyond what Next.js documents,
or React Native / Expo.

## Dangerous patterns (regex/AST hints)

### SSRF via server-side fetch with user-controlled URL — CWE-918

- Why: `fetch(userInput)` or `fetch(req.query.url)` in a Server Component or API Route allows attackers to probe internal services (metadata APIs, databases, localhost).
- Grep: `fetch\(.*req\.(query|body|params)|fetch\(.*searchParams\.get|fetch\(.*params\[`
- File globs: `**/app/**/*.ts`, `**/app/**/*.tsx`, `**/pages/api/**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### dangerouslySetInnerHTML with user data — CWE-79

- Why: Injecting user-controlled strings into `dangerouslySetInnerHTML` bypasses React's escaping and enables DOM XSS.
- Grep: `dangerouslySetInnerHTML\s*=\s*\{\{.*__html.*req\.|dangerouslySetInnerHTML.*params\.|dangerouslySetInnerHTML.*searchParams`
- File globs: `**/*.tsx`, `**/*.jsx`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Leaking secrets via NEXT_PUBLIC_ prefix — CWE-200

- Why: Any environment variable prefixed `NEXT_PUBLIC_` is inlined into client bundles and visible in browser source; API keys, tokens, and internal URLs must never use this prefix.
- Grep: `NEXT_PUBLIC_.*KEY|NEXT_PUBLIC_.*SECRET|NEXT_PUBLIC_.*TOKEN|NEXT_PUBLIC_.*PASSWORD`
- File globs: `**/.env*`, `**/next.config.*`
- Source: https://nextjs.org/docs/app/building-your-application/configuring/environment-variables

### Missing CSRF protection on Server Actions / API Routes — CWE-352

- Why: Next.js does not add automatic CSRF tokens to API Routes or (prior to 14.x) Server Actions; state-changing endpoints accepting cookies must validate origin or use CSRF tokens.
- Grep: `export\s+(default\s+)?async\s+function\s+(POST|PUT|DELETE|PATCH)|"use server"`
- File globs: `**/pages/api/**/*.ts`, `**/app/**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/CSRF_Prevention_Cheat_Sheet.html

### Image remotePatterns open redirect / SSRF — CWE-601

- Why: Setting `remotePatterns` with broad wildcards (e.g., `hostname: "**"`) in `next.config.js` allows the image optimization proxy to fetch and proxy arbitrary URLs.
- Grep: `hostname\s*:\s*["']\*\*?["']|remotePatterns.*hostname.*\*`
- File globs: `**/next.config.*`
- Source: https://nextjs.org/docs/app/api-reference/components/image#remotepatterns

### getServerSideProps with unsanitized user input in DB/FS calls — CWE-89

- Why: `context.params` and `context.query` values used directly in database queries or file reads in `getServerSideProps` are attacker-controlled.
- Grep: `getServerSideProps.*context\.params|getServerSideProps.*context\.query`
- File globs: `**/pages/**/*.tsx`, `**/pages/**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Secure patterns

```typescript
// SSRF prevention: allowlist URL origins before fetching
const ALLOWED_ORIGINS = ["https://api.example.com"];

function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_ORIGINS.includes(parsed.origin);
  } catch {
    return false;
  }
}

// In Server Component or API Route:
if (!isSafeUrl(userProvidedUrl)) {
  return Response.json({ error: "Forbidden" }, { status: 403 });
}
const data = await fetch(userProvidedUrl);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

```javascript
// next.config.js — restrictive remotePatterns
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "assets.example.com",
        pathname: "/images/**",
      },
    ],
  },
};
```

Source: https://nextjs.org/docs/app/api-reference/components/image#remotepatterns

## Fix recipes

### Recipe: Allowlist fetch URLs to prevent SSRF — addresses CWE-918

**Before (dangerous):**

```typescript
const res = await fetch(req.query.url as string);
```

**After (safe):**

```typescript
const allowed = ["https://api.example.com"];
const target = req.query.url as string;
const origin = new URL(target).origin;
if (!allowed.includes(origin)) {
  return res.status(403).json({ error: "Forbidden URL" });
}
const data = await fetch(target);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Recipe: Replace dangerouslySetInnerHTML with safe rendering — addresses CWE-79

**Before (dangerous):**

```tsx
<div dangerouslySetInnerHTML={{ __html: userComment }} />
```

**After (safe):**

```tsx
// Use a sanitizer library (DOMPurify) if HTML is required,
// or plain text rendering if not:
<div>{userComment}</div>
// For rich HTML: import DOMPurify; __html: DOMPurify.sanitize(userComment)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### Recipe: Move secret env vars off NEXT_PUBLIC_ prefix — addresses CWE-200

**Before (dangerous):**

```bash
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
```

**After (safe):**

```bash
STRIPE_SECRET_KEY=sk_live_...   # server-only; no NEXT_PUBLIC_ prefix
```

Source: https://nextjs.org/docs/app/building-your-application/configuring/environment-variables

### Recipe: Restrict next/image remotePatterns — addresses CWE-601

**Before (dangerous):**

```javascript
images: { remotePatterns: [{ hostname: "**" }] }
```

**After (safe):**

```javascript
images: {
  remotePatterns: [
    { protocol: "https", hostname: "cdn.example.com", pathname: "/media/**" }
  ]
}
```

Source: https://nextjs.org/docs/app/api-reference/components/image#remotepatterns

## Version notes

- Next.js 14+: Server Actions automatically include CSRF protection via `Origin` header validation for same-origin requests; API Routes do not get this protection and still require explicit CSRF handling.
- Next.js 13 App Router: Server Components run on the server but any data passed to Client Components via props may be serialized into the HTML payload — avoid passing secrets as props.
- `getServerSideProps` is Pages Router only; App Router uses `async` Server Components and `searchParams` prop — same injection risks apply.

## Common false positives

- `dangerouslySetInnerHTML` used with a DOMPurify-sanitized string or a fully static developer-owned HTML constant — safe if no user data path exists.
- `NEXT_PUBLIC_` variables exposing only truly public, non-secret configuration (e.g., `NEXT_PUBLIC_SITE_URL`) — not a finding; only flag when the value is a secret or internal address.
- `fetch()` in server components calling a developer-owned, hardcoded URL with no user-controlled segments — not SSRF.
