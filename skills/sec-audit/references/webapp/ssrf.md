# Server-Side Request Forgery (SSRF)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — OWASP SSRF Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A10:2021 SSRF)
- https://cwe.mitre.org/data/definitions/918.html — CWE-918: Server-Side Request Forgery
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html — OWASP Input Validation Cheat Sheet

## Scope

Covers SSRF in server-side code that makes outbound HTTP/TCP requests using attacker-influenced URLs or hostnames. Applies to Python (`requests`, `urllib`, `httpx`), Node.js (`http.get`, `https.get`, `fetch`, `axios`), Java (`java.net.URL`, `HttpClient`, `RestTemplate`), and Go (`http.Get`, `http.NewRequest`). Does not cover blind SSRF via DNS (covered in network scan lane) or client-side `fetch` (see XSS pack).

## Dangerous patterns (regex/AST hints)

### Python requests.get/post with user-controlled URL — CWE-918

- Why: Passing an attacker-controlled URL to `requests` allows fetching internal resources (169.254.0.0/16, 10.0.0.0/8, localhost).
- Grep: `requests\.(get|post|put|delete|head|request)\s*\(\s*[^"'][^,)]*`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Python urllib.request.urlopen with variable — CWE-918

- Why: `urlopen` follows redirects by default; a redirect chain can reach internal addresses even if the initial URL is validated.
- Grep: `urlopen\s*\(\s*(?!["'])`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Node.js http/https.get or fetch with dynamic URL — CWE-918

- Why: `http.get` and `fetch` accept full URLs; with user-controlled hostnames the server becomes an open proxy.
- Grep: `(http|https)\.get\s*\(\s*[^"']|fetch\s*\(\s*[^"']`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Java URL / HttpClient with user-provided string — CWE-918

- Why: `new URL(userInput).openConnection()` will resolve and connect to any host including link-local and loopback.
- Grep: `new\s+URL\s*\(\s*(?!")[^)]+\)|HttpClient.*send\s*\(.*Request\.newBuilder\s*\(\s*URI\.create`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Go http.Get / http.NewRequest with dynamic URL — CWE-918

- Why: Go's `net/http` package will resolve DNS and connect without any IP-range filtering; cloud metadata endpoints are reachable.
- Grep: `http\.(Get|Post|NewRequest)\s*\(\s*(?:"[^"]*"\s*\+|[^"]+,)`
- File globs: `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Webhook / callback URL parameter — CWE-918

- Why: Parameters named `url`, `callback`, `webhook`, `endpoint`, `redirect_uri`, or `src` are common SSRF entry points when passed to an HTTP client.
- Grep: `params\[.*(url|callback|webhook|endpoint)\]|request\.(GET|POST|args)\[.*(url|callback|src)`
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`, `**/*.php`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Cloud metadata endpoint reachability — CWE-918

- Why: `169.254.169.254` (AWS/GCP/Azure IMDS) is reachable from most cloud VMs; an SSRF that can reach it can exfiltrate IAM credentials.
- Grep: `169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.java`, `**/*.go`, `**/*.rb`, `**/*.tf`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## Secure patterns

Allowlist-based URL validation before making a request (Python):

```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"api.example.com", "partner.example.org"}

def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Scheme not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not in allowlist")
    return url

response = requests.get(validate_url(user_url), timeout=5)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Block private/link-local IP ranges after DNS resolution (Python):

```python
import socket, ipaddress

def resolve_and_check(hostname: str) -> None:
    ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"Resolved to blocked address: {ip}")
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Go allowlist check before request:

```go
var allowedHosts = map[string]bool{
    "api.example.com": true,
}

func safeGet(rawURL string) (*http.Response, error) {
    u, err := url.Parse(rawURL)
    if err != nil || !allowedHosts[u.Hostname()] {
        return nil, fmt.Errorf("host not allowed: %s", u.Hostname())
    }
    return http.Get(rawURL)
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Add allowlist validation before outbound request — addresses CWE-918

**Before (dangerous):**

```python
url = request.args.get('url')
resp = requests.get(url)
```

**After (safe):**

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com"}

url = request.args.get('url')
host = urlparse(url).hostname
if host not in ALLOWED_HOSTS:
    abort(400, "URL not permitted")
resp = requests.get(url, timeout=5)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Recipe: Replace full URL parameter with path/ID parameter — addresses CWE-918

**Before (dangerous):**

```js
// Caller supplies full URL; server fetches it blindly
const targetUrl = req.query.url;
const data = await fetch(targetUrl).then(r => r.json());
```

**After (safe):**

```js
// Caller supplies only an opaque ID; server constructs the URL itself
const RESOURCE_BASE = 'https://api.example.com/resources/';
const resourceId = req.query.id.replace(/[^a-z0-9_-]/gi, '');
const data = await fetch(`${RESOURCE_BASE}${resourceId}`).then(r => r.json());
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Recipe: Block private ranges after DNS resolution (Java) — addresses CWE-918

**Before (dangerous):**

```java
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
```

**After (safe):**

```java
URL url = new URL(userInput);
InetAddress addr = InetAddress.getByName(url.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
    throw new SecurityException("SSRF: resolved to private address");
}
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## Version notes

- AWS IMDSv2 (2019+) requires a `PUT` to obtain a session token before metadata retrieval; IMDSv1 is still enabled by default on many AMIs — do not rely on IMDSv2 enforcement as an SSRF mitigation in application code.
- Python `requests` follows redirects by default (`allow_redirects=True`); set `allow_redirects=False` and validate the `Location` header before following when the initial URL is controlled.
- Java `HttpClient` (Java 11+) does not follow redirects by default (`NEVER` policy); `HttpURLConnection` follows HTTP → HTTP redirects by default.
- Go `http.DefaultClient` follows up to 10 redirects; supply a custom `CheckRedirect` function to block redirects to private ranges.

## Common false positives

- `requests.get("https://api.example.com/data")` — hard-coded string literal with no variable; not a sink unless the string is assembled from dynamic parts elsewhere.
- `fetch(url)` inside a service worker or browser extension — client-side fetch is not SSRF (no server trust boundary); file is misclassified if the glob sweeps frontend code.
- Webhook delivery code that validates the URL against a stored, admin-configured allowlist before each request — safe if the allowlist is populated out-of-band and not user-editable.
- `169.254.169.254` appearing in deny-list or blocklist expressions — the literal is a check for the unsafe address, not a call to it; confirm surrounding context is rejection logic.
