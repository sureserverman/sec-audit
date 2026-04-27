# Go Standard Library — Security Patterns

## Source

- https://go.dev/doc/security/best-practices — Go team's security best practices (canonical)
- https://pkg.go.dev/crypto/rand — `crypto/rand` reference
- https://pkg.go.dev/html/template — `html/template` (auto-escaping)
- https://pkg.go.dev/database/sql — `database/sql` (parameterised queries)
- https://pkg.go.dev/os/exec — `os/exec` (argument injection surface)
- https://pkg.go.dev/path/filepath — `filepath` (path-traversal surface)
- https://pkg.go.dev/encoding/xml — `encoding/xml` (XXE class)
- https://pkg.go.dev/crypto/tls — `crypto/tls` reference
- https://pkg.go.dev/net/http — `net/http` (timeouts, header handling)
- https://owasp.org/www-project-top-ten/ — OWASP Top Ten
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — OWASP SQLi prevention

## Scope

Covers Go 1.21+ stdlib security patterns: cryptographic-randomness sourcing, HTML/JS/URL auto-escaping in `html/template`, parameterised SQL via `database/sql`, command-execution argument handling in `os/exec`, path-traversal hygiene in `path/filepath` + `os.Open`, XXE class in `encoding/xml`, TLS configuration in `crypto/tls`, HTTP server hardening in `net/http`. Out of scope: third-party web-framework patterns (covered by `go/web-frameworks.md`); module-ecosystem and supply-chain concerns (covered by `go/module-ecosystem.md`); `cgo`/FFI safety (Go's FFI surface is narrow; treat as a separate concern when it appears).

## Dangerous patterns (regex/AST hints)

### `math/rand` used for security-sensitive randomness — CWE-338

- Why: `math/rand` is a deterministic PRNG seeded from the wall clock by default. It is appropriate for simulations and shuffling test data; it is NOT cryptographically secure. Any token, session ID, password reset code, nonce, or salt generated with `math/rand.Int*` / `rand.Read` (the package-level one, not `crypto/rand.Read`) is predictable to an attacker who can observe a few outputs. Go 1.20 stopped seeding the global `math/rand` source from the clock in `init` — subsequent calls return the same sequence on every program start unless `rand.Seed` is called — but that does not make it secure, only repeatable. Use `crypto/rand` for any security-relevant randomness.
- Grep: `math/rand` import combined with calls in identifiers containing `token|secret|password|nonce|salt|session|csrf|reset|api[_]?key`.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/crypto/rand

### `text/template` used for HTML output — CWE-79

- Why: `text/template` performs no contextual auto-escaping; injecting attacker-controlled data into a template that renders HTML produces stored or reflected XSS. `html/template` provides context-aware escaping for HTML, JS, CSS, and URL contexts. Any handler that builds an HTML response with `text/template.Execute` is structurally vulnerable. The fix is to switch the import to `html/template` (the API is otherwise compatible) and ensure all dynamic data is passed as data values, not concatenated into the template body.
- Grep: `import\s+\(\s*"text/template"` AND the same file references `http.ResponseWriter` or writes to a `*http.Response`.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/html/template

### Concatenated SQL string with user input — CWE-89

- Why: The classic SQL-injection class. `db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))` (or `+`-concatenation) embeds the user input directly into the SQL text. `database/sql` provides placeholder syntax (`?` for MySQL/SQLite; `$1`/`$2` for Postgres; `:name` for the SQL Server driver) — `db.Query("SELECT * FROM users WHERE id = ?", userID)` is the safe form. The driver handles quoting and type-encoding; no string concatenation is needed for parameterised queries. ORM users (sqlx, GORM) are immune unless they invoke `Raw` / `Exec` with concatenated strings.
- Grep: `db\.(Query|QueryRow|Exec)(Context)?\s*\(\s*(fmt\.Sprintf|`+`|"\s*\+\s*[^,]+`-style concatenation patterns).
- File globs: `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### `exec.Command` with shell-interpolation argv — CWE-78

- Why: Go's `os/exec.Command(name, args...)` does NOT invoke a shell — it `execve`s the named binary with the given argv directly. That is the safe pattern. The unsafe pattern is `exec.Command("sh", "-c", "git pull " + userInput)` or `exec.Command("bash", "-c", fmt.Sprintf("ls %s", userInput))`, which hands `sh -c` an attacker-influenced string and re-introduces shell-quoting hazards. The fix is to call the binary directly with separate args (`exec.Command("git", "pull", userInput)`) so no shell parsing occurs, OR if the command genuinely requires a shell, pre-validate the input against a strict allow-list before splicing.
- Grep: `exec\.Command(Context)?\s*\(\s*"(sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell)"\s*,\s*"-c"\s*,\s*[^"]+(\+|fmt\.|Sprintf)`
- File globs: `**/*.go`
- Source: https://pkg.go.dev/os/exec

### `filepath.Join` with user input followed by `os.Open` — CWE-22

- Why: `filepath.Join` cleans `..` segments lexically but does NOT prevent path traversal. `filepath.Join("/srv/uploads", userInput)` with `userInput = "../../../etc/passwd"` yields `/etc/passwd`. The defence is to (a) call `filepath.Clean` on the user input first, (b) verify the result with `strings.HasPrefix(absPath, allowedRoot)` after `filepath.Abs`, and (c) reject any path containing `..` segments before joining. Go 1.20 added `os.Root` (per-directory rooted file access) which removes the entire class — use it when available.
- Grep: `os\.(Open|OpenFile|ReadFile)\s*\(\s*filepath\.Join\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*\)` where the second arg to `Join` is a parameter, struct field, or HTTP-form value.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/path/filepath

### `encoding/xml` decoder without `xml.Decoder.Strict` and DTD/external-entity handling — CWE-611

- Why: Go's `encoding/xml` does NOT process external entity references at all (it ignores DOCTYPE declarations entirely), so the classic XXE attack via external entity expansion is structurally impossible. However, `Decoder.Strict = false` (or omitting strict mode) accepts malformed XML that other parsers reject, and a downstream XML processor (e.g. SOAP libraries, libxml-backed CGO bindings) may expand entities. Flag `Strict = false` settings as suspicious; flag any `cgo` invocation of libxml2/expat XML processing.
- Grep: `\.Strict\s*=\s*false` on an `xml.Decoder` instance, OR direct cgo `import "C"` + `libxml` references.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/encoding/xml

### `tls.Config{InsecureSkipVerify: true}` — CWE-295

- Why: `InsecureSkipVerify: true` disables certificate-chain validation. The TLS handshake completes with any certificate the peer presents — including self-signed test certificates and attacker MITM certificates. A common pattern in development that leaks into production. Production code should never set this; if a self-signed cert is required (private CA), pin the CA pool via `tls.Config.RootCAs` instead.
- Grep: `InsecureSkipVerify\s*:\s*true`
- File globs: `**/*.go`
- Source: https://pkg.go.dev/crypto/tls

### `http.ListenAndServe` with no `ReadTimeout` / `WriteTimeout` — CWE-400

- Why: `http.ListenAndServe(":8080", handler)` constructs a `Server` with zero-valued timeouts, meaning a slow client can hold a connection open indefinitely (Slowloris). Production servers must set `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, and `IdleTimeout` on a `&http.Server{}` and call `srv.ListenAndServe()`. Go 1.20 added a default `ReadHeaderTimeout` proposal but it has not landed; explicit configuration is still required. Same applies to TLS variants.
- Grep: `http\.ListenAndServe(TLS)?\s*\(` with no preceding `&http.Server{` or `http.Server{` block setting timeouts.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/net/http

### `http.Request.Host` trusted for TLS / CSRF / origin checks — CWE-345

- Why: `r.Host` is attacker-controlled — any HTTP client can set the `Host` header to anything. Code paths that route security decisions (e.g. "is this a same-origin request?", CSRF token scoping, redirect-target validation) on `r.Host` are bypassable by setting the header to the expected value. Use the `Origin` header (validated against an allow-list) for CSRF, and rely on TLS SNI + the verified server certificate for the canonical hostname.
- Grep: `if\s+r\.Host\s*[!=]=\s*` or `r\.Host\s*[!=]=\s*` in security-decision contexts.
- File globs: `**/*.go`
- Source: https://go.dev/doc/security/best-practices

## Secure patterns

Cryptographic random token generation:

```go
import (
    "crypto/rand"
    "encoding/base64"
)

func newSessionToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}
```

Source: https://pkg.go.dev/crypto/rand

Parameterised SQL query:

```go
row := db.QueryRowContext(ctx,
    `SELECT id, email FROM users WHERE id = $1 AND tenant = $2`,
    userID, tenantID,
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

Hardened HTTP server:

```go
srv := &http.Server{
    Addr:              ":8443",
    Handler:           mux,
    ReadTimeout:       10 * time.Second,
    ReadHeaderTimeout: 5 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       120 * time.Second,
    MaxHeaderBytes:    1 << 16,           // 64 KiB
    TLSConfig: &tls.Config{
        MinVersion:       tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
    },
}
log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
```

Source: https://pkg.go.dev/net/http

## Fix recipes

### Recipe: replace `math/rand` with `crypto/rand` for token generation — addresses CWE-338

**Before (dangerous):**

```go
import "math/rand"

func newToken() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b)
}
```

**After (safe):**

```go
import "crypto/rand"

func newToken() (string, error) {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```

Source: https://pkg.go.dev/crypto/rand

### Recipe: parameterise SQL — addresses CWE-89

**Before (dangerous):**

```go
q := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
rows, _ := db.Query(q)
```

**After (safe):**

```go
rows, err := db.QueryContext(ctx,
    `SELECT id, email FROM users WHERE email = $1`,
    email,
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: replace `sh -c` invocation with direct argv — addresses CWE-78

**Before (dangerous):**

```go
out, err := exec.Command("sh", "-c", "git clone " + repoURL).Output()
```

**After (safe):**

```go
out, err := exec.CommandContext(ctx, "git", "clone", "--", repoURL).Output()
```

Source: https://pkg.go.dev/os/exec

### Recipe: add HTTP server timeouts — addresses CWE-400

**Before (dangerous):**

```go
log.Fatal(http.ListenAndServe(":8080", mux))
```

**After (safe):**

```go
srv := &http.Server{
    Addr:              ":8080",
    Handler:           mux,
    ReadTimeout:       10 * time.Second,
    ReadHeaderTimeout: 5 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       120 * time.Second,
}
log.Fatal(srv.ListenAndServe())
```

Source: https://pkg.go.dev/net/http

## Version notes

- `crypto/rand.Read` is guaranteed to fill its buffer or return a non-nil error since Go 1.0; never ignore the error return on platforms with a finite entropy source (BSD, embedded).
- `os.Root` (the per-directory rooted file API that prevents path traversal structurally) landed in Go 1.24. For Go 1.23 and earlier, the manual `filepath.Abs` + `strings.HasPrefix` defence is required.
- `http.Server.DisableGeneralOptionsHandler` (Go 1.20) and `Server.MaxHeaderBytes` (Go 1.0) limit specific DoS classes; review per-server.
- `database/sql.NullString` and friends should be preferred over checking `err == sql.ErrNoRows` in places where NULL is a valid domain value — a missed NULL handling in security code (e.g. permission checks) is its own class of bug.

## Common false positives

- `math/rand` used in test files (`*_test.go`) for deterministic test inputs — flag as INFO, not HIGH.
- `text/template` used to generate non-HTML content (CSS, JSON, plain text emails, generated source code) — context-correct; downgrade unless the output is later embedded in HTML.
- `exec.Command("sh", "-c", ...)` where the command string is a hard-coded constant with no interpolation — the shell invocation has no injection surface; flag as INFO.
- `tls.InsecureSkipVerify: true` in test files or behind an explicit `--insecure` CLI flag in a CLI tool — annotate; downgrade if scoped.
