# Go Web Frameworks — Security Patterns

## Source

- https://pkg.go.dev/net/http — `net/http` (canonical)
- https://github.com/gin-gonic/gin — Gin canonical (the most-used Go web framework)
- https://echo.labstack.com/docs — Echo canonical
- https://docs.gofiber.io/ — Fiber canonical
- https://github.com/go-chi/chi — Chi canonical (lightweight router)
- https://github.com/gorilla/mux — gorilla/mux canonical
- https://grpc.io/docs/languages/go/ — gRPC-Go
- https://owasp.org/www-project-api-security/ — OWASP API Security Top 10
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — OWASP CSRF Prevention

## Scope

Covers the dominant Go web-framework patterns: `net/http` direct use, Gin, Echo, Fiber, Chi, gorilla/mux, and gRPC-Go services. Patterns covered: middleware ordering (auth-before-handler), CORS configuration, CSRF token enforcement, request-body size limits, JSON deserialisation safety, panic recovery (a missing recover middleware = remote DoS), gRPC interceptor authentication, and reverse-proxy header trust. Out of scope: stdlib `crypto/*` patterns (covered by `go/stdlib-security.md`); module/supply-chain (`go/module-ecosystem.md`); ORM-specific (sqlx, GORM, ent — overlap with `databases/postgres.md` etc.); template-engine specifics (covered by `go/stdlib-security.md`'s `html/template` pattern).

## Dangerous patterns (regex/AST hints)

### CORS allow-origin set to `*` with credentials enabled — CWE-942

- Why: `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is rejected by browsers (a documented CORS spec violation), but a wildcard echo pattern (`AllowOrigins: []string{"*"}` in Gin's `cors.New(cors.Config{...})`, or middleware that reflects the `Origin` header verbatim and sets `Allow-Credentials: true`) is the dangerous pattern. Any cross-origin attacker can then issue authenticated requests against the API. The hardened pattern is an explicit allow-list of origins (`AllowOrigins: []string{"https://app.example.com"}`) with `AllowCredentials: true`, OR a wildcard origin with credentials disabled.
- Grep: `AllowOrigins:\s*\[\]string\{\s*"\*"` AND same struct/file references `AllowCredentials:\s*true`. Also: a custom middleware that copies `r.Header.Get("Origin")` into `Access-Control-Allow-Origin` without an allow-list check.
- File globs: `**/*.go`
- Source: https://owasp.org/www-project-api-security/

### Missing recover middleware — CWE-754

- Why: A panic in any handler in Go's `net/http` (and unwrapped in Gin/Echo/Fiber/Chi without their respective `Recovery` middleware) crashes the goroutine handling that request — but more critically, an uncaught panic in a `httptest.NewServer` or in older versions of `net/http` could propagate and stop the process. Even in modern Go, the absence of recovery middleware means a single attacker-triggered panic (e.g. via a nil-pointer dereference on user-supplied input) returns a partial/empty response and may leak stack traces in development builds. Gin, Echo, Fiber, and Chi all ship dedicated `Recovery` middleware; using their default `New()` (without `Default()`) requires explicit installation.
- Grep: `gin\.New\(\)` not followed by `\.Use\(gin\.Recovery\(\)\)` in the same file; `echo\.New\(\)` not followed by `e\.Use\(middleware\.Recover\(\)\)`; raw `http.HandleFunc` handlers with no `defer func() { recover() }` wrapping for hot paths.
- File globs: `**/*.go`
- Source: https://github.com/gin-gonic/gin

### Body size unlimited (`r.Body` read directly without `http.MaxBytesReader`) — CWE-400

- Why: An attacker who POSTs a multi-gigabyte body forces the server to either buffer the whole body (memory DoS) or stream it (CPU/disk DoS). `net/http.MaxBytesReader(w, r.Body, N)` caps the body size at `N` bytes and returns an error to the handler when the cap is exceeded. Gin has `MaxMultipartMemory` for multipart uploads but does not cap raw bodies; Echo has `BodyLimit(size)`; Fiber has `BodyLimit` in `Config`. Without an explicit cap, large-body DoS is an open attack surface.
- Grep: `io\.ReadAll\s*\(\s*r\.Body\s*\)` OR `json\.NewDecoder\s*\(\s*r\.Body\s*\)\.Decode` without a preceding `MaxBytesReader` / `BodyLimit` on the same handler.
- File globs: `**/*.go`
- Source: https://pkg.go.dev/net/http

### Reverse-proxy header trust without an allow-list (`X-Forwarded-For`, `X-Real-IP`) — CWE-345

- Why: When a Go service runs behind a reverse proxy (nginx, HAProxy, Cloudflare), the client IP must come from the `X-Forwarded-For` chain — but ONLY if the request actually arrived through the trusted proxy. If the service is also reachable directly (e.g. an internal cluster route), an attacker can set `X-Forwarded-For` to any value to spoof their IP for rate-limiting, audit logging, or geo-restriction bypasses. Gin v1.7+ added `engine.SetTrustedProxies([]string{...})` to require the immediate peer to be in the trusted-proxy CIDR list before honouring `X-Forwarded-For`. Echo has `IPExtractor`. Without explicit configuration, the framework reads `X-Forwarded-For` from any peer.
- Grep: `c\.ClientIP\(\)` (Gin) or `c\.RealIP\(\)` (Echo) or `r\.Header\.Get\("X-Forwarded-For"\)` in a file that does NOT also call `SetTrustedProxies` or set `IPExtractor`.
- File globs: `**/*.go`
- Source: https://github.com/gin-gonic/gin

### gRPC server with no authentication interceptor — CWE-306

- Why: A `grpc.NewServer()` with no `grpc.UnaryInterceptor` / `grpc.StreamInterceptor` configured serves every method to every caller. This is appropriate for an internal cluster-only service behind a service-mesh enforcing mTLS, but if the gRPC port is reachable from outside the cluster (an Ingress, a NodePort, an exposed LoadBalancer), the absence of an auth interceptor exposes every RPC method to anonymous callers. The hardened pattern is to install an interceptor that validates a JWT, mTLS certificate, or shared secret on every call, OR to gate the gRPC listener at the network layer (NetworkPolicy, mTLS-required service mesh).
- Grep: `grpc\.NewServer\(\s*\)` (no interceptor args) in a file whose surrounding code references `lis, _ := net.Listen("tcp", ":` (a directly-exposed TCP listener).
- File globs: `**/*.go`
- Source: https://grpc.io/docs/languages/go/

### `c.JSON(http.StatusOK, err.Error())` leaks internal error text — CWE-209

- Why: Returning the raw `err.Error()` string in a public HTTP response leaks stack traces, SQL error messages with table/column names, file paths, and library-internal identifiers. An attacker uses these for reconnaissance (database type, framework version, file-system layout). The hardened pattern is to log the full error server-side (`log.Printf("...: %v", err)`) and return a generic message + correlation ID to the client (`{"error":"internal", "request_id":"..."}`).
- Grep: `c\.JSON\s*\([^,]+,\s*err\.Error\(\)\s*\)` (Gin), `c\.String\s*\(\s*[0-9]+\s*,\s*err\.Error\(\)\s*\)`, or `http\.Error\s*\(\s*w\s*,\s*err\.Error\(\)`.
- File globs: `**/*.go`
- Source: https://owasp.org/www-project-api-security/

### CSRF protection absent on state-changing handlers — CWE-352

- Why: Any HTTP handler accepting POST/PUT/PATCH/DELETE that uses cookie-based sessions for authentication needs CSRF protection (token validation on every state-change). Gin has `gin-csrf` (third-party); Echo has `middleware.CSRF`; Chi has `gorilla/csrf`. Without one of these middlewares (or an explicit `Origin` header allow-list check), an authenticated user visiting an attacker-controlled page is forced to issue cross-origin state-changing requests using their cookie. Note: APIs using `Authorization: Bearer <token>` (not cookies) for auth are immune to CSRF; flag only when cookie-session middleware is also present.
- Grep: file with cookie-session middleware (`gin-contrib/sessions`, `gorilla/sessions`, `scs`) AND `POST|PUT|PATCH|DELETE` route registrations AND no CSRF middleware reference in the same package.
- File globs: `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Secure patterns

Gin server with explicit security defaults:

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/cors"
    "time"
)

func newServer() *gin.Engine {
    r := gin.New()
    r.Use(gin.Recovery())                            // panic → 500 response, not crash
    r.SetTrustedProxies([]string{"10.0.0.0/8"})      // only honour XFF from cluster ingress
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"https://app.example.com"},
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
        AllowHeaders:     []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }))
    r.MaxMultipartMemory = 8 << 20                   // 8 MiB cap on multipart
    return r
}
```

Source: https://github.com/gin-gonic/gin

Authenticated gRPC server with interceptor:

```go
import "google.golang.org/grpc"

func newGRPC(authFn grpc.UnaryServerInterceptor) *grpc.Server {
    return grpc.NewServer(
        grpc.UnaryInterceptor(authFn),
        grpc.StreamInterceptor(streamAuth(authFn)),
        grpc.MaxRecvMsgSize(4 << 20),                // 4 MiB cap
    )
}
```

Source: https://grpc.io/docs/languages/go/

JSON body decode with size cap:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 1 << 20) // 1 MiB cap
    var req CreateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    // ...
}
```

Source: https://pkg.go.dev/net/http

## Fix recipes

### Recipe: pin CORS allow-list — addresses CWE-942

**Before (dangerous):**

```go
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"*"},
    AllowCredentials: true,
}))
```

**After (safe):**

```go
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://app.example.com", "https://staging.example.com"},
    AllowCredentials: true,
}))
```

Source: https://owasp.org/www-project-api-security/

### Recipe: install Recovery middleware on `gin.New()` — addresses CWE-754

**Before (dangerous):**

```go
r := gin.New()
r.GET("/", handler)
r.Run(":8080")
```

**After (safe):**

```go
r := gin.New()
r.Use(gin.Recovery())
r.GET("/", handler)
r.Run(":8080")
```

Source: https://github.com/gin-gonic/gin

### Recipe: cap request body size — addresses CWE-400

**Before (dangerous):**

```go
body, _ := io.ReadAll(r.Body)
```

**After (safe):**

```go
r.Body = http.MaxBytesReader(w, r.Body, 1 << 20) // 1 MiB
body, err := io.ReadAll(r.Body)
if err != nil {
    http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
    return
}
```

Source: https://pkg.go.dev/net/http

### Recipe: scrub error before returning to client — addresses CWE-209

**Before (dangerous):**

```go
if err := db.Create(&user).Error; err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
}
```

**After (safe):**

```go
if err := db.Create(&user).Error; err != nil {
    requestID := uuid.New().String()
    log.Printf("create user failed [%s]: %v", requestID, err)
    c.JSON(http.StatusInternalServerError, gin.H{
        "error":      "internal server error",
        "request_id": requestID,
    })
    return
}
```

Source: https://owasp.org/www-project-api-security/

## Version notes

- Gin v1.7 introduced `SetTrustedProxies`. Earlier Gin always honoured `X-Forwarded-For` from any peer. If a project's `go.mod` pins Gin < 1.7 and the service is internet-exposed, the trust-boundary issue is structural — flag the version pin as the primary finding.
- Echo v4 changed middleware-package paths (`github.com/labstack/echo/v4/middleware`); v3 paths in `go.mod` indicate a stale dependency without years of security fixes.
- Fiber's `BodyLimit` defaults to 4 MiB; Gin's `MaxMultipartMemory` defaults to 32 MiB. Override per-deployment based on actual upload requirements; large defaults are DoS surface.
- gRPC-Go's default `MaxRecvMsgSize` is 4 MiB; raise only when a specific RPC requires it.

## Common false positives

- `gin.Default()` (which auto-installs Recovery + Logger) — always safe; the missing-Recovery pattern only flags `gin.New()` without the explicit `Use(Recovery)`.
- CORS wildcard origin in a public-API service that does NOT use cookie auth (`Authorization: Bearer` only) — CSRF is structurally absent here; the wildcard is acceptable.
- `c.JSON(..., err.Error())` in a handler that wraps the error with `errors.New("invalid input")` first — the outer message is curated; the leak class does not apply.
- Internal-only gRPC services in a service mesh enforcing mTLS at the proxy layer — the missing in-process interceptor is fine; flag only when no mesh is documented.
