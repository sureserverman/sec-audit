# Insecure Direct Object Reference / Broken Access Control

## Source

- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A01:2021 Broken Access Control)
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html — OWASP IDOR Prevention Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — OWASP Authorization Cheat Sheet
- https://cwe.mitre.org/data/definitions/639.html — CWE-639: Authorization Bypass Through User-Controlled Key
- https://cwe.mitre.org/data/definitions/285.html — CWE-285: Improper Authorization
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html — OWASP REST Security Cheat Sheet

## Scope

Covers horizontal and vertical privilege escalation via direct object references in HTTP APIs and web handlers. Applies to REST APIs (Express, Django REST Framework, Spring, Rails), JWT-based authorization, and role/permission checks in middleware. Does not cover authentication bypass (see sessions reference) or CSRF (separate pack).

## Dangerous patterns (regex/AST hints)

### Route parameter used directly in DB query without ownership check — CWE-639

- Why: Fetching a record by user-supplied ID without verifying the requesting user owns or is authorized to access it enables horizontal privilege escalation.
- Grep: `findById\s*\(\s*req\.params\.|params\[:id\]\|request\.GET\['id'\]\|@PathVariable.*id`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

### Express: no authorization middleware before resource handler — CWE-285

- Why: Defining resource routes without an `isAuthenticated` or `authorize` middleware call means any request, including unauthenticated ones, can access the handler.
- Grep: `router\.(get|post|put|patch|delete)\s*\([^,]+,\s*(async\s*)?\(req` (check for missing middleware argument)
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

### Django: view missing @login_required or permission_classes — CWE-285

- Why: A Django view or DRF viewset without `@login_required`, `permission_classes`, or `IsAuthenticated` is publicly accessible.
- Grep: `def\s+\w+\s*\(\s*request\b` (check for absent `@login_required` or `@permission_required` decorator above)
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

### DRF ViewSet with permission_classes = [] or AllowAny — CWE-285

- Why: Explicitly setting `permission_classes = []` or `[AllowAny]` disables all access control on the viewset.
- Grep: `permission_classes\s*=\s*\[\s*\]|permission_classes\s*=\s*\[.*AllowAny`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

### JWT: scope or role claim used without server-side verification — CWE-285

- Why: Trusting a role or scope value decoded from a JWT without re-checking it against the database allows token forgery or stale-privilege escalation if the signing key is weak or the claim was modified.
- Grep: `decoded\.(role|scope|admin|is_admin)|payload\.(role|scope)|claims\.(role|scope)`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

### Admin or privileged action without role check — CWE-285

- Why: Routes that perform privileged operations (delete user, promote role, access billing) must verify the caller's role, not just their authentication status.
- Grep: `/admin|/delete|/promote|/grant|/revoke|/impersonate` (check handler for absent role assertion)
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`, `**/*.java`
- Source: https://owasp.org/www-project-top-ten/

### Predictable sequential integer IDs in resource URLs — CWE-639

- Why: Sequential integer IDs allow enumeration of all records. An attacker who can access `/invoices/1001` can try `/invoices/1000`, `/invoices/999`, etc.
- Grep: `id\s*=\s*request\.(GET|POST|params)\[['"]id['"]\]|params\[:id\]` (cross-reference schema for integer PK)
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

### Rails: no current_user ownership scope in ActiveRecord query — CWE-639

- Why: `Record.find(params[:id])` fetches any record; `current_user.records.find(params[:id])` restricts to owned records.
- Grep: `\bRecord\.find\s*\(\s*params\b|\bPost\.find\s*\(\s*params\b|\bOrder\.find\s*\(\s*params\b`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

## Secure patterns

Scope queries to the authenticated user (Rails):

```ruby
# Always scope through current_user association — raises ActiveRecord::RecordNotFound
# if the record does not belong to the current user, which returns 404 automatically.
@order = current_user.orders.find(params[:id])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

Explicit ownership check in Express:

```js
const doc = await Document.findById(req.params.id);
if (!doc) return res.status(404).json({ error: 'Not found' });
if (doc.ownerId.toString() !== req.user.id) {
  return res.status(403).json({ error: 'Forbidden' });
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

Django DRF — restrict queryset to requesting user:

```python
class InvoiceViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

Use UUIDs or opaque tokens as resource identifiers instead of sequential integers:

```python
import uuid
class Invoice(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Scope Rails query to current_user — addresses CWE-639

**Before (dangerous):**

```ruby
@document = Document.find(params[:id])
```

**After (safe):**

```ruby
@document = current_user.documents.find(params[:id])
# ActiveRecord raises RecordNotFound (-> 404) if not owned by current_user
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

### Recipe: Add permission_classes to DRF viewset — addresses CWE-285

**Before (dangerous):**

```python
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # No permission_classes — publicly accessible
```

**After (safe):**

```python
class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

### Recipe: Add ownership check in Express handler — addresses CWE-639

**Before (dangerous):**

```js
app.get('/api/reports/:id', authenticate, async (req, res) => {
  const report = await Report.findById(req.params.id);
  res.json(report);
});
```

**After (safe):**

```js
app.get('/api/reports/:id', authenticate, async (req, res) => {
  const report = await Report.findOne({ _id: req.params.id, userId: req.user.id });
  if (!report) return res.status(404).json({ error: 'Not found' });
  res.json(report);
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

### Recipe: Add role assertion for admin route in Express — addresses CWE-285

**Before (dangerous):**

```js
app.delete('/api/users/:id', authenticate, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.status(204).send();
});
```

**After (safe):**

```js
app.delete('/api/users/:id', authenticate, requireRole('admin'), async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.status(204).send();
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Version notes

- Django REST Framework's `DEFAULT_PERMISSION_CLASSES` setting defaults to `[IsAuthenticated]` since DRF 3.x; however, individual viewsets that set `permission_classes = []` override the global default — always check per-viewset.
- Rails 7 introduced `config.action_controller.raise_on_open_redirects = true` by default but provides no built-in IDOR protection; authorization is always the application's responsibility.
- Spring Security 6 moved from `WebSecurityConfigurerAdapter` (deprecated in 5.7) to `SecurityFilterChain` beans; review migrated projects to confirm route-level authorization rules were preserved.
- JWT libraries that do not verify `alg` header (e.g. accepting `alg: none`) enable trivial claim forgery; pin the expected algorithm explicitly.

## Common false positives

- `findById(req.params.id)` — acceptable when the route is intentionally public (e.g. a public product catalog or public post) and the data is non-sensitive; confirm intent before flagging.
- `permission_classes = [AllowAny]` on registration or login endpoints — these endpoints are intended to be unauthenticated; not a finding.
- Sequential IDs — low severity when the resource is intentionally public or when the application enforces ownership checks on access; flag as informational only if ownership checks are present.
- JWT role/scope claim decoded from a trusted, short-lived token issued by an internal auth service — acceptable if the signing key is strong and token lifetime is short; note in the finding rather than flagging as high severity.
