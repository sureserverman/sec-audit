# Mass Assignment

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html — OWASP Mass Assignment Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection / A04:2021 Insecure Design)
- https://cwe.mitre.org/data/definitions/915.html — CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters — Rails Strong Parameters docs
- https://docs.djangoproject.com/en/stable/topics/forms/modelforms/#selecting-the-fields-to-use — Django ModelForm fields

## Scope

Covers mass assignment vulnerabilities in web frameworks that bind HTTP request parameters directly to model or object fields. Applies to Rails (ActiveRecord), Express/Node.js (body-parser), Django (ModelForm / DRF serializers), and Spring MVC (@ModelAttribute). Does not cover SQL injection or type-coercion bugs that are independent of parameter binding.

## Dangerous patterns (regex/AST hints)

### Rails: ActiveRecord.new / update without strong parameters — CWE-915

- Why: Passing `params[:model]` directly to `.new()` or `.update()` allows an attacker to set any column the model exposes, including `admin`, `role`, or `balance`.
- Grep: `\bUser\.new\s*\(\s*params\b|\b\.update\s*\(\s*params\b|\b\.create\s*\(\s*params\b`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Rails: params.permit missing or using permit! — CWE-915

- Why: `params.require(:user).permit!` whitelists all attributes unconditionally, defeating the purpose of strong parameters.
- Grep: `\.permit!\s*\b`
- File globs: `**/*.rb`
- Source: https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters

### Express: Object.assign / spread of req.body onto model — CWE-915

- Why: Spreading the full request body onto a model object lets an attacker inject arbitrary fields such as `isAdmin` or `__v`.
- Grep: `Object\.assign\s*\(\s*\w+,\s*req\.body|{\s*\.\.\.\s*req\.body`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Express: Mongoose Model.create / findOneAndUpdate with req.body — CWE-915

- Why: Passing `req.body` directly to Mongoose creates/updates every field the schema defines, including protected ones.
- Grep: `Model\.create\s*\(\s*req\.body|\bfindOneAndUpdate\s*\([^,]+,\s*req\.body`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Django: ModelForm with Meta.fields = '__all__' — CWE-915

- Why: `fields = '__all__'` exposes every model field in form binding, including internal fields like `is_staff` or `is_superuser`.
- Grep: `fields\s*=\s*['"]__all__['"]`
- File globs: `**/*.py`
- Source: https://docs.djangoproject.com/en/stable/topics/forms/modelforms/#selecting-the-fields-to-use

### Django REST Framework: Serializer with no explicit fields — CWE-915

- Why: A `ModelSerializer` that relies on inherited field sets or has `fields = '__all__'` in `Meta` exposes writable fields to API callers.
- Grep: `class\s+\w+Serializer\s*\(.*ModelSerializer.*\)` (inspect for `fields = '__all__'` in Meta)
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Spring MVC: @ModelAttribute without DTO — CWE-915

- Why: Binding a JPA entity directly via `@ModelAttribute` exposes every setter to HTTP parameter injection.
- Grep: `@ModelAttribute\s+\w*\s+\w*Entity\b|@ModelAttribute\s+\w*\s+\w*Model\b`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Spring: @InitBinder without setAllowedFields — CWE-915

- Why: An `@InitBinder` that does not call `setAllowedFields` or `setDisallowedFields` provides no binding restriction.
- Grep: `@InitBinder` (check that `setAllowedFields` or `setDisallowedFields` follows)
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Secure patterns

Rails strong parameters — explicit allowlist:

```ruby
# app/controllers/users_controller.rb
def user_params
  params.require(:user).permit(:name, :email, :password)
  # Never: params.require(:user).permit!
end

User.new(user_params)
```

Source: https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters

Express — destructure only known fields before assignment:

```js
// Destructure known-safe fields; discard everything else
const { name, email } = req.body;
const user = await User.create({ name, email });
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

Django ModelForm — explicit field list:

```python
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email', 'bio']  # never '__all__'
```

Source: https://docs.djangoproject.com/en/stable/topics/forms/modelforms/#selecting-the-fields-to-use

Spring — use a DTO, not the JPA entity:

```java
public class UserUpdateDto {
    private String name;
    private String email;
    // no role, no isAdmin — only fields the API should expose
}

@PostMapping("/users/{id}")
public ResponseEntity<?> update(@RequestBody UserUpdateDto dto, @PathVariable Long id) {
    userService.update(id, dto);
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Fix recipes

### Recipe: Rails — replace permit! with explicit permit — addresses CWE-915

**Before (dangerous):**

```ruby
def user_params
  params.require(:user).permit!
end
```

**After (safe):**

```ruby
def user_params
  params.require(:user).permit(:name, :email, :bio)
end
```

Source: https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters

### Recipe: Express — replace req.body spread with explicit field pick — addresses CWE-915

**Before (dangerous):**

```js
const user = await User.findByIdAndUpdate(id, { ...req.body });
```

**After (safe):**

```js
const { name, email } = req.body;
const user = await User.findByIdAndUpdate(id, { name, email }, { new: true, runValidators: true });
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Recipe: Django — replace '__all__' with explicit fields list — addresses CWE-915

**Before (dangerous):**

```python
class Meta:
    model = User
    fields = '__all__'
```

**After (safe):**

```python
class Meta:
    model = User
    fields = ['username', 'email', 'first_name', 'last_name']
```

Source: https://docs.djangoproject.com/en/stable/topics/forms/modelforms/#selecting-the-fields-to-use

### Recipe: Spring — introduce DTO to replace entity binding — addresses CWE-915

**Before (dangerous):**

```java
@PostMapping("/profile")
public String update(@ModelAttribute UserEntity user) { ... }
```

**After (safe):**

```java
@PostMapping("/profile")
public String update(@ModelAttribute UserUpdateDto dto) {
    UserEntity user = userRepo.findById(dto.getId()).orElseThrow();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    userRepo.save(user);
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Version notes

- Rails 3 and earlier used `attr_accessible` / `attr_protected` on the model; this was replaced by strong parameters in Rails 4. Projects still on Rails 3 must use `attr_accessible` or upgrade.
- Django REST Framework serializers inherit `read_only_fields` from the model's editable flag; setting `editable=False` on a model field excludes it from DRF serializer writes by default, but `fields = '__all__'` still includes it as read-only — verify per-field write access explicitly.
- Mongoose `strict` option (default `true`) rejects unknown schema fields on save, which partially mitigates req.body spread; it does not protect against setting legitimate but privileged fields like `isAdmin`.
- Spring Boot's `@JsonIgnoreProperties(ignoreUnknown = true)` prevents Jackson deserialization errors on unknown fields but does not prevent known privileged fields from being set via request body.

## Common false positives

- `fields = '__all__'` in a Django admin class (e.g. `ModelAdmin`) — admin forms are protected by Django's admin authentication; lower severity unless admin is exposed without auth.
- `Object.assign(target, req.body)` where `target` is a plain response DTO (not a persisted model) — no database write occurs; however, verify the DTO is not later passed to a persistence layer.
- Rails `params.permit!` inside a test factory or seed file — not reachable from HTTP requests; not a runtime vulnerability.
- Spring `@ModelAttribute` on a DTO class (not a JPA entity) — safe if the DTO has no privileged fields and is not persisted directly.
