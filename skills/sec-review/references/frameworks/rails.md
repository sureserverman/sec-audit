# Ruby on Rails

## Source

- https://guides.rubyonrails.org/security.html
- https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Rails 6.x, 7.x, and 8.x, including Active Record, Action View,
Action Controller, and the default session/cookie stack. Does not cover
Hanami or Sinatra, or Rails API-only apps beyond the noted differences.

## Dangerous patterns (regex/AST hints)

### Mass assignment without strong params — CWE-915

- Why: Passing `params` or `params[:model]` directly to `create`/`update`/`new` allows attackers to set any model attribute, including `admin`, `role`, or `confirmed`.
- Grep: `\.create\(params\b|\.update\(params\b|\.new\(params\b|\.update_attributes\(params\b`
- File globs: `**/app/controllers/**/*.rb`
- Source: https://guides.rubyonrails.org/security.html#mass-assignment

### SQL injection via string interpolation in where() — CWE-89

- Why: `Model.where("column = '#{user_input}'")` bypasses Active Record's parameterization and allows SQL injection.
- Grep: `\.where\s*\(\s*["'].*#\{|\.order\s*\(\s*["'].*#\{|\.having\s*\(\s*["'].*#\{|\.group\s*\(\s*["'].*#\{`
- File globs: `**/app/**/*.rb`
- Source: https://guides.rubyonrails.org/security.html#sql-injection

### XSS via html_safe or raw — CWE-79

- Why: Calling `.html_safe` or `raw()` on user-controlled strings marks them as trusted, disabling ERB's auto-escaping.
- Grep: `\.html_safe|raw\s*\(.*params\[|raw\s*\(.*@|content_tag.*html_safe`
- File globs: `**/app/views/**/*.erb`, `**/app/helpers/**/*.rb`
- Source: https://guides.rubyonrails.org/security.html#cross-site-scripting-xss

### YAML.load with user input — CWE-502

- Why: `YAML.load()` deserializes Ruby objects and can execute arbitrary code through crafted YAML payloads; `YAML.safe_load()` or `Psych.safe_load()` must be used instead.
- Grep: `YAML\.load\s*\(|Psych\.load\s*\(`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### send_file / send_data with user-controlled path — CWE-22

- Why: Building a file path from `params` without sanitizing directory traversal sequences allows reading arbitrary files from the server.
- Grep: `send_file\s*\(.*params\[|send_data\s*\(.*params\[|File\.read\s*\(.*params\[`
- File globs: `**/app/controllers/**/*.rb`
- Source: https://guides.rubyonrails.org/security.html#file-uploads

### Open redirect via redirect_to with user params — CWE-601

- Why: `redirect_to params[:return_to]` allows attackers to redirect users to arbitrary external URLs after authentication.
- Grep: `redirect_to\s+params\[|redirect_to\s+@.*params\[`
- File globs: `**/app/controllers/**/*.rb`
- Source: https://guides.rubyonrails.org/security.html#redirection-and-files

## Secure patterns

```ruby
# Strong params in controller
def user_params
  params.require(:user).permit(:name, :email, :password)
end

def create
  @user = User.create!(user_params)
end
```

Source: https://guides.rubyonrails.org/security.html#mass-assignment

```ruby
# Parameterized Active Record queries
User.where("email = ?", params[:email])
User.where(email: params[:email])  # hash syntax preferred
```

Source: https://guides.rubyonrails.org/security.html#sql-injection

```ruby
# Safe YAML loading
data = YAML.safe_load(user_supplied_yaml, permitted_classes: [Symbol])
# Rails 7+: YAML.safe_load is the default in new apps
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Fix recipes

### Recipe: Enforce strong parameters — addresses CWE-915

**Before (dangerous):**

```ruby
def create
  @post = Post.create(params[:post])
end
```

**After (safe):**

```ruby
def create
  @post = Post.create(post_params)
end

private

def post_params
  params.require(:post).permit(:title, :body)
end
```

Source: https://guides.rubyonrails.org/security.html#mass-assignment

### Recipe: Parameterize where() query — addresses CWE-89

**Before (dangerous):**

```ruby
User.where("name = '#{params[:name]}'")
```

**After (safe):**

```ruby
User.where("name = ?", params[:name])
# Or hash syntax:
User.where(name: params[:name])
```

Source: https://guides.rubyonrails.org/security.html#sql-injection

### Recipe: Replace YAML.load with safe_load — addresses CWE-502

**Before (dangerous):**

```ruby
config = YAML.load(File.read(user_path))
```

**After (safe):**

```ruby
config = YAML.safe_load(File.read(user_path))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Recipe: Prevent open redirect — addresses CWE-601

**Before (dangerous):**

```ruby
redirect_to params[:return_to]
```

**After (safe):**

```ruby
allowed = [root_path, dashboard_path]
target = params[:return_to]
redirect_to (allowed.include?(target) ? target : root_path)
```

Source: https://guides.rubyonrails.org/security.html#redirection-and-files

## Version notes

- Rails 7.0+: `config.action_dispatch.cookies_same_site_protection = :strict` is the new default for all cookies; older apps may have `:lax` or `nil`.
- Rails 7.1+: `YAML.safe_load` is used by default in several internals; however, application code calling `YAML.load` directly is still dangerous.
- Rails 6.1+: `protect_from_forgery with: :exception` is the default; downgrading to `:null_session` in API sub-classing requires explicit justification.
- `html_safe` on a string returned from `t()` (I18n) is safe — Rails wraps translation strings; only flag when user-controlled data flows into `html_safe`.

## Common false positives

- `YAML.load` on developer-controlled config files never derived from user input (e.g., `config/database.yml` at boot time) — safe in context.
- `.html_safe` on the output of `link_to`, `content_tag`, or other Rails view helpers — those already HTML-escape their arguments.
- `redirect_to params[:return_to]` with an `only_path: true` constraint — limits to relative paths and mitigates open redirect to same host.
- `where("status = 'active'")` — plain string literals with no interpolation are not SQLi.
