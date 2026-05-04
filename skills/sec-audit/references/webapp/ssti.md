# Server-Side Template Injection (SSTI)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html — OWASP Injection Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection)
- https://cwe.mitre.org/data/definitions/1336.html — CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
- https://jinja.palletsprojects.com/en/3.1.x/sandbox/ — Jinja2 sandboxed environment documentation
- https://docs.djangoproject.com/en/stable/ref/templates/api/ — Django template engine documentation
- https://github.com/nicowillis/twig-security — Twig security notes
- https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-view-thymeleaf — Thymeleaf Spring MVC documentation

## Scope

Covers server-side template injection in Jinja2 (Python/Flask), ERB (Ruby/Rails), Twig (PHP/Symfony), Thymeleaf (Java/Spring), and Handlebars (Node.js). Includes code execution via template expression evaluation and sandbox-escape chains. Does not cover client-side template injection (AngularJS `{{ }}` in HTML served raw) or XSS via template output without escaping (see XSS pack).

## Dangerous patterns (regex/AST hints)

### Jinja2 render_template_string with user input — CWE-1336

- Why: `render_template_string(user_input)` evaluates the entire string as a Jinja2 template; an attacker can inject `{{ ''.__class__.__mro__[1].__subclasses__() }}` to achieve RCE.
- Grep: `render_template_string\s*\(\s*[^"'][^,)]*|render_template_string\s*\(\s*f['"]\s*.*\{`
- File globs: `**/*.py`
- Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

### Jinja2 Environment.from_string() with user-controlled template text — CWE-1336

- Why: `Environment().from_string(user_text).render()` executes attacker-supplied template expressions outside any sandbox.
- Grep: `Environment\s*\(\s*\)\.from_string\s*\(|jinja2\.Template\s*\(\s*[^"']`
- File globs: `**/*.py`
- Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

### ERB (Ruby) rendering user-supplied string — CWE-1336

- Why: `ERB.new(user_template).result(binding)` executes arbitrary Ruby inside `<%= %>` tags; binding passes the current scope to the template.
- Grep: `ERB\.new\s*\(\s*[^"'][^)]*\)\.result|ERB\.new\s*\(\s*params`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

### Twig render / createTemplate with user input — CWE-1336

- Why: `$twig->createTemplate($userInput)->render()` compiles and evaluates an attacker-supplied Twig template; `{{ ''|filter('system') }}` achieves RCE in older Twig versions.
- Grep: `createTemplate\s*\(\s*\$_(GET|POST|REQUEST)|render\s*\(\s*\$_(GET|POST|REQUEST)`
- File globs: `**/*.php`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

### Thymeleaf SpEL expression from request parameter — CWE-1336

- Why: Building a Thymeleaf fragment expression from a request parameter (e.g. in a `@Controller` returning `"fragments/" + userInput`) enables SSTI via Spring Expression Language.
- Grep: `return\s+"fragments/"\s*\+\s*|ModelAndView\s*\(\s*request\.(getParameter|getAttribute)`
- File globs: `**/*.java`
- Source: https://cwe.mitre.org/data/definitions/1336.html

### Handlebars compile() with user template string — CWE-1336

- Why: `Handlebars.compile(userTemplate)` compiles attacker-controlled markup; Handlebars helpers and prototype-pollution gadgets have been chained to RCE.
- Grep: `Handlebars\.compile\s*\(\s*[^"'][^)]*\)|Handlebars\.precompile\s*\(\s*[^"']`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

### Passing raw user data as template variable into unsafe context — CWE-1336

- Why: Even in static templates, passing unescaped user data to a `| safe` filter or `{% autoescape false %}` block executes injected template syntax.
- Grep: `\|\s*safe\b|autoescape\s+false|mark_safe\s*\(`
- File globs: `**/*.py`, `**/*.html`, `**/*.j2`, `**/*.jinja`
- Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

## Secure patterns

Jinja2 — always render from a file-based loader, never from user strings:

```python
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader('/app/templates'), autoescape=True)

# NEVER: env.from_string(user_text)
# CORRECT: load a static template and pass user data as context variables
template = env.get_template('report.html')
html = template.render(username=user_input)  # user_input is data, not template code
```

Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

Jinja2 SandboxedEnvironment for genuinely user-authored templates:

```python
from jinja2.sandbox import SandboxedEnvironment

sandbox = SandboxedEnvironment(autoescape=True)
# SandboxedEnvironment restricts attribute access and blocks common RCE gadgets;
# still audit allowed filters and globals for your use case.
result = sandbox.from_string(user_template).render(data=safe_data)
```

Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

Thymeleaf — use static view names, never concatenate request parameters:

```java
// NEVER: return "fragments/" + request.getParameter("view");
// CORRECT: validate against an allowlist before returning a view name
@GetMapping("/page")
public String page(@RequestParam String section, Model model) {
    Set<String> ALLOWED = Set.of("home", "about", "contact");
    String view = ALLOWED.contains(section) ? section : "home";
    return "pages/" + view;
}
```

Source: https://cwe.mitre.org/data/definitions/1336.html

## Fix recipes

### Recipe: Replace render_template_string with render_template — addresses CWE-1336

**Before (dangerous):**

```python
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template_string(f'<h1>Hello, {name}!</h1>')
```

**After (safe):**

```python
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # User input is passed as a context variable, not template source
    return render_template('greet.html', name=name)
# greet.html: <h1>Hello, {{ name }}!</h1>  — Jinja2 auto-escapes
```

Source: https://jinja.palletsprojects.com/en/3.1.x/sandbox/

### Recipe: Restrict ERB to static template files — addresses CWE-1336

**Before (dangerous):**

```ruby
template_text = params[:template]
html = ERB.new(template_text).result(binding)
```

**After (safe):**

```ruby
# Render from a static file; pass user data as local variables only
template_path = Rails.root.join('app', 'views', 'reports', 'summary.html.erb')
html = ERB.new(File.read(template_path)).result_with_hash(data: safe_data)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

### Recipe: Replace Handlebars dynamic compile with preloaded template — addresses CWE-1336

**Before (dangerous):**

```js
const tmpl = Handlebars.compile(req.body.template);
const html = tmpl({ user: req.user });
```

**After (safe):**

```js
// Compile static templates at startup; never compile user input
const TEMPLATES = {
  greeting: Handlebars.compile('<p>Hello, {{name}}!</p>'),
};

const key = req.body.templateName;
const tmpl = TEMPLATES[key] ?? TEMPLATES.greeting;
const html = tmpl({ name: req.user.name });
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

### Recipe: Fix Twig createTemplate with user input — addresses CWE-1336

**Before (dangerous):**

```php
$template = $twig->createTemplate($_GET['layout']);
echo $template->render(['user' => $user]);
```

**After (safe):**

```php
// Load template by name from the loader; user controls only the data variable
$allowedTemplates = ['card', 'list', 'table'];
$name = in_array($_GET['layout'], $allowedTemplates) ? $_GET['layout'] : 'card';
echo $twig->render("layouts/{$name}.html.twig", ['user' => $user]);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

## Version notes

- Jinja2 `SandboxedEnvironment` mitigates many but not all SSTI RCE chains; sandbox escapes have been published — treat sandboxed user templates as medium risk, not safe.
- Twig 3.x introduced `createTemplate()` restrictions; `{{ ''|filter('system') }}` is blocked by default in Twig >= 1.44.7 / 2.12.6 / 3.0.0 via the filter sandbox, but `createTemplate` with a full template string still evaluates control structures.
- Thymeleaf Spring Boot auto-configuration uses a `SpringTemplateEngine` with SpEL enabled by default; the SSTI surface exists wherever view names are constructed from request data.
- Handlebars Node.js >= 4.5.3 patches a prototype-pollution-to-RCE chain (CVE-2021-23383); update and audit custom helpers for unsafe property access.
- Django's built-in template engine uses a restricted language that does not execute arbitrary Python; `render(request, template_name, context)` with static `template_name` is safe. Only flag when `Engine.from_string(user_input)` is used.

## Common false positives

- `render_template_string('<p>Static HTML with no variables</p>')` — a fully static string literal is not a sink; flag only when the argument contains a variable or f-string expression.
- `{{ variable | safe }}` in a Jinja2 template where `variable` is derived from a developer-controlled constant (e.g. a translated UI string from a locale file) — not user-controlled; verify the data source.
- `ERB.new(File.read('app/views/mailer/welcome.html.erb')).result_with_hash(...)` — rendering from a file committed to the repo; the template is not user-supplied.
- `mark_safe('<strong>OK</strong>')` in Django where the HTML is a hardcoded string literal — acceptable; flag only when `mark_safe` is called on a value derived from request data.
