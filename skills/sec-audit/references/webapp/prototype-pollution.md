# Prototype Pollution

## Source

- https://cwe.mitre.org/data/definitions/1321.html — CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html — OWASP Prototype Pollution Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection)
- https://portswigger.net/web-security/prototype-pollution — PortSwigger Web Security Academy: Prototype Pollution

## Scope

Covers prototype pollution in server-side Node.js/JavaScript applications and client-side JavaScript. Applies to JSON body parsing, deep-merge utility functions, template engines, and configuration loaders. Does not cover Python or Ruby object attribute injection (see mass-assignment pack). Does not cover V8 sandbox escapes or native module exploits.

## Dangerous patterns (regex/AST hints)

### Object.assign with parsed JSON from user input — CWE-1321

- Why: If `JSON.parse(userInput)` contains a key `__proto__`, `Object.assign` copies that key onto the target's prototype chain, affecting all objects in the process.
- Grep: `Object\.assign\s*\(\s*\w+,\s*JSON\.parse\b|Object\.assign\s*\(\s*\w+,\s*req\.body`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

### lodash _.merge with user-controlled input — CWE-1321

- Why: `_.merge` in lodash < 4.17.21 recursively merges keys including `__proto__`, polluting `Object.prototype`. CVE-2020-8203.
- Grep: `_\.merge\s*\(|lodash\.merge\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://portswigger.net/web-security/prototype-pollution

### lodash _.mergeWith / _.defaultsDeep with user input — CWE-1321

- Why: `_.defaultsDeep` and `_.mergeWith` share the same recursive-merge code path and are equally vulnerable in lodash < 4.17.21.
- Grep: `_\.defaultsDeep\s*\(|_\.mergeWith\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://portswigger.net/web-security/prototype-pollution

### Object.setPrototypeOf with user-controlled object — CWE-1321

- Why: Directly setting the prototype of an object to a user-supplied value can replace the prototype chain of existing application objects.
- Grep: `Object\.setPrototypeOf\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

### __proto__ key access via bracket notation — CWE-1321

- Why: Code that resolves property paths from user input using bracket notation (e.g. `obj[key] = value`) can be tricked into setting `obj.__proto__.polluted = true` when `key` is `"__proto__"`.
- Grep: `\w+\[.*__proto__|\w+\[userKey\]|\w+\[key\]\s*=\s*value` (manual review for path-traversal patterns)
- File globs: `**/*.js`, `**/*.ts`
- Source: https://portswigger.net/web-security/prototype-pollution

### constructor.prototype assignment via user-controlled path — CWE-1321

- Why: A property-path setter that allows `constructor.prototype.x = value` modifies the constructor's prototype and affects all instances of that type.
- Grep: `constructor\.prototype|['"]constructor['"].*['"]prototype['"]`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

### JSON body parser with no schema validation before merge — CWE-1321

- Why: Accepting an arbitrary JSON body and merging it into an options or config object without validating keys first is the most common server-side prototype pollution vector.
- Grep: `JSON\.parse\s*\(\s*req\.body|express\.json\(\)` (trace data flow to any `merge` or `assign` call)
- File globs: `**/*.js`, `**/*.ts`
- Source: https://portswigger.net/web-security/prototype-pollution

## Secure patterns

Use `Object.create(null)` to create objects with no prototype when accumulating user-controlled keys:

```js
// Dictionary/map with no prototype — __proto__ is just a regular string key
const safeMap = Object.create(null);
safeMap[userKey] = userValue;  // cannot pollute Object.prototype
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

Validate and block dangerous keys before any merge:

```js
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    target[key] = source[key];
  }
  return target;
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

Use `Object.freeze(Object.prototype)` at application startup to prevent runtime pollution:

```js
// Call once at startup — any attempted pollution will silently fail (strict mode throws)
Object.freeze(Object.prototype);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

Use `structuredClone` (Node 17+ / browsers) for deep-copying user data without prototype leakage:

```js
// structuredClone does not copy prototype; __proto__ keys are stripped
const safe = structuredClone(JSON.parse(userInput));
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace lodash _.merge with safe alternative — addresses CWE-1321

**Before (dangerous):**

```js
const _ = require('lodash');  // version < 4.17.21
const config = _.merge({}, defaultConfig, req.body);
```

**After (safe):**

```js
// Option 1: upgrade lodash to >= 4.17.21 (patched for CVE-2020-8203)
// Option 2: use a prototype-safe approach
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const safeInput = Object.fromEntries(
  Object.entries(req.body).filter(([k]) => !FORBIDDEN.has(k))
);
const config = Object.assign({}, defaultConfig, safeInput);
```

Source: https://portswigger.net/web-security/prototype-pollution

### Recipe: Replace bracket-notation path setter with safe version — addresses CWE-1321

**Before (dangerous):**

```js
function setPath(obj, path, value) {
  const keys = path.split('.');
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = value;
}
setPath(config, req.body.path, req.body.value);
```

**After (safe):**

```js
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

function setPath(obj, path, value) {
  const keys = path.split('.');
  if (keys.some(k => FORBIDDEN.has(k))) throw new Error('Invalid path');
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!Object.prototype.hasOwnProperty.call(cur, keys[i])) throw new Error('Invalid path');
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = value;
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

### Recipe: Freeze Object.prototype at startup — addresses CWE-1321

**Before (dangerous):**

```js
// No prototype freeze; app accepts deep merge of user JSON
app.use(express.json());
```

**After (safe):**

```js
// server.js — run before any request handlers
Object.freeze(Object.prototype);
app.use(express.json());
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

## Version notes

- lodash `_.merge` was patched in 4.17.21 (CVE-2020-8203, published June 2020). Versions < 4.17.21 are vulnerable. The `_.defaultsDeep` path was patched in the same release.
- `node-serialize` (npm) is vulnerable to prototype pollution and arbitrary code execution when deserializing untrusted input; the package has no maintained version — replace with `flatted` or `devalue`.
- Node.js 22+ enables `--frozen-intrinsics` as a flag; not yet default. `Object.freeze(Object.prototype)` is the portable equivalent.
- `JSON.parse` itself does not pollute — the danger arises when the parsed result is merged into an existing object without key sanitization.

## Common false positives

- `_.merge` called with only static/compile-time constant objects — no user input reaches the merge; not exploitable, but note for hygiene.
- `Object.assign` on a target created with `Object.create(null)` — no prototype chain exists; `__proto__` is treated as a regular key and cannot pollute `Object.prototype`.
- `Object.setPrototypeOf` in a polyfill or `class`-inheritance shim with only constructor-level static arguments — review carefully but usually safe when arguments are not user-controlled.
- `constructor.prototype` references inside TypeScript decorator metadata (`reflect-metadata`) — framework-internal use; not user-controlled.
