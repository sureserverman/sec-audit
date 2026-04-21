# IIS

## Source

- https://www.cisecurity.org/benchmark/microsoft_iis — CIS Microsoft IIS 10 Benchmark
- https://ncp.nist.gov/checklist/952 — NCP / DISA IIS 10.0 STIG
- https://learn.microsoft.com/en-us/iis/configuration/system.webserver/ — Microsoft Learn system.webServer reference
- https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/ — Microsoft Learn system.applicationHost reference
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325 TLS recommendations

## Scope

Covers IIS 10+ on Windows Server 2016/2019/2022 with review of `web.config` (per-application) and `applicationHost.config` (server-wide) configuration. Applies to server-level handler mappings, site-level bindings, request filtering, authentication modes, custom errors, response headers, and TLS binding configuration. Out of scope: Windows OS hardening (registry tuning, WinRM, SMB, LSA protections), .NET framework deserialization gadget chains, and WCF/WebAPI application-code review.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — TLS 1.0/1.1 enabled  — CWE-326

- Why: TLS 1.0 and 1.1 are deprecated by RFC 8996 and disallowed by RFC 9325. IIS bindings or application-level `<sslProtocols>` that still include `Tls10` or `Tls11` expose the site to known downgrade and cipher weaknesses.
- Grep: `<sslProtocols>.*Tls1[01]` or `sslProtocols="[^"]*Tls1[01]"`
- File globs: `web.config`, `applicationHost.config`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 2 — Directory browsing on  — CWE-548

- Why: `<directoryBrowse enabled="true">` exposes full directory listings when no default document is present, leaking filenames, backup files, and source artifacts.
- Grep: `<directoryBrowse[^>]+enabled="true"`
- File globs: `web.config`, `applicationHost.config`
- Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Pattern 3 — Server / X-Powered-By header not suppressed  — CWE-200

- Why: IIS emits `Server: Microsoft-IIS/10.0` and `X-Powered-By: ASP.NET` by default. These aid attacker fingerprinting and are explicitly called out by the CIS IIS 10 Benchmark.
- Grep: files containing `<httpProtocol>` but no `<remove name="Server"` and/or no `<remove name="X-Powered-By"` nearby
- File globs: `web.config`, `applicationHost.config`
- Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Pattern 4 — Detailed custom errors in production  — CWE-209

- Why: `<customErrors mode="Off">` or `<httpErrors errorMode="Detailed">` returns full stack traces and server paths to remote clients, enabling reconnaissance and disclosure of internals.
- Grep: `<customErrors[^>]+mode="Off"` or `<httpErrors[^>]+errorMode="Detailed"`
- File globs: `web.config`, `applicationHost.config`
- Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Pattern 5 — Anonymous auth without app-pool isolation  — CWE-284

- Why: `<anonymousAuthentication enabled="true" userName="IUSR">` (or any shared built-in account) across multiple application pools breaks the CIS-recommended "unique identity per app pool" posture and enables lateral access between sites.
- Grep: `<anonymousAuthentication[^>]+enabled="true"[^>]*userName="IUSR"` or `<anonymousAuthentication[^>]+enabled="true"` with no `password=`
- File globs: `web.config`, `applicationHost.config`
- Source: https://www.cisecurity.org/benchmark/microsoft_iis

### Pattern 6 — machineKey AutoGenerate on webfarm  — CWE-330

- Why: `validationKey="AutoGenerate"` / `decryptionKey="AutoGenerate"` regenerates per-node keys, breaking forms-auth/ViewState validation across a farm and forcing sticky sessions or — worse — accepting any node's tokens via fallback. For multi-node deployments, both keys MUST be explicit and identical.
- Grep: `<machineKey[^>]+validationKey="AutoGenerate"` or `<machineKey[^>]+decryptionKey="AutoGenerate"`
- File globs: `web.config`, `applicationHost.config`
- Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Pattern 7 — Request filtering absent / maxAllowedContentLength huge  — CWE-20

- Why: Default `maxAllowedContentLength` is 30 MB. Values above ~100 MB (9+ digits) are rarely justified and enable DoS via large upload bodies; absence of `<requestLimits>` altogether means defaults for URL length (4096) and query string (2048) may also be over-relaxed elsewhere.
- Grep: `maxAllowedContentLength="[1-9][0-9]{8,}"`
- File globs: `web.config`, `applicationHost.config`
- Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Pattern 8 — Missing security response headers  — CWE-1021 / CWE-319

- Why: Without `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options` (or a framed-ancestors CSP) IIS sites are vulnerable to clickjacking, MIME confusion, and protocol-downgrade attacks. OWASP HTTP Headers Cheat Sheet lists these as baseline.
- Grep: files containing `<httpProtocol>` block but no `<add name="Strict-Transport-Security"` — the absence of an HSTS `add` entry inside a `<customHeaders>` block
- File globs: `web.config`, `applicationHost.config`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Secure patterns

```xml
<!-- TLS binding: disable TLS 1.0/1.1 at the site / app level (IIS 10+) -->
<system.webServer>
  <security>
    <access sslFlags="Ssl, SslNegotiateCert, SslRequireCert, Ssl128" />
  </security>
</system.webServer>
<!-- Companion registry enforcement is required for OS-wide SCHANNEL; app-level
     sslFlags enforces client-cert and 128-bit minimums on the binding. -->
```

Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

```xml
<!-- Request filtering limits (CIS IIS 10 Benchmark, Request Filtering section) -->
<system.webServer>
  <security>
    <requestFiltering allowDoubleEscaping="false" allowHighBitCharacters="false">
      <requestLimits maxAllowedContentLength="30000000"
                     maxUrl="4096"
                     maxQueryString="2048" />
      <fileExtensions allowUnlisted="false">
        <add fileExtension=".aspx" allowed="true" />
        <add fileExtension=".config" allowed="false" />
      </fileExtensions>
      <verbs allowUnlisted="false">
        <add verb="GET" allowed="true" />
        <add verb="POST" allowed="true" />
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>
```

Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

```xml
<!-- HTTP response headers: HSTS + nosniff + framing + remove banners -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="Server" />
      <remove name="X-Powered-By" />
      <add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="X-Frame-Options" value="DENY" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Content-Security-Policy" value="default-src 'self'" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Fix recipes

### Recipe: Disable TLS 1.0/1.1, enable TLS 1.2+  — addresses CWE-326

**Before (dangerous):**

```xml
<system.webServer>
  <security>
    <access sslFlags="Ssl" />
  </security>
</system.webServer>
<!-- with SCHANNEL registry leaving Tls10 / Tls11 enabled -->
```

**After (safe):**

```xml
<system.webServer>
  <security>
    <access sslFlags="Ssl, Ssl128" />
  </security>
</system.webServer>
<!-- Plus SCHANNEL registry: disable TLS 1.0 / TLS 1.1 server-side, enable
     TLS 1.2 and TLS 1.3 (Server 2022). Per RFC 9325, TLS 1.2 is the minimum. -->
```

Source: https://datatracker.ietf.org/doc/html/rfc9325 and https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Recipe: Remove Server and X-Powered-By headers  — addresses CWE-200

**Before (dangerous):**

```xml
<system.webServer>
  <!-- no customHeaders block; IIS emits Server: Microsoft-IIS/10.0
       and ASP.NET emits X-Powered-By: ASP.NET -->
</system.webServer>
```

**After (safe):**

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="Server" />
      <remove name="X-Powered-By" />
    </customHeaders>
  </httpProtocol>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
</system.webServer>
```

Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Recipe: Enforce HSTS and security response headers  — addresses CWE-319 / CWE-1021

**Before (dangerous):**

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders />
  </httpProtocol>
</system.webServer>
```

**After (safe):**

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="X-Frame-Options" value="DENY" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Content-Security-Policy" value="default-src 'self'" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html and https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

### Recipe: Harden request filtering and custom errors  — addresses CWE-20 / CWE-209

**Before (dangerous):**

```xml
<system.web>
  <customErrors mode="Off" />
</system.web>
<system.webServer>
  <httpErrors errorMode="Detailed" />
  <security>
    <requestFiltering>
      <requestLimits maxAllowedContentLength="2147483647" />
    </requestFiltering>
  </security>
</system.webServer>
```

**After (safe):**

```xml
<system.web>
  <customErrors mode="RemoteOnly" defaultRedirect="~/Error" />
</system.web>
<system.webServer>
  <httpErrors errorMode="DetailedLocalOnly" existingResponse="Replace">
    <remove statusCode="500" />
    <error statusCode="500" path="/Error/500" responseMode="ExecuteURL" />
  </httpErrors>
  <security>
    <requestFiltering allowDoubleEscaping="false" allowHighBitCharacters="false">
      <requestLimits maxAllowedContentLength="30000000"
                     maxUrl="4096"
                     maxQueryString="2048" />
    </requestFiltering>
  </security>
</system.webServer>
```

Source: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/

## Version notes

- `removeServerHeader` attribute on `<requestFiltering>` requires IIS 10.0 (Windows Server 2016+); on IIS 8.5 and earlier, the `Server` header must be stripped via a URL Rewrite outbound rule or the `HTTP_HIDE_SERVER_HEADER` registry key.
- TLS 1.3 support on IIS requires Windows Server 2022 (or Windows 11) with SCHANNEL TLS 1.3 enabled; on Server 2016/2019 the practical ceiling is TLS 1.2.
- `<sslProtocols>` as an element inside `<access>` is available in IIS 10 version 1709+; earlier releases gate TLS versions only through the SCHANNEL registry keys under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`.

## Common false positives

- Sample `web.config` files shipped under `packages/` or `node_modules/` (NuGet/npm downloads) — these are outside the user's control and should be excluded via `.gitignore` semantics before triage.
- Template `web.config` files under `Templates/` or `ProjectTemplates/` directories (e.g. Visual Studio scaffolding) — hits are real XML but the file is a template, not a deployed artifact.
- Intentionally-vulnerable test fixtures in `tests/fixtures/`, `e2e/`, or `WebGoat`-style training apps — grep-hits are legitimate but the file exists precisely to host the pattern.
- `<customErrors mode="Off">` inside a `Debug`-only `web.config.debug` transform that is never deployed to production — verify the transform pipeline before flagging.
- `maxAllowedContentLength` large values on a `location`-scoped `<requestFiltering>` under `/upload` when business justification is an explicit large-file upload endpoint — note and confirm rather than auto-flag.
