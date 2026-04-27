# IIS test fixture

Intentionally vulnerable IIS configuration used by sec-audit tests.

Intentional misconfigurations:

- TLS 1.0 / 1.1 enabled in `<sslProtocols>`
- `<directoryBrowse enabled="true" />` leaks filenames
- No `<remove name="Server" />` and no HSTS / X-Content-Type-Options / X-Frame-Options under `<httpProtocol>`
- `<customErrors mode="Off" />` and `<httpErrors errorMode="Detailed" />` return stack traces to remote clients
- `maxAllowedContentLength="999999999"` enables large-body DoS
- Anonymous auth runs as shared `IUSR` (no per-app-pool identity)
- `<machineKey validationKey="AutoGenerate" decryptionKey="AutoGenerate" />` breaks multi-node ViewState / forms-auth

Do NOT deploy this configuration to a real server.
