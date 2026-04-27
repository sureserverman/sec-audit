# Certificate Rotation and Lifecycle

## Source

- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator and Best Practices
- https://letsencrypt.org/docs/ — Let's Encrypt Documentation (ACME, short-lived certificates)
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html — OWASP Transport Layer Protection Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers TLS certificate lifecycle: issuance via ACME, certificate validity periods, private key storage and protection, Subject Alternative Names (SANs), name constraints, and Certificate Transparency (CT). Applies to any service that terminates TLS. Does not cover cipher suite or protocol version selection (see tls-bcp.md) or HSTS (see hsts-hpkp.md).

## Dangerous patterns (regex/AST hints)

### Long certificate validity (> 398 days) — CWE-295

- Why: Certificates valid for more than 398 days are rejected by Safari/Chrome as of 2020; compromise of such a cert has a long blast radius.
- Grep: `days\s*=\s*[0-9]{4,}|validity.*[0-9]{4,}|3650|7300` (in certificate generation scripts)
- File globs: `**/*.sh`, `**/*.conf`, `**/*.py`, `**/openssl*.cnf`, `**/*.yaml`
- Source: https://ssl-config.mozilla.org/

### Private key stored without passphrase in world-readable location — CWE-312

- Why: Unencrypted private keys readable by unprivileged processes expose the key to local privilege escalation.
- Grep: `-----BEGIN.*PRIVATE KEY-----|RSA PRIVATE KEY` (in non-secrets-manager files)
- File globs: `**/*.pem`, `**/*.key`, `**/*.p12`, `**/id_rsa`, `**/*.env`, `**/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### Self-signed certificate in production — CWE-295

- Why: Self-signed certs have no third-party trust chain; clients cannot distinguish a legitimate cert from a MITM attacker's cert without out-of-band pinning.
- Grep: `self.signed|selfsigned|subjectAltName.*localhost` in production config, or `openssl req.*-x509` without a CA step
- File globs: `**/*.sh`, `**/*.conf`, `**/*.yaml`, `**/docker-compose*.yml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### CN used instead of SAN — CWE-295

- Why: Modern browsers (Chrome 58+) ignore the CN field for hostname verification; only SANs are checked.
- Grep: `commonName|CN\s*=` (check absence of `subjectAltName` or `SAN` in certificate config)
- File globs: `**/openssl*.cnf`, `**/*.sh`, `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### ACME auto-renewal not configured — CWE-295

- Why: Let's Encrypt certificates expire every 90 days; without automated renewal, certificate expiry causes outages and may prompt users to accept invalid-cert warnings.
- Grep: `certbot|acme` (check absence of cron/systemd timer or certbot renew hook)
- File globs: `**/crontab`, `**/systemd/**/*.timer`, `**/certbot*.sh`, `**/acme*.sh`
- Source: https://letsencrypt.org/docs/faq/

## Secure patterns

Certbot auto-renewal with pre/post hooks (systemd timer):

```ini
# /etc/systemd/system/certbot-renew.timer
[Unit]
Description=Twice daily certbot renewal

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=43200
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
#!/bin/bash
systemctl reload nginx
```

Source: https://letsencrypt.org/docs/

Private key file permissions (Linux):

```bash
# Key should be owned by the service user, not world-readable
install -m 600 -o nginx -g nginx /path/to/privkey.pem /etc/nginx/ssl/privkey.pem
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

OpenSSL CSR with SAN (no CN-only):

```ini
# openssl.cnf extension section
[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
# No reliance on CN for hostname verification
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

## Fix recipes

### Recipe: Switch from long-lived to ACME-managed short-lived certificates — addresses CWE-295

**Before (dangerous):**

```bash
openssl req -x509 -newkey rsa:4096 -days 3650 -keyout server.key -out server.crt -nodes
```

**After (safe):**

```bash
# Use certbot for automated 90-day certificates with auto-renewal
certbot certonly --webroot -w /var/www/html -d example.com -d www.example.com \
  --deploy-hook "systemctl reload nginx"
```

Source: https://letsencrypt.org/docs/

### Recipe: Restrict private key file permissions — addresses CWE-312

**Before (dangerous):**

```bash
chmod 644 /etc/ssl/private/server.key   # world-readable
```

**After (safe):**

```bash
chmod 600 /etc/ssl/private/server.key
chown root:ssl-cert /etc/ssl/private/server.key
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### Recipe: Add SAN to certificate signing request — addresses CWE-295

**Before (dangerous — CN only):**

```bash
openssl req -new -key server.key -subj "/CN=example.com" -out server.csr
```

**After (safe — SAN included):**

```bash
openssl req -new -key server.key \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com" \
  -out server.csr
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### Recipe: Use HSM/KMS for private key storage — addresses CWE-312

**Before (insufficient — key on disk):**

```nginx
ssl_certificate_key /etc/ssl/private/server.key;
```

**After (better — key in KMS, referenced via PKCS#11):**

```nginx
# Example with AWS ACM Private CA or Vault PKI Secrets Engine
# Private key never leaves the HSM; nginx uses PKCS#11 provider
ssl_certificate_key engine:pkcs11:pkcs11:token=mytoken;object=mykey;type=private;
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

## Version notes

- Let's Encrypt certificates have a 90-day maximum validity; Let's Encrypt recommends renewing at 60 days to allow retry windows.
- As of 2020, Apple/Safari enforces a maximum 398-day certificate validity; any cert with a longer validity is rejected. All major browsers now follow this limit.
- Certificate Transparency is mandatory for publicly trusted certificates (Chrome policy since April 2018); all certificates issued by public CAs are logged automatically.
- ACME v2 (RFC 8555) is the current protocol; ACME v1 (Let's Encrypt legacy) is shut down.

## Common false positives

- Long validity in internal/development CA certificates — acceptable for internal PKI; flag only for publicly trusted or customer-facing certificates.
- Private key in `.pem` file inside a Docker build context — flag if the image is pushed to a public registry; acceptable if build secrets are used correctly (Docker BuildKit `--secret`).
- Self-signed certificates in local development `docker-compose.yml` — not a production concern; confirm environment context before flagging.
