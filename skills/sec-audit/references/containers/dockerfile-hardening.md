# Dockerfile Hardening

## Source

- https://docs.docker.com/develop/develop-images/dockerfile_best-practices/ — Dockerfile best practices
- https://docs.docker.com/build/building/secrets/ — BuildKit secret mounts
- https://docs.docker.com/engine/reference/builder/ — Dockerfile reference
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 Application Container Security Guide
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html — OWASP Docker Security Cheat Sheet

## Scope

Covers `Dockerfile` authorship for Linux-based images built with Docker Engine (BuildKit) or compatible builders (BuildX, Kaniko, ko). Applies to both application images and base images. Does not cover runtime security controls (those are in `containers/docker.md` and `containers/kubernetes.md`) or image registry access controls.

## Dangerous patterns (regex/AST hints)

### Running as root (no USER instruction) — CWE-250

- Why: If no `USER` instruction is present the container process runs as UID 0 (root). A process escape or remote code execution vulnerability then yields host root if user namespaces are absent.
- Grep: `^USER\s+` (check for absence in Dockerfile)
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Secrets in ARG or ENV — CWE-312

- Why: `ARG` values are stored in the image's build history (`docker history`); `ENV` values are embedded in the image manifest and visible to anyone who can pull the image.
- Grep: `ARG\s+(PASSWORD|SECRET|TOKEN|KEY|PASS|API_KEY)|ENV\s+(PASSWORD|SECRET|TOKEN|KEY|PASS|API_KEY)`
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://docs.docker.com/build/building/secrets/

### ADD from remote URL — CWE-494

- Why: `ADD <url>` fetches content at build time without checksum verification, allowing a compromised upstream to inject malicious content. Use `curl` + checksum verification or `COPY` from a verified local artifact instead.
- Grep: `^ADD\s+https?://`
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy

### Unpinned base image (mutable tag) — CWE-829

- Why: A mutable tag (e.g. `FROM ubuntu:22.04`) can silently point to a different image after a registry push, introducing unexpected changes or supply-chain substitution.
- Grep: `^FROM\s+(?!scratch)(?!.*@sha256:)\S+`
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.2.1)

### apt-get cache not cleared — CWE-459

- Why: Leaving `/var/lib/apt/lists` in the image inflates image size and retains index data that may expose package metadata useful to an attacker.
- Grep: `apt-get\s+install` (check for absence of `rm -rf /var/lib/apt/lists`)
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run

### COPY --chown not used for sensitive files — CWE-732

- Why: `COPY` without `--chown` defaults ownership to root:root; if the container later switches to a non-root user, files may be readable by root only or writable by root, depending on umask and permissions in the source.
- Grep: `^COPY\s+(?!.*--chown)`
- File globs: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Source: https://docs.docker.com/engine/reference/builder/#copy---chown---chmod

## Secure patterns

Multi-stage build with pinned digest, non-root user, and BuildKit secret mount:

```dockerfile
# syntax=docker/dockerfile:1.6
FROM golang:1.22.2@sha256:<digest> AS builder
WORKDIR /src
COPY --chown=1000:1000 . .
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    go build -trimpath -ldflags="-s -w" -o /app ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
COPY --from=builder --chown=65532:65532 /app /app
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/app", "healthz"]
ENTRYPOINT ["/app"]
```

Source: https://docs.docker.com/build/building/secrets/ and https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

apt-get with cache cleanup and pinned versions:

```dockerfile
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl=7.88.1-10+deb12u5 \
       ca-certificates=20230311 \
    && rm -rf /var/lib/apt/lists/*
```

Source: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run

.dockerignore to prevent secret leakage:

```
.env
.env.*
*.pem
*.key
*.p12
.git
**/.git
**/node_modules
**/dist
**/__pycache__
```

Source: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#dockerignore-file

## Fix recipes

### Recipe: Add non-root USER instruction — addresses CWE-250

**Before (dangerous):**

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
CMD ["node", "server.js"]
```

**After (safe):**

```dockerfile
FROM node:20.12.2-alpine3.19@sha256:<digest>
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --chown=appuser:appgroup package*.json ./
RUN npm ci --omit=dev
COPY --chown=appuser:appgroup . .
USER appuser
CMD ["node", "server.js"]
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Recipe: Replace ARG secret with BuildKit secret mount — addresses CWE-312

**Before (dangerous):**

```dockerfile
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc \
    && npm ci \
    && rm ~/.npmrc
```

**After (safe):**

```dockerfile
# syntax=docker/dockerfile:1.6
RUN --mount=type=secret,id=npm_token,target=/root/.npmrc \
    npm ci
```

Build invocation:

```bash
docker build --secret id=npm_token,src=.npmrc .
```

Source: https://docs.docker.com/build/building/secrets/

### Recipe: Pin base image to digest — addresses CWE-829

**Before (dangerous):**

```dockerfile
FROM python:3.12-slim
```

**After (safe):**

```dockerfile
FROM python:3.12.3-slim-bookworm@sha256:<digest>
```

Source: https://csrc.nist.gov/publications/detail/sp/800-190/final (Section 4.2.1)

### Recipe: Use multi-stage build to produce minimal image — addresses CWE-250

**Before (dangerous):**

```dockerfile
FROM python:3.12
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
CMD ["python", "/app/main.py"]
```

**After (safe):**

```dockerfile
FROM python:3.12.3-slim-bookworm@sha256:<digest> AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM gcr.io/distroless/python3-debian12@sha256:<digest>
COPY --from=builder /install /usr/local
COPY --chown=65532:65532 app/ /app
USER 65532:65532
CMD ["/app/main.py"]
```

Source: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#use-multi-stage-builds

## Version notes

- BuildKit secret mounts (`--mount=type=secret`) require BuildKit, enabled by default in Docker Engine 23.0+ and Docker Desktop 4.x. On older engines set `DOCKER_BUILDKIT=1`.
- The `syntax=docker/dockerfile:1.6` frontend directive requires Docker BuildKit; remove for plain Docker builds, but secret mounts will not be available.
- Distroless images moved to `gcr.io/distroless` for the Google-maintained variants; verify digest freshness against https://github.com/GoogleContainerTools/distroless.
- `COPY --chown` with numeric UIDs was added in Dockerfile syntax 1.2 (BuildKit); older syntax parsers may fail on it.
- `HEALTHCHECK` is a Dockerfile instruction ignored by Kubernetes (which uses `livenessProbe`/`readinessProbe`) but respected by Docker Compose and Docker Swarm.

## Common false positives

- `ADD` without a URL (e.g. `ADD archive.tar.gz /app`) — `ADD` with a local tar archive auto-extracts; this is intentional and does not carry the remote-URL risk. Flag only `ADD https?://...`.
- `ARG BUILD_DATE` or `ARG VCS_REF` — non-secret build metadata arguments are fine; grep matches should be triaged against the argument name.
- `ENV NODE_ENV=production` — non-secret environment variables (log levels, runtime mode flags) do not carry the CWE-312 risk; flag only when the value looks like a credential.
- `USER root` in an intermediate build stage followed by `USER nonroot` before `CMD` — root is acceptable in builder stages that need package installation; verify the final stage uses a non-root user.
