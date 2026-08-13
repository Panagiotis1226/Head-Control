# Security model

## Where the secrets live

| Secret | Where | Notes |
|---|---|---|
| Headscale API key | Head-Control container env (server-side only) | Never sent to the browser — the browser talks only to Head-Control, same-origin. This is the key design difference from localStorage-based headscale UIs. |
| Admin password | Env var; bcrypt hash recommended (`hash-password` subcommand) | Plaintext comparison is constant-time; hash keeps the password out of `docker inspect`. `_FILE` variants support compose secrets. |
| Session tokens | Browser cookie + SHA-256 in SQLite | `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`; revocable server-side; 12h sliding lifetime. |
| Pre-auth / API key secrets | Shown once at creation, never stored | Headscale bcrypt-hashes them at rest (0.28+); Head-Control's audit log records metadata only. |

## Login hardening

Rate limiting (5 attempts/min per IP, 20/min global), uniform 401 responses with a constant delay,
bcrypt verification, sessions revocable by restart or logout. CSRF: per-session token required in
`X-CSRF-Token` on every mutation, on top of `SameSite=Lax`.

## Browser hardening

Strict CSP (`default-src 'self'`; no external scripts, fonts or connections), `nosniff`,
`frame-ancestors 'none'`, no referrer leakage. All assets are served from the binary itself.

## Container hardening

Distroless static image (no shell, no package manager), runs as `nonroot` (uid 65532), works with
`read_only: true` (all writes go to `/data` or explicitly mounted files, using same-directory temp
files + atomic rename). No capabilities needed.

## The Docker socket integration

File-mode ACL reloads need to signal the headscale container. Access to the Docker socket is
root-equivalent, so:

- the integration is **off by default** — file-mode saves still work, the UI just shows the one
  manual reload command;
- when enabled, scope it with [docker-socket-proxy](https://github.com/linuxserver/docker-socket-proxy)
  so Head-Control can only list containers and send signals (see `deploy/examples/file-mode/`);
- the target container is matched by an explicit label (`me.headcontrol.target=headscale`) or name.

## What to put in front

Head-Control has one admin role and one password. For internet-facing deployments put your reverse
proxy's TLS in front, and consider proxy-level access control (client certificates, IP allowlists,
or an authenticating proxy) as an additional layer. Headscale 0.29 API keys have no scopes — the
key Head-Control holds can do everything — so treat the Head-Control host with the same care as the
headscale host.

## Reporting

Please report suspected vulnerabilities via GitHub security advisories rather than public issues.
