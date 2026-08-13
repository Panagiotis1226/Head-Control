# Security Policy

## Supported versions

Only the **latest release** receives security fixes. Head-Control is a young project with a
fast release cadence — please update to the newest version before reporting.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Older releases | ❌ — update first |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting: go to the
[Security tab](https://github.com/Panagiotis1226/Head-Control/security) → **Report a
vulnerability**. This keeps the report private between you and the maintainer until a fix is
released.

If that form is unavailable, open a regular issue saying only that you have a security report
and need a private contact — **without any details of the vulnerability** — and the maintainer
will follow up.

What helps: the Head-Control and headscale versions, your deployment shape (compose file,
reverse proxy, policy mode), and reproduction steps.

## Scope notes

Head-Control fronts your headscale coordination server, so treat it as security-critical
infrastructure. Before reporting, it's worth reading the
[security model](../docs/security.md) — it documents the deliberate design decisions
(server-side API key, session handling, container hardening, the Docker socket integration's
threat model) so you can tell a deviation from the design apart from the design itself.
