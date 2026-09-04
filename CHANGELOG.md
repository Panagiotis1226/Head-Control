# Changelog

All notable changes to Head-Control are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- **ACLs Beta** tab: a structured, NetBird-style editor for `acls` rules, `groups`, `tagOwners`
  and `hosts` next to the raw HuJSON editor. Rules get UI-local names, descriptions and an
  enable/disable switch (stored in Head-Control's database; disabled rules leave the live policy).
  Saves are applied as a minimal patch on the HuJSON document, so comments and formatting in
  hand-written policies survive. New endpoints `GET/PUT /api/policy/model` with optimistic
  concurrency (`baseHash`, 409 on drift). Other sections (`grants`, `ssh`, `autoApprovers`, …)
  are preserved untouched.
- Step-by-step VPS quick-start walkthrough in the README.
- Ko-fi funding link (`FUNDING.yml` + README Support section).
- Community files: security policy, issue templates, this changelog, README badges.
- UI screenshots (dashboard, ACL editor) in the README.

### Changed
- Repository renamed from `claude-head` to **`head-control`**; documentation URLs updated.
  Old links redirect.
- Go module path renamed to `github.com/panagiotis1226/head-control` to match (no public API —
  nothing imports this module).

## [0.1.1] — 2026-08-13

### Fixed
- First-deploy failures: `/data` volume ownership now works with the `nonroot` user out of the
  box, and a Docker-Compose-mangled `ADMIN_PASSWORD_HASH` (unquoted `$` interpolation) is now
  detected at startup with a clear error instead of breaking logins silently.
- Startup race: headscale is probed synchronously on the first `/api/meta` call, so the UI no
  longer shows a transient "unreachable" state right after boot.
- Fresh `database`-mode headscale servers with a never-set policy no longer error on the ACL
  page.

## [0.1.0] — 2026-08-13

Initial release.

### Added
- Full admin UI for headscale **v0.29.x**: machines, users, subnet routes & exit nodes,
  pre-auth keys, API keys, device registration approval, DNS, health — all 29 REST operations.
- ACL editing in both policy modes: `database` (validate + apply via API) and `file`
  (atomic write to the mounted policy file, optional SIGHUP reload via scoped Docker
  integration).
- UI-local policy version history with diff and rollback.
- Session auth with bcrypt admin password, rate limiting, CSRF protection, audit log.
- Single distroless container (multi-arch, `nonroot`, `read_only`-compatible), one-file
  Docker Compose install, full-stack and file-mode deployment examples.
- Contract test pinned to headscale v0.29.3's OpenAPI spec; CI smoke test against a real
  headscale.

[Unreleased]: https://github.com/Panagiotis1226/Head-Control/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Panagiotis1226/Head-Control/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Panagiotis1226/Head-Control/releases/tag/v0.1.0
