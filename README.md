# Head-Control

**A self-hosted admin console for [headscale](https://github.com/juanfont/headscale) v0.29.x** — the
Tailscale control-plane experience, for your own coordination server.

- **One `docker-compose.yaml` to deploy.** Prebuilt multi-arch image on ghcr.io — no cloning, no building.
- **The headscale API key never touches your browser.** Head-Control's Go backend holds it
  server-side and proxies everything same-origin — no CORS setup, no key in localStorage
  (the two problems that plague most headscale UIs).
- **Complete API coverage.** Every one of headscale v0.29.3's 29 REST operations is wired into the
  UI — machines, users, routes, pre-auth keys, API keys, policy, registration approval, health.
- **ACL editing in both policy modes.** `database` mode saves through the API; `file` mode writes
  the mounted policy file atomically and reloads headscale via an opt-in Docker integration.
- **Honest about limits.** Where headscale has no server-side support (webhooks, user roles,
  tailnet lock, …), the UI says so instead of pretending.

> **Compatibility:** Head-Control 1.x targets **headscale v0.29.0 – v0.29.3** (tested against
> v0.29.3). Headscale 0.26–0.28 are unsupported (different node/key APIs). Headscale 0.30 changes
> the API fundamentally (gRPC removal, new error format) and will need the next Head-Control major.
> The UI detects your server version at runtime and warns on mismatch.

## Quick start

```bash
# 1. On your headscale host, mint an API key:
headscale apikeys create

# 2. Hash your admin password (recommended over plain ADMIN_PASSWORD):
docker run --rm -i ghcr.io/panagiotis1226/head-control:latest hash-password

# 3. Grab the compose file, fill in the environment, and start:
curl -LO https://raw.githubusercontent.com/panagiotis1226/head-control/main/deploy/docker-compose.yaml
docker compose up -d
```

Open `http://your-host:8000`, log in with your admin password, done. Put a TLS reverse proxy in
front for production (`BASE_PATH=/admin` lets it share your headscale domain — see
`deploy/examples/full-stack/` for a complete headscale + Head-Control + Caddy stack).

### Step-by-step: fresh VPS, ~5 minutes

New to Docker or self-hosting? Here is every command, spelled out. You need a VPS that can reach
your headscale server (v0.29.x). *No headscale yet either?* Skip this and use
[`deploy/examples/full-stack/`](deploy/examples/full-stack/) instead — one compose file that runs
headscale + Head-Control + automatic HTTPS together.

**1. Install Docker** (skip if you have it):

```bash
curl -fsSL https://get.docker.com | sh
```

**2. Create a headscale API key.** Run this where headscale runs:

```bash
headscale apikeys create --expiration 90d
# if headscale runs in Docker:
#   docker exec <headscale-container> headscale apikeys create --expiration 90d
```

Copy the key it prints — it is shown only once.

**3. Download the compose file** into a fresh directory on your VPS:

```bash
mkdir head-control && cd head-control
curl -LO https://raw.githubusercontent.com/panagiotis1226/head-control/main/deploy/docker-compose.yaml
```

**4. Hash the password** you'll use to log in to the UI (type it when prompted):

```bash
docker run --rm -i ghcr.io/panagiotis1226/head-control:latest hash-password
```

**5. Create a `.env` file** next to the compose file with the key from step 2 and the hash from
step 4 — **keep the single quotes around the hash**, they are load-bearing:

```bash
cat > .env <<'EOF'
HEADSCALE_API_KEY=paste-your-api-key-here
ADMIN_PASSWORD_HASH='$2b$10$paste-your-hash-here'
EOF
```

**6. Point it at your headscale.** Open `docker-compose.yaml` and set `HEADSCALE_URL` to wherever
your headscale lives (e.g. `https://headscale.example.com`). If you'll open the UI over plain
HTTP for now (no TLS yet), also un-comment `COOKIE_SECURE: "false"` — otherwise the login cookie
is HTTPS-only and sign-in won't stick.

**7. Start it:**

```bash
docker compose up -d
```

**8. Log in.** Open `http://<your-vps-ip>:8000`, enter the password from step 4. Done.

For anything internet-facing, put TLS in front (Caddy makes this a 3-line config) and remove the
`COOKIE_SECURE` override. If something misbehaves, `docker compose logs head-control` says why —
misconfiguration fails loudly with an explanation, not silently.

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `HEADSCALE_URL` | ✔ | — | How this container reaches headscale (e.g. `http://headscale:8080`) |
| `HEADSCALE_API_KEY` (or `_FILE`) | ✔ | — | From `headscale apikeys create` |
| `ADMIN_PASSWORD_HASH` or `ADMIN_PASSWORD` (or `ADMIN_PASSWORD_FILE`) | ✔ | — | UI login; bcrypt hash preferred (`hash-password` subcommand). **Single-quote the hash in `.env`** (`'$2b$10$…'`) — compose interpolates `$` |
| `PUBLIC_SERVER_URL` | | `HEADSCALE_URL` | Client-facing URL used in copyable `tailscale up` commands |
| `LISTEN_ADDR` | | `:8000` | Bind address |
| `BASE_PATH` | | `/` | Serve under a sub-path (e.g. `/admin`) — runtime, no rebuild |
| `DATA_DIR` | | `/data` | SQLite (sessions, audit log, policy history) |
| `COOKIE_SECURE` | | `true` | Set `false` only for plain-HTTP LAN use |
| `SESSION_LIFETIME` | | `12h` | Login session lifetime (sliding) |
| `POLICY_MODE` | | `auto` | `auto` \| `database` \| `file` |
| `POLICY_FILE_PATH` | | — | Mount headscale's policy file to enable file-mode ACL editing |
| `EXTRA_RECORDS_PATH` | | — | Mount headscale's `dns.extra_records_path` JSON to edit DNS records (hot-reloaded) |
| `HEADSCALE_CONFIG_PATH` | | — | Mount `config.yaml` read-only to display DNS/server settings |
| `DOCKER_SOCK` | | — | e.g. `unix:///var/run/docker.sock` — enables SIGHUP reload after file-mode saves (use [docker-socket-proxy](deploy/examples/file-mode/)) |
| `DOCKER_CONTAINER_LABEL` | | `me.headcontrol.target=headscale` | How the headscale container is found |
| `DOCKER_CONTAINER_NAME` | | — | Alternative to the label |
| `HEADSCALE_CA_FILE` | | — | Custom CA bundle for headscale's TLS |
| `HEALTH_INTERVAL` | | `30s` | Headscale health/version probe cadence |
| `LOG_LEVEL` / `LOG_FORMAT` | | `info` / `text` | Logging |

## ACL editing — the two policy modes

| headscale setting | What Head-Control does |
|---|---|
| `policy.mode: database` (recommended) | Full editor. Saves validate via `POST /policy/check` (against live users/nodes, including `tests`/`sshTests`), then apply instantly via `PUT /policy`. Nothing to mount. |
| `policy.mode: file` | Mount the policy file into Head-Control (`POLICY_FILE_PATH`, shared volume with headscale). Saves validate, write atomically (`.tmp` → fsync → rename, keeping a `.bak`), then reload headscale — automatically via SIGHUP when the Docker integration is configured, otherwise the UI shows the one manual command. |

Every save — and any change made outside the UI — is snapshotted into a local version history with
diff and rollback. Rollback loads a version into the editor; nothing applies without validation.

## Feature parity vs. the Tailscale admin console

| Tailscale console | Head-Control | Notes |
|---|---|---|
| Machines list, search, filters | ✅ | minus OS/client-version/posture columns — headscale has no client telemetry |
| Rename, tags, delete, expire key | ✅ | plus expire-at-time and never-expire (0.29 API) |
| Subnet route & exit-node approval | ✅ | concurrency-guarded (detects mid-air route changes) |
| Auto-approvers | ✅ | via policy; cross-referenced on the Routes page |
| Device approval queue | ⚠️ partial | headscale 0.29 has approve/reject/register APIs but **no pending-list endpoint** — codes are pasted in; pre-auth-key joins bypass approval |
| Users CRUD | ✅ | roles/invites/suspend/SCIM don't exist in headscale |
| ACL editor + syntax check + tests | ✅ | server-side validation incl. `tests`/`sshTests` |
| Policy version history + rollback | ✅ (UI-local) | headscale keeps no history; Head-Control snapshots every observed change |
| Auth keys / API keys | ✅ | show-once secrets; self-lockout guard when rotating the UI's own key |
| DNS: nameservers, MagicDNS, split DNS | 👁 display-only | no DNS API in headscale — config.yaml only (mount it for display) |
| DNS: custom records | ✅ | via `dns.extra_records_path` (hot-reloaded, no restart) |
| Webhooks, config-audit logs w/ diffs, flow logs | ❌ | no server-side support; Head-Control keeps its own audit log of UI actions |
| Tailnet lock, node sharing, HTTPS certs, Services | ❌ | Tailscale-proprietary control-plane features |

## Development

```bash
# backend (Go ≥1.24): all tests incl. the pinned v0.29.3 API contract test
go test ./...

# frontend (Node 22 + pnpm)
cd frontend && pnpm install && pnpm build

# full image
docker build -t head-control:dev .
```

The repository pins headscale's v0.29.3 OpenAPI spec at `testdata/headscale-v0.29.3.swagger.json`;
a contract test fails if the client and spec ever drift.

## AI disclosure

This is a vibe-coded project: the codebase was co-authored with **Claude** (Anthropic's AI),
which wrote the bulk of the implementation under human direction, with human edits, review, and
real-world testing on top. The design was researched against the headscale v0.29.3 source and
the behavior verified end-to-end against a live headscale server before release — but you should
weigh the AI co-authorship in your own trust assessment, as with any dependency. Commits carry
`Co-Authored-By` trailers marking the AI's involvement. Bug reports are very welcome; they get
fixed the same way the code was written.

## License

[MIT with Commons Clause](LICENSE) — free for anyone to use, modify, and self-host, personally or
inside a company. What the Commons Clause removes is the right to **sell** Head-Control: no selling
the software itself, and no paid hosting/consulting/support offerings whose value derives
substantially from it.
