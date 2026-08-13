# Installing Head-Control

Head-Control is a single container. The only supported install is the prebuilt image — you never
need to clone this repository.

## 1. UI-only (recommended start)

You already run headscale somewhere. On the headscale host:

```bash
headscale apikeys create --expiration 90d
```

Then, anywhere that can reach headscale:

```bash
curl -LO https://raw.githubusercontent.com/panagiotis1226/claude-head/main/deploy/docker-compose.yaml
# hash your admin password:
docker run --rm -i ghcr.io/panagiotis1226/head-control:latest hash-password
# create a .env next to the compose file:
cat > .env <<'EOF'
HEADSCALE_API_KEY=<the key from apikeys create>
ADMIN_PASSWORD_HASH=<the bcrypt hash>
EOF
# edit HEADSCALE_URL in docker-compose.yaml, then:
docker compose up -d
```

Open `http://host:8000` and log in.

> **Note on `$` in bcrypt hashes:** in a `.env` file the hash needs no escaping. If you inline it
> in `docker-compose.yaml` instead, double every `$` (`$$2a$$10$$…`) — compose interpolates `$`.

## 2. Behind a reverse proxy (production)

Terminate TLS in front of Head-Control. Two common shapes:

- **Own subdomain** — proxy `admin.example.com` → `head-control:8000`. No extra config.
- **Same domain as headscale** — serve the UI under a path on the headscale domain:
  set `BASE_PATH=/admin` and route `/admin*` → `head-control:8000`, everything else → headscale.
  See `deploy/examples/full-stack/` for a complete compose with Caddy.

Head-Control only ever talks to headscale server-side, so there is **no CORS to configure** —
ever — regardless of which shape you pick.

Headscale's own proxying has sharp edges (non-standard WebSocket upgrade on POST, no Cloudflare
proxying) — see the [headscale reverse-proxy docs](https://headscale.net/stable/ref/integration/reverse-proxy/).
They apply to the headscale side only; Head-Control is a plain HTTP app.

## 3. Enable optional integrations

| Feature | What to add |
|---|---|
| ACL editing with `policy.mode: file` | Mount headscale's policy file read-write and set `POLICY_FILE_PATH`; add the docker-socket-proxy for automatic reloads (see `deploy/examples/file-mode/`) |
| Editable DNS records | Point headscale's `dns.extra_records_path` at a JSON file, mount it, set `EXTRA_RECORDS_PATH` — headscale hot-reloads it |
| DNS/settings display | Mount headscale's `config.yaml` read-only and set `HEADSCALE_CONFIG_PATH` |

If headscale runs with `policy.mode: database` (recommended), ACL editing needs **no mounts at all**.

## 4. Upgrades

```bash
docker compose pull && docker compose up -d
```

Pin a version tag in production (`ghcr.io/panagiotis1226/head-control:1.0.0`). The `hs-v0.29` tag
always points at the newest release compatible with headscale 0.29.x.

## Troubleshooting

- **"headscale rejected this server's API key"** — the key expired or was deleted. Create a new one
  (`headscale apikeys create`), update `HEADSCALE_API_KEY`, restart the container.
- **Login always fails** — if you inlined `ADMIN_PASSWORD_HASH` in compose YAML, check the `$$`
  escaping (see above).
- **UI unreachable behind proxy at a sub-path** — set `BASE_PATH` to the same path the proxy strips
  or forwards (Head-Control expects the prefix to still be present, e.g. `/admin/api/...`).
- **Plain-HTTP LAN use** — set `COOKIE_SECURE=false` or the session cookie will be dropped.
