# Headscale compatibility

| Head-Control | Headscale | Status |
|---|---|---|
| 1.x (`hs-v0.29` image tag) | v0.29.0 – v0.29.3 | ✅ supported; developed and tested against v0.29.3 |
| — | ≤ v0.28 | ❌ unsupported — different node/tag/pre-auth-key APIs (0.26 removed the routes API; 0.28 removed move-node and reshaped tags/keys) |
| future 2.x | v0.30+ | planned — 0.30 removes gRPC, switches errors to RFC 7807 and the spec to OpenAPI 3.1 |

Head-Control checks the server's `/version` at runtime and shows a warning banner on any mismatch;
operations may still work partially, but no guarantees.

## Why pinning matters

Headscale's API has changed incompatibly in most minor releases, which is why most third-party UIs
broke at 0.26 and again at 0.28. Head-Control pins the exact v0.29.3 OpenAPI contract in
`testdata/headscale-v0.29.3.swagger.json`; a contract test fails the build if the client and spec
drift, and every endpoint's behavior is exercised in CI against a real headscale v0.29.3 container.

## Verified-against-live-server notes (v0.29.3)

Facts confirmed against a running v0.29.3 that differ from (or refine) the documentation:

- API keys have the shape `hskey-api-{prefix}-{secret}` where the **secret itself contains hyphens**.
- Interactive registration auth IDs use the prefix **`hskey-authreq-`** and are exactly 38
  characters; the deprecated docs-era `hskey-reg-` prefix does not appear.
- In file mode, `GET /api/v1/policy` reads the policy file **fresh from disk**, so file edits are
  visible via the API before a SIGHUP reload applies them to the running filter state.
- Approving either exit-node prefix (`0.0.0.0/0` or `::/0`) approves both, server-side.
- `/version` returns JSON (`{"version":"v0.29.3", ...}`).
