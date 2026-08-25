# Deploying Huntsman on Railway

Termux on Android is this project's primary target and is unaffected by
anything here. This document covers a second, optional deployment path: HSE in a
container behind a public URL.

Read the first section before deploying. The rest is mechanical.

---

## Read this first: a public deployment is a different threat model

On a phone, HSE binds loopback. The database — which holds whatever personal
data about **third parties** your scans collected — is reachable only from the
device it lives on. That property is what makes the default posture safe, and
it does not survive a move to a public URL.

Two consequences:

1. **The API has no authentication of its own.** Nothing in the crate gated the
   HTTP surface before this deployment path existed, because loopback *was* the
   gate. `HSE_API_TOKEN` adds a bearer check in front of every route except
   `/api/v1/health`. The container **refuses to start** on a public bind without
   it — a warning in a deploy log nobody reads is not a control.

2. **You become the custodian of other people's data on someone else's
   infrastructure.** Scan results routinely include names, addresses,
   coordinates, phone numbers and account handles belonging to people who are
   not you and did not consent. Consider whether your jurisdiction's data-
   protection rules permit you to host that on a third-party PaaS, and prefer
   `hse prune` / `hse delete` retention over an ever-growing store.

If you only want AI analysis and not a public UI, there is a better shape: keep
scanning on-device and point `HUNTSMAN_OLLAMA_URL` at a remote model host. No
personal data leaves the phone.

---

## What Railway is and is not good at here

**Good:** the Rust service. HSE builds to a single binary linking only
libc/libm/libgcc — SQLite is statically bundled and TLS is rustls — so the
runtime image is small and starts fast.

**Poor:** the model. **Railway is CPU-only; it offers no GPU.** Ollama there
runs on llama.cpp's CPU kernels, which is workable for small models and slow for
large ones. Railway's Pro tier goes up to 24 vCPU / 24 GB per replica, so a 3B
model is reasonable and a 7B is possible but expensive.

**Measured, with its limits stated:** a `qwen2.5:3b` analysis of a ~200-entity
scan completed on a 4-vCPU x86_64 container, but that machine was concurrently
running a Rust build, so treat it as a floor rather than a benchmark. No
measurement of Railway's own hardware was taken. At Railway's published rates
(~$10/GB-month RAM, ~$20/vCPU-month) an always-on 3B service is roughly
$100–150/month; a 7B roughly double. Scale to zero when idle if that matters.

---

## Deploy

### 1. The HSE service

```
Build:  Dockerfile (railway.toml selects it)
Volume: mount at /data          <- REQUIRED, see below
```

**The volume is not optional.** `HOME=/data` and HSE resolves its database to
`$HOME/.huntsman/huntsman.db`. Without a mount at `/data`, every redeploy
silently discards all scan history. The entrypoint warns when `/data` is not a
mountpoint.

Environment:

| Variable | Required | Purpose |
|---|---|---|
| `HSE_API_TOKEN` | **yes** | Bearer token. `openssl rand -hex 32`. Container refuses to start on a public bind without it. |
| `PORT` | injected | Railway sets this; the entrypoint binds `0.0.0.0:$PORT`. |
| `HUNTSMAN_OLLAMA_URL` | no | Enables `hse analyze`. See below. |
| `HUNTSMAN_OLLAMA_MODEL` | no | e.g. `qwen2.5:3b`. |
| `HSE_ALLOW_PUBLIC_NO_AUTH` | no | Set to `1` to run open deliberately. Only for a throwaway instance with an empty database. |

### 2. Optional: an Ollama service for `hse analyze`

Deploy Ollama as a **separate Railway service** (its own image, its own volume
for model weights — a 3B is ~2.2 GB), then point HSE at it over the private
network:

```
HUNTSMAN_OLLAMA_URL = http://<ollama-service>.railway.internal:11434
HUNTSMAN_OLLAMA_MODEL = qwen2.5:3b
```

Use the internal hostname, not a public one: it keeps prompts — which contain
scan data, i.e. personal data — off the public internet, and avoids paying
egress to talk to your own service.

Analysis is opt-in and downstream. `feature.ai_daemon` must be armed
(`hse config feature.ai_daemon on`), and nothing about scanning changes if the
model is absent or unreachable.

---

## Using a token-gated instance

**API clients** send the header:

```bash
curl -H "Authorization: Bearer $HSE_API_TOKEN" https://<app>/api/v1/scans
```

**The web UI** prompts for the token on its first 401 and remembers it for the
browser session (`sessionStorage`, cleared when the tab closes). It also writes
a `SameSite=Strict` session cookie carrying the same value, because the
live-scan log is an SSE stream and `EventSource` cannot send an `Authorization`
header — the cookie is the only carrier that reaches it. Cross-site abuse of
that cookie is blocked by the pre-existing `X-HSE-CSRF` requirement on every
mutating request.

`/api/v1/health` stays open so Railway's health check works without a
credential. It returns no scan data.

---

## What is already handled, and what is not

Handled by the existing code, not by this deployment path:

- **CORS is bound to the origin derived from the bind address**, in every case —
  never `allow_origin(Any)`, on loopback or otherwise. (A stale doc comment near
  the top of `src/api/routes/mod.rs` still describes the old permissive-loopback
  policy; the implementation in `build_cors_layer` is the authority.)

  A Railway-specific consequence: the allowlist is computed from the *bind*
  (`0.0.0.0:$PORT`), which never equals the public hostname the browser uses. The
  embedded SPA is served same-origin from the same binary, so it is unaffected —
  same-origin requests do not consult CORS at all. But a **cross-origin browser
  client on another domain will be refused**, by design. Server-side API clients
  (curl, scripts) are unaffected: CORS is a browser control.
- **CSRF**: every mutating `/api` request requires an `X-HSE-CSRF` header, which
  a cross-site *simple* request cannot set. This is what makes the auth cookie
  safe to use as a carrier.
- **Key writes and cell-DB import require a loopback peer** regardless of the
  bind address, so a public instance cannot have API keys written into it over
  the network.
- **CSP** is `default-src 'self'` with `connect-src 'self'`, so an injection
  cannot exfiltrate to an external origin.

Not handled — know these before you deploy:

- **No rate limiting.** A token-gated instance is only as strong as the token;
  there is no lockout or backoff on repeated failed attempts. Put Railway's
  proxy or an external WAF in front if that matters.
- **No multi-user model.** One token, one privilege level. Anyone holding it
  can do everything, including delete scans.
- **No audit log of API access.** Scan provenance is recorded; who called the
  API is not.
- **The Host-header allowlist does NOT apply here.** It is deliberately
  loopback-only — `src/api/routes/mod.rs` states it is "skipped for a
  non-loopback bind: the operator opted into exposure and the valid Host set …
  isn't enumerable here". It exists to defeat DNS rebinding against a
  *loopback* install, which is not the Railway threat. On a public deployment
  the bearer token is the control, not the Host check. Do not read the
  on-device hardening as covering this path.
- **The token is compared in constant time**, but it lives in the environment
  and in `sessionStorage` — treat it as a shared secret, rotate it by changing
  the variable and redeploying.
