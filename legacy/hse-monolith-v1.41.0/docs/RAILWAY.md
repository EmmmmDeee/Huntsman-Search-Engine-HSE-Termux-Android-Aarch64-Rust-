# Deploying to Railway

HSE ships a `Dockerfile` and `railway.json` at the repo root — Railway
detects and builds them with no further configuration required beyond what's
below.

## Quick start

1. Create a Railway project from this repo (or `railway up` from a checkout).
2. Attach a **Volume** mounted at `/data`. This is not optional: without it,
   every redeploy starts from an empty SQLite store — scans, the key pool,
   and the event log are all gone. Railway's ephemeral container filesystem
   is wiped on every deploy; only a Volume survives one.
3. Set `HSE_AUTH_TOKEN` to a long random value (`openssl rand -hex 32`) as a
   Railway variable. HSE binds `0.0.0.0:$PORT` on Railway (a non-loopback
   bind — see below), and without an explicit token it mints and prints a
   random one to the container's logs on every restart, which is awkward to
   retrieve from a redeploy and rotates out from under any client holding
   the previous one.
4. Deploy. Railway injects `$PORT`; the image's entrypoint binds
   `hse serve` to it directly — no manual configuration needed.

## What's already wired up

- **Health check**: `railway.json` points Railway's health probe at
  `GET /api/v1/health`, a dependency-free `{"status":"ok"}` — it never blocks
  on the database, a key pool, or an external provider, so it can't flap
  because a paid OSINT source is slow or down.
- **Port binding**: the image's `CMD` reads `$PORT` (Railway's convention;
  falls back to `8080` if unset) and passes it to `hse serve --bind
  0.0.0.0:$PORT`. `hse serve`'s own default remains `127.0.0.1:8080`
  (loopback-only) for the bare-metal/Termux case — the container is the
  platform adapter that supplies the non-default bind, not a change to that
  default.
- **Non-root + volume ownership**: the container runs `hse` as a dedicated
  non-root user, but starts as root just long enough for its entrypoint
  (`docker-entrypoint.sh`) to reconcile `/data`'s ownership before dropping
  privileges. This matters because a Railway Volume (like any bind/volume
  mount) carries the *host* side's ownership, not whatever the image's
  `useradd --create-home` baked in — skip this and every deploy that
  actually uses a Volume crash-loops on "unable to open database file".
- **Auth on the public bind**: binding `0.0.0.0` (required to be reachable
  on Railway at all) gates every route behind a bearer token
  (`HSE_AUTH_TOKEN`, or an auto-minted one printed once at startup) — see
  `src/api/auth/`. A loopback bind (the Termux/bare-metal default) is
  unaffected: no token, no gate, byte-identical behaviour to before.

## Constraints to design around

- **Single instance only.** HSE persists to a local SQLite file in WAL mode
  under `$HOME/.huntsman` (`$HOME=/data` in the container). This is a
  single-writer, single-reader-set embedded database on a local disk — it is
  **not** safe to run with Railway's replica count above 1, and a
  Volume cannot be shared by more than one running container at a time
  in general. Keep this service scaled to exactly one instance.
- **No horizontal scaling path today.** Scaling this service means a
  vertical resize (more CPU/RAM on the one instance), not more replicas.
  Moving to a shared backing store (e.g. a managed Postgres) is the
  prerequisite for multi-instance HSE and is out of scope for this
  Dockerfile/railway.json pairing.
- **Cold starts re-run the search-engine liveness sweep** and the startup
  self-test — both are bounded, best-effort, and never block the port bind
  (see `src/cli/serve/mod.rs`), so they don't delay Railway's health check,
  but expect a few seconds of "down" engine-health readings in the logs
  immediately after a cold start on a sandboxed/restricted network.

## Verifying a deployment yourself

The same checks this repo's own CI/dev-loop tooling runs locally:

```sh
curl -sS https://<your-app>.up.railway.app/api/v1/health
# {"status":"ok","version":"1.40.0"}

# Everything else requires the bearer token once HSE_AUTH_TOKEN is set:
curl -sS -H "Authorization: Bearer $HSE_AUTH_TOKEN" \
  https://<your-app>.up.railway.app/api/v1/scans
```
