# Railway deployment — Huntsman Recon

This is the current `huntsman-recon` deployment path. The preserved legacy
`hse` Railway adapter remains at `deploy/railway/Dockerfile` so existing
legacy services are not silently downgraded or replaced.

## Current deployment contract

New Railway services can point directly at this repository's `main` branch.
Railway detects the root `Dockerfile` automatically. The container:

- builds the root `huntsman-recon` crate with the locked Cargo graph;
- runs the current server as an unprivileged uid after startup preparation;
- listens on Railway's injected `PORT`;
- exposes `/api/health` without authentication for Railway deployment health checks;
- requires a bearer token for protected metadata endpoints;
- runs the offline `check` and ledger verification before starting by default;
- uses `RAILWAY_VOLUME_MOUNT_PATH` when a Railway volume is attached, otherwise
  `/data`.

The entrypoint accepts `HSE_AUTH_TOKEN`. If it is absent, a 256-bit token is
generated from `/dev/urandom`, stored at
`$HUNTSMAN_DATA_DIR/.huntsman/railway-auth-token`, and printed once to the
deployment log. Set `HSE_AUTH_TOKEN` as a Railway variable for a stable token
that does not depend on volume persistence.

## Healthcheck

Use:

```text
/api/health
```

Railway injects `PORT` and uses that port for deployment health checks.
`huntsman-recon serve` also detects Railway directly, so the correct
`0.0.0.0:$PORT` bind does not depend solely on the container entrypoint.

## Persistent data

Persistence is optional. For durable relative outputs, attach one Railway volume
at `/data`. The image can start without a volume; in that case `/data` is
ephemeral and a generated authentication token can change after redeployment.

## Live acceptance

Use the repository-owned acceptance harness after Railway reports the candidate
deployment healthy. Keep the bearer token in the environment rather than a
positional argument so it is not copied into shell history:

```sh
HUNTSMAN_RAILWAY_URL=https://YOUR-SERVICE.up.railway.app \
HSE_AUTH_TOKEN="$HSE_AUTH_TOKEN" \
  bash scripts/railway-live-acceptance.sh
```

The harness is also used by CI against the built container, so live and local
acceptance cannot silently drift. A pass requires:

- `GET /api/health` -> HTTP 200 with `status=ok`;
- unauthenticated `GET /api/modules` -> HTTP 401;
- authenticated `GET /api/modules` -> HTTP 200 with a module catalogue;
- authenticated `GET /api/command` -> HTTP 200 with the command invariant.

Before promotion, independently verify in Railway that the successful
deployment metadata names the exact commit intended for release. HTTP
acceptance proves runtime behavior; Railway deployment metadata supplies the
source-revision binding.

## Infrastructure as Code

`.railway/railway.ts` is the current Railway Infrastructure-as-Code entry
point. It intentionally does not create a paid volume automatically. Apply it
with the Railway CLI only after linking the intended project/environment.

```sh
railway config plan
railway config apply
```

The older `railway.toml` / `railway.json` Config-as-Code system is not used
for new Huntsman deployments.
