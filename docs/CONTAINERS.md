# Optional self-hosted container

The supported primary runtime is unprivileged Android Termux on AArch64. The repository also retains a portable, provider-neutral Linux container image as an optional self-hosted deployment target. No managed hosting service, infrastructure-as-code SDK or cloud account is required.

Build the pinned-image Dockerfile from the repository root:

```sh
docker build --build-arg HUNTSMAN_BUILD_SHA="$(git rev-parse HEAD)" -t huntsman-recon:local .
docker run --rm --name huntsman-recon -p 127.0.0.1:18080:8080 \
  -v huntsman-data:/data -e HSE_AUTH_TOKEN="YOUR_SECRET_TOKEN" \
  huntsman-recon:local
```

Only bind the host loopback interface in the sample. The container internally listens on port 8080. The generic entrypoint validates `PORT`, explicitly sets `HSE_BIND`, runs the offline startup acceptance, and runs the binary without root as uid 10001. It forwards stop signals and preserves state under `/data`. If a bearer token is not provided, it creates and saves a 256-bit random token privately at `/data/.huntsman/container-auth-token`; the secret itself is not printed. Attach durable storage if that token and scan data must survive container replacement. To inspect it locally, access the mounted volume rather than the deployment logs.

Health: `http://127.0.0.1:18080/api/health`. To verify authenticated endpoints, supply the token and execute:

```sh
HUNTSMAN_CONTAINER_URL=http://127.0.0.1:18080 HSE_AUTH_TOKEN="YOUR_SECRET_TOKEN" \
HUNTSMAN_EXPECTED_SHA="$(git rev-parse HEAD)" \
  bash scripts/container-live-acceptance.sh
```

The harness permits plain HTTP only on loopback; remote hosts require HTTPS. Local and Termux `serve` operations remain loopback-only unless explicitly configured with `--bind` or `HSE_BIND`; no container platform variable can silently widen the bind.
