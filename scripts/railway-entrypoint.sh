#!/bin/sh
set -eu

DATA_DIR="${RAILWAY_VOLUME_MOUNT_PATH:-${HUNTSMAN_DATA_DIR:-/data}}"
PORT_VALUE="${PORT:-8080}"

case "$PORT_VALUE" in
  ''|*[!0-9]*) echo "huntsman-entrypoint: invalid PORT: $PORT_VALUE" >&2; exit 64 ;;
esac
if [ "$PORT_VALUE" -lt 1 ] || [ "$PORT_VALUE" -gt 65535 ]; then
  echo "huntsman-entrypoint: PORT must be in 1..65535" >&2
  exit 64
fi

export HUNTSMAN_DATA_DIR="$DATA_DIR"
export HOME="$DATA_DIR"
export HSE_BIND="${HSE_BIND:-0.0.0.0:$PORT_VALUE}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR/.huntsman" "$DATA_DIR/var"
  chown huntsman:huntsman "$DATA_DIR" "$DATA_DIR/.huntsman" "$DATA_DIR/var" 2>/dev/null || true
  chown -R huntsman:huntsman "$DATA_DIR/.huntsman" "$DATA_DIR/var" 2>/dev/null || true
else
  mkdir -p "$DATA_DIR/.huntsman" "$DATA_DIR/var"
fi

TOKEN_FILE="$DATA_DIR/.huntsman/railway-auth-token"
generated_token=0
if [ -z "${HSE_AUTH_TOKEN:-}" ]; then
  if [ -r "$TOKEN_FILE" ]; then
    IFS= read -r HSE_AUTH_TOKEN < "$TOKEN_FILE" || true
  fi
  if [ -z "${HSE_AUTH_TOKEN:-}" ]; then
    HSE_AUTH_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [ -n "$HSE_AUTH_TOKEN" ] || {
      echo "huntsman-entrypoint: failed to generate HSE_AUTH_TOKEN" >&2
      exit 70
    }
    umask 077
    printf '%s\n' "$HSE_AUTH_TOKEN" > "$TOKEN_FILE"
    chmod 0600 "$TOKEN_FILE"
    if [ "$(id -u)" = "0" ]; then
      chown huntsman:huntsman "$TOKEN_FILE" 2>/dev/null || true
    fi
    generated_token=1
  fi
  export HSE_AUTH_TOKEN
fi

if [ "$generated_token" = "1" ]; then
  printf 'huntsman-entrypoint: generated HSE_AUTH_TOKEN=%s\n' "$HSE_AUTH_TOKEN" >&2
  printf 'huntsman-entrypoint: set HSE_AUTH_TOKEN as a Railway variable to keep the same token without relying on /data persistence\n' >&2
fi

run_huntsman() {
  if [ "$(id -u)" = "0" ]; then
    gosu huntsman "$@"
  else
    "$@"
  fi
}

if [ "${HUNTSMAN_STARTUP_CHECK:-1}" != "0" ]; then
  check_dir="$(mktemp -d /tmp/huntsman-startup-check.XXXXXX)"
  if [ "$(id -u)" = "0" ]; then
    chown huntsman:huntsman "$check_dir"
  fi
  old_pwd="$(pwd)"
  cd "$check_dir"
  run_huntsman /usr/local/bin/huntsman-recon check >/dev/null
  run_huntsman /usr/local/bin/huntsman-recon verify var/ledger.json >/dev/null
  cd "$old_pwd"
  rm -rf "$check_dir"
fi

cd "$DATA_DIR"
if [ "$#" -eq 0 ]; then
  set -- serve
fi
if [ "$1" = "huntsman-recon" ]; then
  shift
fi

if [ "$(id -u)" = "0" ]; then
  exec gosu huntsman /usr/local/bin/huntsman-recon "$@"
fi
exec /usr/local/bin/huntsman-recon "$@"
