#!/bin/sh
# Reconciles ownership of $HOME (/data) before dropping to the unprivileged
# `hse` user, then execs the real command as that user.
#
# Why this exists: a bind mount or a Railway persistent Volume at /data
# always carries the HOST side's ownership — it does NOT inherit the `chown`
# baked into the image by `useradd --create-home` in the Dockerfile. Without
# this reconciliation, any deployment that actually mounts a volume at /data
# (the entire point of one — surviving a redeploy) crash-loops on
# "unable to open database file", verified by mounting a plain host
# directory at /data and watching `hse` fail to start with exactly that
# error. A container with NO mounted volume never hits this: /data already
# belongs to `hse` from the image layer, so the check below is a no-op.
set -eu

if [ "$(stat -c '%u' "$HOME")" != "$(id -u hse)" ]; then
    chown hse:hse "$HOME"
    # Reconcile any content a previous run already left on the volume (e.g.
    # a volume attached mid-life, or restored from a snapshot) — but not on
    # every startup, only when the top-level directory itself needed it.
    find "$HOME" -mindepth 1 -not -user hse -exec chown hse:hse {} +
fi

exec gosu hse "$@"
