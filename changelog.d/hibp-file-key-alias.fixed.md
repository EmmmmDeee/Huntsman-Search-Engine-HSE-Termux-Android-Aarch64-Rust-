- A `HIBP_API_KEY` line in `~/.huntsman.env` (for example from
  `huntsman-recon keys set HIBP_API_KEY --stdin`) is now used by the lookups, as
  `credential-status` already reported it was. `credential-status` printed
  `provider=HIBP` with `state=configured`, but with neither `HIBP_API_KEY` nor `HUNTSMAN_HIBP_KEY` in
  the environment, keyed `hibp` subcommands exited 66 with `no API key for this keyed lookup`,
  and `exposure`, `scan -k exposure` and `/api/lookup` skipped the HIBP account leg as `no
  operator key configured; no request made`. The loader now reads the `HUNTSMAN_HIBP_KEY` slot by
  the same rule `credential-status` uses (`provider_credentials::secret_for_slot`, now public): an
  `HIBP_API_KEY` environment variable first, then the `HUNTSMAN_HIBP_KEY` slot (the file, then the
  environment), then a `HIBP_API_KEY` line in the file, then `~/.config/hibp/api_key`. A unit test
  in `src/cli/credentials.rs` holds it and fails on the previous code.
