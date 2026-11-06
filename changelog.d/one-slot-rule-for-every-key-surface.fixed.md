- `credential-status`, its `--probe` and the web UI's key settings now report each provider key
  by the rule the lookups use it by. Before, the lookups and `dehashed search` read
  `~/.config/dehashed/api_key`, while `credential-status` reported DeHashed as `incomplete`,
  probed nothing, and the settings page showed it unset.
  - **One source of keys.** The keys file, the environment and DeHashed's own key file are read
    once, through the private-file gate `~/.huntsman.env` passes.
  - **Refused key file.** A key file others can read is named on stderr, and on the settings page,
    with `chmod 600` for that file, not for `~/.huntsman.env`.
  - **What the settings page shows.** It reports every key a lookup would use as set:
    - the shared abuse.ch key on URLhaus and ThreatFox;
    - HIBP's own `HIBP_API_KEY`;
    - DeHashed's key file.
    It says where a key it did not save is: in the environment, by another slot, or in the file.
