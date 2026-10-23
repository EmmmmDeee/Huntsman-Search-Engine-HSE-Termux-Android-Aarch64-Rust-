- The warning and error for a symlinked `~/.huntsman.env`, or for one whose owner cannot be
  checked, no longer tell you to pass `--keys`. They are printed by lookups such as
  `huntsman-recon ip 8.8.8.8`, by `keys set` and `keys remove`, and by the Settings page, and none
  of those takes `--keys`, so following the advice gave a usage error. A symlink now reads `it is
  a symlink; remove the symlink and create a regular file owned by you with mode 600`. An unknown
  uid now ends `; set the keys in the environment instead`, which works everywhere because every
  slot falls back to the environment. `doctor`'s `env_file` fix for an unknown uid changes from
  `pass --keys FILE to each command` to the same environment advice.
