- A lookup whose stderr cannot be written no longer dies at the skipped-keys-file warning. With
  `~/.huntsman.env` at mode 0644 (or a symlink), `huntsman-recon phone +61412345678 --save p.json`
  with stderr on a pipe whose reader had gone, or on `/dev/full`, exited 141 (or 74) while it
  collected, before it wrote `p.json`; under `serve`, a `/api/lookup` or `/api/settings` request
  that met the same warning ended the whole server. The same happened to `scan` at its `scan_route=` line, before it handed over to the lookup, and to `scan --input-file` at its batch progress lines. These lines and the warning are now plain writes that ignore
  a failed stderr, so the lookup saves its ledger and exits on its own result, and `serve` keeps
  running. Nothing changes while stderr is writable. Tests in `tests/closed_output.rs` hold both
  and fail on the previous code.
