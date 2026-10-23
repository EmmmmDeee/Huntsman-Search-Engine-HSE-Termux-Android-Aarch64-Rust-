- A lookup whose stderr cannot be written no longer dies at the skipped-keys-file warning. With
  `~/.huntsman.env` at mode 0644 (or a symlink), `huntsman-recon phone +61412345678 --save p.json`
  with stderr on a pipe whose reader had gone, or on `/dev/full`, exited 141 (or 74) while it
  collected, before it wrote `p.json`; under `serve`, a `/api/lookup` or `/api/settings` request
  that met the same warning ended the whole server. The warning is now a plain write that ignores
  a failed stderr, so the lookup saves its ledger and exits on its own result, and `serve` keeps
  running. Nothing changes while stderr is writable. A test in `tests/closed_output.rs` holds it
  and fails on the previous code.
