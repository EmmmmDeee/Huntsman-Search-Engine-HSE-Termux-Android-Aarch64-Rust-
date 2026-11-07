- `credential-status`, its `--probe` and the web UI's key settings now count HIBP's own private
  key file, `~/.config/hibp/api_key`, as the `HUNTSMAN_HIBP_KEY` key. Every HIBP lookup reads
  that file last. Before, a key kept only there was used by the lookups while `credential-status`
  reported HIBP `incomplete`, the probe checked nothing, and the settings page showed it unset.
  - **Refused file.** A file others can read is named with `chmod 600` for that file, as
    DeHashed's is.
  - **`hibp subscription`.** It still names the file, `file:PATH`, as the key's source.
