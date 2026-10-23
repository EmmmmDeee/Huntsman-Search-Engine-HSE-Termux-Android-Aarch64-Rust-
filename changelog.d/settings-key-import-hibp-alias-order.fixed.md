- Importing keys on the Settings page (or `POST /api/settings/keys` with `import=`) now saves the
  HIBP key that a keys file holding the same lines gives `credential-status` and the lookups. For
  the text `HUNTSMAN_HIBP_KEY=NEW` followed by `HIBP_API_KEY=OLD`, the import wrote
  `HUNTSMAN_HIBP_KEY='OLD'` to `~/.huntsman.env`, because a later line replaced an earlier one
  whichever name it used. Read as a keys file, the same text gives `NEW`, since a `HIBP_API_KEY`
  line counts only when nothing sets `HUNTSMAN_HIBP_KEY`. The import now follows that rule. A
  `HUNTSMAN_HIBP_KEY` or `sfp_haveibeenpwned:api_key` line wins over a `HIBP_API_KEY` line in
  either order, and a `HIBP_API_KEY` line alone still fills the slot. A placeholder line is
  still skipped rather than read as unsetting the slot, so `HUNTSMAN_HIBP_KEY=NEW`,
  `HUNTSMAN_HIBP_KEY=changeme`, `HIBP_API_KEY=OLD` imports `NEW`, where a keys file reads `OLD`.
  The answer's `slots`, `unused` and `settings` are unchanged.
