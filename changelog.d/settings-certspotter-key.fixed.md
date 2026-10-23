- The web UI's Settings page shows Cert Spotter's optional key. `GET /api/settings` gave the
  `certspotter` module `key_env: []` and `configured: null`, so the page showed no set/not-set
  label and no key editor for it, although `HUNTSMAN_CERTSPOTTER_KEY` raises its limit and
  `/api/settings/keys` can save it. It now gives `key_env: ["HUNTSMAN_CERTSPOTTER_KEY"]` and
  `configured` true or false, and the page offers Set key or Change key for Cert Spotter.
