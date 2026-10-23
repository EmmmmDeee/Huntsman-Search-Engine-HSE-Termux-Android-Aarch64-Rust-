- The web UI's Settings page shows Cert Spotter's optional key. `GET /api/settings` gave the
  `certspotter` module `key_env: []` and `configured: null`, so the page showed no set/not-set
  label and no key editor for it, although `HUNTSMAN_CERTSPOTTER_KEY` raises its limit and
  `/api/settings/keys` can save it. It now gives `key_env: ["HUNTSMAN_CERTSPOTTER_KEY"]` and
  `configured` true or false, and the page offers Set key or Change key for Cert Spotter.
- The Settings page shows the key of every module that takes one. `GET /api/settings` also gave
  `key_env: []` and `configured: null` to `hibp_account` (HIBP's account search in `exposure`),
  `wigle_bluetooth` and `opencellid`, so the page showed no set/not-set label for them.
  `hibp_account` now lists HIBP's slots and `wigle_bluetooth` WiGLE's, as `hibp` and `wigle` do,
  and `opencellid` lists `HUNTSMAN_OPENCELLID_KEY`. That slot joins the credential catalogue, so
  `credential-status` and `GET /api/settings/keys` list OpenCelliD, the Settings page can save its
  key, and `docs/PROVIDER_CREDENTIALS.md` names it. `doctor`'s keys check and `diagnostics`'
  `providers_total` count it too, so a keys file holding only an OpenCelliD key now reads as one
  configured provider.
- A module whose key takes two slots, WiGLE's user and token, reads as set on the Settings page
  only when both hold a key, as `credential-status` reads it; one slot alone used to read as set.
  HIBP's slot still reads as set through `HIBP_API_KEY`.
