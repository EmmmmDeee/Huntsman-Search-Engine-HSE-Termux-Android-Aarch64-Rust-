- `reverse-image IMAGE-FILE [--live] [--provider NAME] [--json]` prints the SHA-256 of a local
  image without sending anything. With `--live` it uploads the whole image to the configured
  Google Cloud Vision web detection, Lenso or SauceNAO reverse-image index, or only to the one
  `--provider` names, each with the operator's own key from a new slot
  (`HUNTSMAN_GOOGLE_VISION_KEY`, `HUNTSMAN_LENSO_KEY` or `HUNTSMAN_SAUCENAO_KEY`). Each key goes
  only to its own provider: Google's in a header, Lenso's as a bearer token and SauceNAO's as the
  `api_key` parameter of the request, never inside the uploaded image. The three slots show on
  the Settings page and in `credential-status`. A provider with no key, or one that fails, is
  reported as such, never as "no matches". CLI only: there is no web route or web UI panel.
