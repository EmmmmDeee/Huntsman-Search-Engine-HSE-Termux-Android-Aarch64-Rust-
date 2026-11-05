- `reverse-image IMAGE-FILE [--live] [--provider NAME] [--json]` prints the SHA-256 of a local
  image without sending anything. With `--live` it uploads the whole image to the configured
  Google Cloud Vision web detection, Lenso or SauceNAO reverse-image index, or only to the one
  `--provider` names, each with the operator's own key from a new slot
  (`HUNTSMAN_GOOGLE_VISION_KEY`, `HUNTSMAN_LENSO_KEY` or `HUNTSMAN_SAUCENAO_KEY`). A provider
  with no key, or one that fails, is reported as such, never as "no matches". CLI only: there is
  no web route or web UI panel.
