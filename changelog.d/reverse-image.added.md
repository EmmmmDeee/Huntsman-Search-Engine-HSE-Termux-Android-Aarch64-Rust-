- `reverse-image IMAGE-FILE [--live --provider NAME] [--json]` prints the SHA-256, size and
  format of a local image without sending anything: no search runs, and the report says so
  instead of listing zero matches. `--live --provider google_vision|lenso|saucenao` uploads the
  whole image to that one provider (Google Cloud Vision web detection, Lenso or SauceNAO) and
  lists what its own index returned. `--live` without `--provider` is refused, so the image never
  goes to more than one provider. Each provider uses the operator's own key from a new slot
  (`HUNTSMAN_GOOGLE_VISION_KEY`, `HUNTSMAN_LENSO_KEY` or `HUNTSMAN_SAUCENAO_KEY`), and each key
  goes only to its own provider: Google's in a header, Lenso's as a bearer token and SauceNAO's
  as the `api_key` parameter of the request, never inside the uploaded image. The three slots
  show on the Settings page and in `credential-status`. A provider with no key is asked nothing,
  and a failed search is reported as a failure, never as "no matches". Matches are leads about
  where a picture is reused, never proof of who is in it. CLI only: there is no web route or web
  UI panel.
