# Native reverse-image search (Rust / Termux)

The command accepts a **local image file**. It computes a SHA-256 digest offline, and can
optionally send the image to three independent reverse-image indexes. A returned visual
match is evidence about **image reuse**, never proof that two profiles share an owner.

```sh
huntsman-recon reverse-image /path/to/photo.jpg --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider google_vision --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider lenso --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider saucenao --json
```

**No external requests are sent without `--live`.** With `--live`, all configured
providers are requested once unless `--provider NAME` restricts the query. Requests may consume provider quotas or incur charges.
Provider keys are read through Huntsman's existing `$HOME/.huntsman.env` and environment
resolution; store the file with mode 600. Slots:

| Provider | Credential slot | Search | Provenance |
| --- | --- | --- | --- |
| Google Cloud Vision | `HUNTSMAN_GOOGLE_VISION_KEY` | WEB_DETECTION | [Google documentation](https://docs.cloud.google.com/vision/docs/detecting-web) |
| Lenso.ai | `HUNTSMAN_LENSO_KEY` | duplicates | [Lenso API](https://github.com/lenso-ai/reverse-image-search-api) |
| SauceNAO | `HUNTSMAN_SAUCENAO_KEY` | db 999 | [SauceNAO](https://saucenao.com/) |

Only configure services for which the operator has authorized API access and accepted
applicable terms. Third-party providers receive image bytes when called. Do not submit
personal or sensitive photographs without appropriate authorization. Credentials are
never written to reports. Each key is read only from its slot and sent only to its
provider's origin, added to the request as it is sent: Google Cloud Vision's in the
`X-goog-api-key` header, Lenso's as `Authorization: Bearer`, and SauceNAO's as the
`api_key` query parameter, which is how SauceNAO's API takes it, never inside the
uploaded form. Recorded URLs drop their query, and redirects are not followed.

## Result states

* `not_requested`: no external call because `--live` was omitted.
* `unconfigured`: provider key missing; never interpret this as no matches.
* `failed`: the provider returned a transport/HTTP/schema error; not a negative result.
* `completed`: provider replied with valid JSON. `results=0` then means no matches
  returned **by that provider**, not absence from the wider internet.

`image_sha256` identifies the exact image bytes uploaded. The response includes
`observed_at_unix`, `truncated`, and `shared_image_urls` (the exact same image URL
reported by more than one service; this is source-index agreement, not proof of identity).
The CLI now uses Huntsman's bounded, symlink-refusing file reader, not an unbounded
read between a file-stat and the subsequent open. No local perceptual
hashing or face recognition is claimed by this release; providers perform their own
matching. `match_type` and `provider_score` are provider-specific, **not identity
probabilities**. Google results may be full, partial or visual. Lenso provides its
duplicate category. SauceNAO predominantly covers its specialised indexed sources.

**Limits:** 4 MiB per file, at most 80 retained matches, 30 seconds per provider,
no automatic retries or redirects. The file must be a local JPEG/PNG/GIF/WebP by
magic bytes. The signature check is not a full decoder, so invalid/truncated images
can still be rejected by the provider. The command is available from the Termux CLI
only: there is no web route or Web UI panel.

To verify:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
huntsman-recon reverse-image ./known.jpg --json
```

The last offline command must show all three providers as `not_requested`.
For a real external integration test, use a non-sensitive image known to occur on a
public web page, configure exactly one provider key, run `--live` and verify both
the API response and independent existence of its returned source URLs. Repeat for
the other configured providers. A single provider failure cannot be treated as a
clean negative.

## Instagram QR and image provenance

A QR graphic and a username identify a profile destination, **not the photo bytes**
needed for visual matching. Export or save the actual publicly accessible profile
photo to the phone, then pass its image file to the CLI. An identical image can be
reused by unrelated accounts; neither exact-image matches nor visually similar
images establish that two profiles are controlled by the same person.
