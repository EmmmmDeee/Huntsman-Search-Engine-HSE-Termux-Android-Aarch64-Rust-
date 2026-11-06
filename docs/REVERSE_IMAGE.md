# Reverse-image search

`reverse-image` takes a **local image file**. Offline, it prints the file's SHA-256, size and
format and sends nothing: no search runs, so the report holds no matches to read, rather than
zero matches. With `--live --provider NAME` it uploads the picture, **without its embedded
metadata**, to that **one** provider and reports what the provider's own index returned. A
returned match is evidence about **image reuse**, never proof that two profiles share an owner.

```sh
huntsman-recon reverse-image /path/to/photo.jpg --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider google_vision --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider lenso --json
huntsman-recon reverse-image /path/to/photo.jpg --live --provider saucenao --json
```

**The operator picks the recipient.** `--live` without `--provider` is refused (exit 64), and so
is `--provider` without `--live`. No run sends the image to more than one provider, and no scan,
lookup or web route sends it at all: the command is CLI only. A live search may cost provider
credits.

| Provider | `--provider` | Credential slot | Search | Where the key goes |
| --- | --- | --- | --- | --- |
| Google Cloud Vision | `google_vision` | `HUNTSMAN_GOOGLE_VISION_KEY` | `WEB_DETECTION` ([docs](https://docs.cloud.google.com/vision/docs/detecting-web)) | `X-goog-api-key` header, to `vision.googleapis.com` only ([API keys](https://docs.cloud.google.com/docs/authentication/api-keys-use)) |
| Lenso.ai | `lenso` | `HUNTSMAN_LENSO_KEY` | `duplicates` ([docs](https://github.com/lenso-ai/reverse-image-search-api)) | `Authorization: Bearer`, to `api.lenso.ai` only |
| SauceNAO | `saucenao` | `HUNTSMAN_SAUCENAO_KEY` | every index, `db=999` ([docs](https://saucenao.com/user.php?page=search-api)) | `api_key` query parameter, to `saucenao.com` only |

Keys are read from `$HOME/.huntsman.env` (mode 600) or the environment, through the credential
path every keyed source uses: a key goes only to its provider's origin, is added to the request
only as it is sent, is never carried through a redirect, and is scrubbed from every diagnostic.
SauceNAO's API takes its key as the `api_key` query parameter, which is how SauceNAO's own
example client sends it beside the uploaded file; the URL Huntsman builds holds no key, recorded
URLs drop their query, and the uploaded form never holds it. Configure only services you are
authorised to use, and do not upload personal or sensitive photographs without authority to do
so: the provider receives the image.

## What is uploaded, and what is read

The provider receives the file exactly as it was read: every byte, with all of its embedded
metadata. Nothing is removed or rewritten. A JPEG keeps its Exif (with any GPS position), XMP,
IPTC, ICC profile, maker notes and comments, a PNG its `eXIf` and text chunks, a WebP its `EXIF`
and `XMP ` chunks, and anything after the end of the image goes too. JPEG, PNG, WebP and GIF files
are uploaded alike. The upload is labelled with a generic file name (`image.jpg`), not the local
one. The JSON report's `upload` gives the SHA-256 and size of the bytes sent, which are the file's
own.

Every report, offline or live, also reads that metadata through the same reader the `exif` and
`docmeta` commands, the web inspect view and `investigate --file` use (`embedded_metadata`):

- the document entity, with every Exif, XMP, IPTC and PDF field kept as evidence;
- the GPS position as a coordinates entity, which reverse-geocodes, takes geohash and area
  checks and joins the rest of an investigation like any other point;
- every email address, link, domain, IP address or phone number written into a field people
  write (an author, rights, contact, comment or description field) as an entity of its own,
  attributed to the file and to the field that holds it. A value the camera or a program writes
  for itself (a serial number, an identifier, a version, a time) is read only for an email
  address or a link, so its digits are never taken for a phone number.

The JSON report holds them under `metadata` (`entities` and the two readers' `outcomes`), and the
text report prints them as the `exif` and `docmeta` commands do.

## Result states

- `"search": "not_run"`: nothing was sent. Either `--live` was not given, the provider's key is
  not configured (`outcome.kind` is `not_configured`, exit 66), or the request was refused before
  sending (exit 77). `matches` is `null`.
- `"search": "failed"`: the image was sent and no answer could be read: a transport failure, an
  HTTP or provider error, a rate limit, a challenge page, or an answer that is not the provider's
  documented shape. `matches` is `null`, the `outcome` says why, and the exit is 69. It is never a
  negative result.
- `"search": "completed"`: the provider answered. `matches` lists what it returned from its own
  index, at most 80, and `truncated` says when it returned more. An empty list means that
  provider's index held no match, not that the picture is nowhere else.

`file_sha256`, `file_bytes` and `format` describe the file as read, and `upload` (once a request
was sent) the bytes that were uploaded, which are the same; `observed_at_unix` is when the command
ran.
`match_type` and `provider_score` are the provider's own, **never identity probabilities**. No
local perceptual hashing or face recognition is done: the provider does its own matching.

**Limits:** 4 MiB per file, read through Huntsman's bounded reader, which refuses a symbolic link
and a file that changes during the read; at most 80 matches; one request per search, within the
20-second API leg timeout, with no retries and no redirects. The file may be a JPEG, PNG, WebP or GIF
by its first bytes, offline and live. CLI only: there is no
web route or Web UI panel.

To check an install offline, `huntsman-recon reverse-image ./known.jpg --json` must print
`"search": "not_run"` and `"matches": null`. For a real external check, use a non-sensitive image
known to occur on a public web page, configure one provider's key, run
`--live --provider NAME`, and verify the returned source URLs independently. A failed search is
never a clean negative.

## Instagram QR and image provenance

A QR graphic and a username identify a profile destination, **not the photo bytes**
needed for visual matching. Export or save the actual publicly accessible profile
photo to the phone, then pass its image file to the CLI. An identical image can be
reused by unrelated accounts; neither exact-image matches nor visually similar
images establish that two profiles are controlled by the same person.
