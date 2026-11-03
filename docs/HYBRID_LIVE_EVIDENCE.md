# Live public-source and hybrid OSINT evidence on Termux

## Contract

The `fetch --body` command is a human-readable diagnostic that prints status and
a lossy UTF-8 version of the provider body. It is **not** a byte-preserving source
capture. Use `fetch PUBLIC_HTTPS_URL --raw-body` to stream the complete response
body bytes to stdout, with **no status line, decoding into a String, formatting,
redaction, or terminal markup**. Public HTTPS URLs only; the parser refuses
`--allow-private`, `--bearer`, `--header` and `--keys` in raw mode.

The raw mode fails before emitting any bytes for a truncated transport response,
a non-2xx HTTP response or a classified challenge/WAF/error. The hybrid
script supplies `--max-redirects 0`, so a redirected response is not silently
attributed to the initial URL; a 3xx is a failed capture, not evidence. An ordinary HTTP
200 body remains an *observed response body*, **not** evidence that a returned
claim is correct. The body is whatever bytes the Huntsman HTTP transport provides
after HTTP-layer handling, **not** a packet capture, TLS wire trace, or a signed
provider provenance attestation.

## Hybrid collection (source bytes + index discovery + offline extraction)

On a checked-out build containing the new raw-body mode:

```bash
bash scripts/termux-hybrid-evidence.sh \
  "https://www.example.org/" \
  "example.org public information"
```

The script uses only the actual Huntsman Rust binary for outbound HTTP and
extraction. Bash orchestrates bounded execution, SHA-256 checksums and private
on-device atomic storage. Only use public data or data you are authorised to
collect; the script does not solicit API keys or execute breach dumps.

Each completed receipt is under `$HUNTSMAN_HOME/hybrid/receipt-XXXXXX` (else
`~/.huntsman/hybrid`) with private files:

- `source-body.bin` — unredacted original **transport response body bytes**.
- `search-discovery.json` — unmodified JSON output of
  `huntsman-recon query --adaptive`, including exact discovered URLs.
- `extracted-candidates.txt` — output of offline `investigate --file`;
  extraction failures are recorded, not mistaken for no identifiers.
- `manifest.json` — exact binary build SHA, first collection timestamp,
  source URL, body byte count, separate SHA-256 digests of those three files,
  typed per-provider outcomes and semantic limitations.

A `PASS` requires a complete non-challenge public 2xx source response,
a successful offline candidate extraction and at least one observed
search-engine discovery lead with a zero command exit.
In other cases a successfully retrieved source body remains saved and tagged
`PARTIAL` (exit 69). A failed raw retrieval publishes no completed receipt.
Source capture has a 1 MiB local admission limit. Search and extracted outputs
are individually limited to 1 MiB. If those limits are insufficient, do not
silently truncate bytes and then claim source completeness.

**Do not equate any of the following:** HTTP 200, search index inclusion,
identical URL appearances across search engines, offline matching of entity
strings, independent primary-source corroboration, authenticated provenance,
or correct current real-world identity attribution.

Use `sha256sum source-body.bin` and compare it with
`manifest.json.source.body_sha256` to verify local integrity; likewise for
the discovery and extracted-candidate files. A digest proves consistency of
retained bytes, not their truth or original publication time.

## Device acceptance and compatibility

```bash
bash scripts/termux-runtime-acceptance.sh
bash tests/termux_online_acceptance.sh
bash tests/termux_hybrid_evidence.sh

# Separately, with live internet on physical Android/Termux:
bash scripts/termux-online-acceptance.sh
```

The first script is the previously established offline handset acceptance.
The mock tests use a fake binary to prove that raw bytes survive and false
online successes are rejected, not real internet access. The live probe uses
a fixed, non-personal search query and preserves typed provider outcomes.
Actual handset acceptance of the new `--raw-body` mode and hybrid script
requires building/installing the reviewed Rust commit, running the scripts
on the phone and checking stored manifest digests.

A source record remains `observed` until an independent corroborating origin
is checked against its exact claim. Provider status and raw evidence stay
separate in the ledger; no private keys are printed or saved by this workflow.
