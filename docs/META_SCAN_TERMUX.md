# Native MetaScan for unrooted Termux (Android aarch64)

This is a **Rust port of the four implemented** [HackUnderway MetaScan](https://github.com/HackUnderway/meta_scan) Facebook Pages Scraper 3 operations **plus a keyless discovery mode** using Huntsman's existing guarded web-index search. It is a standalone Huntsman binary with a mobile Web UI, not a replacement for the existing `huntsman-recon` UI.

**Modes:** Keyless indexed URL discovery is the default and does not require a subscription, an API key or paid quota; it produces **URL leads only**, never Facebook profile metadata or identity verification. The four richer profile/business collection operations run **only if the operator explicitly selects `--provider`, `--combined`, or a corresponding option in the Rust-rendered Web UI form**. Those routes still depend on an independent RapidAPI subscription. Missing records, restricted access, rate limits and blocked indexes are **not** interpreted as proof that an account is absent.

## Run on Android Termux (no root)

From the Huntsman repository in your Termux home directory:

```sh
pkg install rust clang make pkg-config
cargo build --locked --release --bin meta_scan
```

The binary is `target/release/meta_scan`. To start the browser UI:

```sh
target/release/meta_scan --serve
```

Visit **http://127.0.0.1:8787/** in Android Chrome or your preferred local browser. No root, privileged port, Python, Node.js, CDN, or externally hosted JavaScript is needed. The UI serves HTML and CSS generated from Rust source without JavaScript or WASM and binds **only to loopback**, including when you specify `--bind`.

For long sessions, Termux may require keeping the terminal awake; the existing Huntsman Termux wakelock wrapper can be used. Builds use Huntsman's existing release profile (thin LTO and symbol stripping). This binary adds no new Rust crate dependencies.

## Provider configuration

Obtain a key and subscription directly from the independent Facebook Pages Scraper 3 provider on RapidAPI, if available. This can incur charges; **do not subscribe or spend credits without verifying current plan terms**.

The port reads `RAPIDAPI_KEY` from Huntsman's standard key-resolution mechanism. You can configure it through the environment or through `~/.huntsman.env`:

```sh
# Open an editor and add a line: RAPIDAPI_KEY=<your actual key>
nano ~/.huntsman.env
chmod 600 ~/.huntsman.env
```

Do not paste credentials into the browser; they are sent only to the fixed RapidAPI host and are not returned to clients or stored in reports. Existing Huntsman key precedence applies: the private keys file overrides the environment.

## CLI commands

```sh
# Free keyless public-index discovery (default; URL leads only)
target/release/meta_scan -u nasa --show-raw

# Explicit paid-provider opt-in (four original endpoints)
target/release/meta_scan -u nasa --provider --show-raw
# Combined report: keyless public indexed URL leads + all four provider endpoints
# Explicitly uses the configured RapidAPI subscription; may incur billable quota.
target/release/meta_scan -u nasa --combined --out-json ./reports --out-txt ./reports


# Provider profile only (do not call the three business endpoints)
target/release/meta_scan -u nasa --provider --no-business

# Structured JSON and readable TXT, saved to private local files
target/release/meta_scan -u nasa --out-json ./reports --out-txt ./reports

# Up to 200 usernames, one per line (# comments ignored); keyless by default
target/release/meta_scan --batch handles.txt --out-json ./reports

# Mobile Web UI on a different unprivileged loopback port
target/release/meta_scan --serve --bind 127.0.0.1:8788

# Override provider request cap (both timeouts 1..120 seconds)
target/release/meta_scan -u nasa --connect-timeout 10 --read-timeout 20
```

The browser UI supports up to 20 handles per run with sequential, bounded calls and Rust-generated JSON/TXT downloads. **Its default is keyless indexed URL discovery**, showing indexed leads and independent search-engine outcomes. The combined mode keeps both keyless source outcomes and paid provider observations in the same structured report, while explicitly refusing to infer real-world identity from either. When provider enrichment is explicitly selected, it provides separate results for profile, business home, About and transparency. The API key stays server-side.

## Mapping from MetaScan Python

| Original Python capability | Rust port |
|---|---|
| `get-profile-home-page-details` | Yes |
| `get-business-home-page-details` | Yes |
| `get-business-about-details-page` | Yes |
| `get-business-about-profile-transparency-page-details` | Yes |
| `urlSupplier` and profile `url` query parameters | Yes |
| `--no-business` | Yes, with `--provider` |
| `--show-raw` | Yes |
| JSON export | CLI and Web UI |
| TXT export | CLI and Web UI |
| Configurable timeouts | Yes (combined bounded request timeout) |
| HTTP 5xx retry with backoff | Yes, max 3 attempts; 429 is reported without blind paid retries |
| Keyless indexed URL discovery (new) | Yes; three guarded search indexes, direct-page links only |
| Explicit paid-provider opt-in (new) | `--provider` in CLI or form selection in Web UI |
| Keyless + provider combined report | `--combined` or combined mode in the Rust-rendered UI; never enabled automatically |
| Single handle | Yes |
| Batch by file | Added, up to 200 names |
| Web UI | Pure Rust server-rendered HTML forms; mobile-first, localhost-only, no JavaScript, WASM or frontend toolchain |
| Python interactive `--set-api` | Replaced by secure existing Huntsman keys file/environment |
| Python `--donate` | Not included; unrelated to collection |

## Behavioural and resource limits

- HTTPS requests use **Huntsman's shared guarded ureq/rustls transport**, egress policy, maximum 1 MiB response body, disabled redirects, a fixed RapidAPI origin and credential provenance.
- Handle validation prevents arbitrary URLs, query-string injection and open proxying. No login or Facebook cookie collection.
- The Web UI caps headers at 8 KiB, form/JSON request bodies at 4 KiB and simultaneous client sockets at 8. It rejects non-loopback bindings, mismatched Host headers, invalid same-origin submissions and requests lacking a per-process cryptographically random HTML-form token.
- Every HTML form, scan decision, report preview and export is processed by Rust; there is no JavaScript file, WebAssembly module, external template engine, Node.js, Python or CDN. A mobile browser only renders standard HTML/CSS.
- Rust retains the last Web UI batch in a bounded 8 MiB in-process cache for JSON/TXT exports, so exporting does not repeat provider calls or consume additional API quota. Cached results disappear when the process stops.
- Each HTTP collection request is bounded; the Web UI deliberately executes a small number of handles sequentially to avoid exhausting a low-memory Android device.
- Keyless mode queries up to three public search indexes per handle and keeps at most 20 exact, HTTPS, direct-page URL leads from genuine `facebook.com`, `www.facebook.com` or `m.facebook.com` hosts. It excludes posts, lookalike domains and off-platform links, and treats all returned URLs as unverified leads. Search engines may rate-limit or suppress results; zero leads is inconclusive.
- Provider and combined modes are never triggered automatically by a key being present; both may consume paid quota and should be budgeted before scanning large batches.
- Stored JSON/TXT reports have `0600` permissions on Unix/Termux. Reports include raw third-party data, so treat them as private.
- The source returns unverified provider observations; **a successful API response is not proof of ownership or real-world identity**. Field omissions, 404, 403, 429, challenges and malformed JSON must not be treated as absence.
- A device-level Android aarch64 smoke test and a live provider subscription test are separate acceptance gates. x86_64 GitHub CI success alone is not proof of Termux runtime success.

## Test locally or in CI

```sh
cargo fmt --check
cargo test --locked --bin meta_scan
cargo clippy --locked --bin meta_scan -- -D warnings
```

The Rust unit tests use a fake transport; no RapidAPI subscription is consumed.

## Source and licence

Ported as a clean-room reimplementation of the public behaviours of **HackUnderway/meta_scan**, licensed MIT. Source project: https://github.com/HackUnderway/meta_scan . Preserve attribution where distributing derivatives. The implementation contains no Python runtime and no required LLM dependency.
