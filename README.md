# Huntsman Recon

Huntsman Recon is a Rust command-line toolkit for local search, guarded HTTP
fetches, Australian identifier validation, geospatial utilities, and an
append-only evidence ledger. It is designed to make evidence quality and
uncertainty visible; a lead or verified claim is not an attribution or ATT&CK
score.

> **Status:** this is the `huntsman-recon` reconstruction, not the previous
> `hse` monolith. It does not yet provide the old monolith's person-lookups.
> Legacy archives and extracted files are preserved as read-only references,
> not installable/current source. See [architecture and status](ARCHITECTURE.md).

## Install on Termux (Android arm64)

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases), then
run this one-line source install:

```sh
pkg update && pkg install -y git rust clang && HUNTSMAN_HIBP_NO_EMBED=1 cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git --locked --root "$PREFIX" huntsman-recon
```

This builds the current `main` source on-device, installs
`$PREFIX/bin/huntsman-recon`, and prevents accidental build-time embedding of a
locally configured HIBP key. Rust 1.87 or newer is required. For prebuilt,
release-pinned installation, Linux development setup, upgrades, and
troubleshooting, see [`docs/INSTALL.md`](docs/INSTALL.md).

## First commands

```sh
huntsman-recon --help
huntsman-recon check
huntsman-recon search "brisbane port"
huntsman-recon web
```

`check` runs offline self-acceptance. `search` and `sources` are offline; only
`fetch` makes an HTTP request. `fetch` uses public-only egress by default.
`web` starts the loopback-only browser UI at <http://127.0.0.1:8787/>; its first
iteration exposes status/configuration and search over bundled sample records,
not active scans or SpiderFoot compatibility.
Review [`docs/INSTALL.md`](docs/INSTALL.md) and the command reference below
before using credentials or network access.

## Repository map

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI, local-HTTP and legacy-reference integration tests, plus `readme.rs` and `dispositions.rs`, which check this README and `docs/DISPOSITIONS.md` against the binary and `legacy/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | `RECONSTRUCTION_2026-10-02.md` (decisions and falsification passes) and `DISPOSITIONS.md` (per-file accounting of every legacy file). |
| `legacy/` | Byte-identical extraction of both archives. Not part of the build. |
| `*.zip` (root) | The two legacy archives. Pinned by hash in `tests/legacy_reference.rs`; never delete, edit or move them. |

For contributors: one Rust package (`huntsman-recon`), Rust 1.87+, no workspace.
The binary's full command list is available with `huntsman-recon --help`;
run `huntsman-recon COMMAND --help` for command-specific usage.
See the [Termux and SpiderFoot compatibility matrix](docs/COMPATIBILITY.md)
for verified targets and remaining gaps.

```
cargo test
cargo run -- check                     # self-acceptance; regenerates var/*.json
cargo run -- verify var/ledger.json    # entries, admitted count, tip; non-zero if broken
cargo run -- search "brisbane port"    # built-in fixture
cargo run -- search "brisbane port" docs/
cargo run -- sources example.com       # classify + build curated routes; no network
cargo run -- geo -27.4698,153.0251 -33.8688,151.2093
cargo run -- id "53 004 085 616"        # ABN/ACN/BSB, strict grouping
cargo run -- geohash -27.4698,153.0251 9
cargo run -- coarsen -27.4698,153.0251 # one decimal place, ~11 km
cargo run -- classify 200 "<html>just a moment cloudflare</html>"
cargo run -- keys keys.env               # mode 600; prints slot + fingerprint prefix, never the value
cargo run -- fetch https://example.com/  # guarded fetch; run `fetch` without a URL for options
cargo run -- web --help                 # local browser UI options
```

`search` needs at least one term of two or more letters or digits (exit 64 otherwise). `search DIR` loads `.txt` and `.md` (any case) from that one directory. Challenge pages, non-UTF-8 files, files over 1 MiB, and symlinks are skipped and listed on stderr. An unreadable directory exits 66; it does not print `hits=0`.

Credentials for `fetch --bearer SLOT` / `--header NAME=SLOT` come from a keys file and the process environment. The file is `NAME=value` lines (`export`, quotes, blank lines and `#` comments allowed; placeholder values count as unset) and is parsed by `keys::Keys::parse`, the parser `--keys FILE` and `keys FILE` use through `Keys::load`.

- `--keys FILE` loads exactly that file and nothing else. A file accessible by group/others is an error (exit 66, `run chmod 600`).
- Without `--keys`, `$HOME/.huntsman.env` is parsed with the same parser when it exists. If the file is missing (not found, or a `HOME` path component is not a directory), or `HOME` is unset, nothing changes: only the environment is used and nothing is printed. An empty or relative `HOME` (`HOME=.`, `HOME=relative/dir`, `HOME=`) behaves the same, except that it prints one warning (`HOME is not an absolute path`, without the value), so the default file never depends on the working directory. The path is checked with `lstat` and is never followed. The file is not read, and the run continues with the environment only after one stderr warning naming the path and the reason, if it is:
  - a symlink, even to a valid mode-600 file (fix: remove the symlink and create a regular file owned by you with mode 600, or pass `--keys`; `chmod` would follow the link);
  - not a regular file;
  - owned by a uid other than the process's effective uid (read from `/proc/self/status`; where that is unavailable, the file is refused and `--keys` is the way to supply it);
  - accessible by group/others (`mode & 0o077 != 0`; fix with `chmod 600 ~/.huntsman.env`).

  The file is read through the descriptor that was opened. That descriptor must be the same device/inode `lstat` saw and must pass the same checks, so a swap between the check and the read is refused rather than followed. `O_NOFOLLOW` is not set: `OpenOptionsExt::custom_flags` is safe Rust, but the flag value differs per architecture and would need the `libc` crate or a hard-coded per-target table. The remaining gap is a regular file swapped for a FIFO between `lstat` and `open`, which would block the open; that requires write access to `$HOME`.
- Fail-closed cases are separate from the refusals above. They apply only to a default file that passes those checks, and they return an error instead of a warning. A fetch that requests a credential then exits 66, even if the slot is set in the environment:
  - a malformed line (`keys line N: ...`, line number only);
  - content that is not UTF-8;
  - a file over 64 KiB;
  - any I/O error other than not found / not a directory (for example a mode-`200` file the owner cannot open, or a `$HOME` that cannot be searched).
- Precedence: a slot present in the loaded file wins over the same environment variable; slots the file lacks fall back to the environment.
- The file is read only when a credential slot is requested. Values never appear in output, warnings or errors; only slot names, line numbers and fingerprint prefixes do.

`sources` is offline routing, not collection. It classifies the input using the existing Huntsman classifier and renders only compatible, independently curated public/browser search routes from `source_registry`. Generated routes are `LeadOnly`: a URL is never corroborating evidence by itself. External catalogue code or data is not embedded.

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input, 69 `fetch` got no response, 74 artifact write failure, 77 egress policy refused the destination. `check` uses 2–11 for its individual gates.

`tests/readme.rs` runs every example above (except the internet `fetch`), checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` exercises them as gate 5.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.

## Opt-in HIBP library

`huntsman_recon::hibp` ports the HIBP branch onto this single blocking crate;
it does not restore the async monolith or modify either legacy snapshot.
`HibpClient::production(Auth::ApiKey(key), HibpConfig::default())` uses the
guarded `UreqTransport` and the existing fetch boundary without following redirects.
An injected `Arc<dyn Transport + Send + Sync>` supports offline tests.

Read endpoints: breach catalogue, individual/latest breach, data classes,
breached accounts (including options and local SHA-1 k-anonymity lookup), pastes,
verified-domain breaches, subscribed domains, subscription status, all three
stealer-log searches, and free SHA-1/NTLM Pwned Passwords ranges with padding.
Domain verification and email-sending endpoints are intentionally excluded.
Keys never go to public or password endpoints. Entitlements are checked against a
cached subscription response; missing flags fail closed. Keyed calls share a
10/minute sliding window (`HIBP_RATE_LIMIT_PER_MINUTE=0` disables local pacing).
429 retries are bounded; a server delay above `max_retry_after` returns immediately
instead of retrying sooner than requested. Truncated or malformed bodies are errors.

Key precedence: `HIBP_API_KEY`, caller's `HUNTSMAN_HIBP_KEY` slot (or that environment
variable), private `~/.config/hibp/api_key`, then optional build-time embedding.
Blank/placeholders are ignored; files are bounded and symlinks refused.
Personal builds can embed a key only into Cargo's `OUT_DIR` (and therefore the
binary); do not distribute such binaries. `CI`, `HSE_RELEASE`, or
`HUNTSMAN_HIBP_NO_EMBED` being set disables embedding. Runtime keys still work.

`hibp::oauth` implements discovery, public registration, PKCE S256 authorization,
code exchange and refresh for the documented MCP resource, **not REST v3 bearer
authentication**. The caller must verify the returned state before exchanging a
code. Authorization-server URLs must stay on HIBP's HTTPS origin. Linux/Termux
randomness comes from `/dev/urandom`. Token stores support memory or bounded,
atomic mode-600 files. Debug/errors omit keys, tokens and upstream error bodies.
All integration evidence here is offline fake-transport testing; live HIBP and
Termux handset acceptance remain unverified.

## Lineage and the automatic-merge rule

`huntsman_recon::lineage::resolve_with_lineage` takes parsed observations and candidate merge decisions. It derives countable lineage from explicit upstream dataset fields and, where the acquisition path is verified, registry identity; record URLs/ids and collector names do not create independent families. Two collectors relaying one dataset therefore count as one family. It returns every observation and every candidate. A candidate auto-merges only with two independent families and a present, in-range match probability of at least 0.90 (legacy `breach_consensus` parity). Otherwise it is held, with every reason stated. `check` gate 5 runs it, and separately checks a hand-built ancestry graph through `allows_automatic_merge`, the path `resolve::automatic_clusters` uses. See `docs/LINEAGE.md`.
