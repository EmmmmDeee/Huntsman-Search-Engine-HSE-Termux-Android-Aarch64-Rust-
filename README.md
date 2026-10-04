# huntsman

One crate, `huntsman-recon`. The current version lives in `src/`; the two legacy zip archives in the repository root and their extracted copies in `legacy/` are permanent read-only reference (see below).
Target design, module map and per-capability status against legacy `7dca720`: [`ARCHITECTURE.md`](ARCHITECTURE.md).

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI, local-HTTP and legacy-reference integration tests, plus `readme.rs` and `dispositions.rs`, which check this README and `docs/DISPOSITIONS.md` against the binary and `legacy/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | `RECONSTRUCTION_2026-10-02.md` (decisions and falsification passes) and `DISPOSITIONS.md` (per-file accounting of every legacy file). |
| `legacy/` | Byte-identical extraction of both archives. Not part of the build. |
| `*.zip` (root) | The two legacy archives. Pinned by hash in `tests/legacy_reference.rs`; never delete, edit or move them. |

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is reachable only through the explicit opt-in `hibp` command. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

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
cargo run -- hibp help                   # HIBP subcommands; offline
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

Exit codes: 64 usage, 65 bad data or invalid upstream request, 66 unreadable input or missing required credential, 69 unavailable/no response, 74 artifact write failure, 77 egress refusal, authentication rejection or unavailable entitlement. `check` uses 2–11 for its individual gates.

`tests/readme.rs` runs every offline example above, checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`. Network HIBP examples below are exercised through a fake transport by `tests/hibp_cli.rs` rather than against the internet in CI.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` exercises them as gate 5.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.

## HIBP (`hibp` command)

`huntsman-recon hibp SUBCOMMAND` exposes the HIBP v3 and Pwned Passwords client in `huntsman_recon::hibp` (blocking, single crate; the async monolith and both legacy snapshots are unchanged). Requests use the guarded `UreqTransport` and existing fetch boundary, with redirects off and only trusted HIBP/Pwned Passwords HTTPS origins accepted. Nothing calls HIBP unless this command is run.

```
cargo run -- hibp breach Adobe                 # one breach, full model; no key
cargo run -- hibp breaches --domain adobe.com  # catalogue, optional domain filter; no key
cargo run -- hibp password-range 21BD1         # Pwned Passwords k-anonymity range; no key
cargo run -- hibp account user@example.com     # breached account, untruncated; key
cargo run -- hibp pastes user@example.com      # pastes for an address; key
cargo run -- hibp subscription                 # plan, rate and entitlements; key
```

Check one password without putting it on the command line or in shell history:

```
read -rs PW && printf '%s\n' "$PW" | huntsman-recon hibp password; unset PW
```

`password` reads one line from stdin (at most 4096 bytes after the `\n`/`\r\n` terminator is stripped), SHA-1 hashes it locally and sends only the first 5 hex characters to `GET https://api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true`. The suffix is matched locally. The password, the full hash and the suffix are never sent, printed, logged or included in an error. The password and hash buffers are overwritten with zeros after use (best effort without `unsafe`; copies in stdin's read buffer are not reached).

Output is `key=value` lines. Each run starts with `source=HIBP`, `service=` (`api-v3` or `pwned-passwords`), `source_attribution=` and `results=N`. Breach/account output preserves the complete parsed model; pastes preserve every parsed paste field; `password-range` drops zero-count padding entries; `subscription` reports plan/rate/entitlement fields and `key_source=`, never the key. Results are never intentionally truncated.

For `breach`, `breaches`, `account` and `pastes`, a 404 is `results=0` with exit 0; for `subscription` and `password-range` it is an error (exit 69). HIBP uses the same process exit-code space: 64 usage, 65 invalid input or HTTP 400, 66 no API key for keyed lookups, 69 upstream unavailable/malformed/rate-limited, and 77 HTTP 401/403 or unavailable entitlement.

Not exposed by this command: domain search, subscribed domains, domain verification, email sending, stealer-log searches, k-anonymity account-range search, latest breach, data classes, NTLM mode and OAuth. Domain verification and email-sending endpoints are not implemented at all.

This command is **provider-specific reachability, not the unified people-lookup pipeline**. It does not yet convert HIBP responses into the common `entity::Evidence`/lineage/identity-resolution/saved-result path.

## Opt-in HIBP library

`huntsman_recon::hibp` ports the HIBP branch onto this single blocking crate; it does not restore the async monolith or modify either legacy snapshot. `HibpClient::production(Auth::ApiKey(key), HibpConfig::default())` uses the guarded `UreqTransport` and the existing fetch boundary without following redirects. An injected `Arc<dyn Transport + Send + Sync>` supports offline tests.

Read endpoints: breach catalogue, individual/latest breach, data classes, breached accounts (including options and local SHA-1 k-anonymity lookup), pastes, verified-domain breaches, subscribed domains, subscription status, all three stealer-log searches, and free SHA-1/NTLM Pwned Passwords ranges with padding. Domain verification and email-sending endpoints are intentionally excluded. Keys never go to public or password endpoints. Entitlements are checked against a cached subscription response; missing flags fail closed. Keyed calls share a 10/minute sliding window (`HIBP_RATE_LIMIT_PER_MINUTE=0` disables local pacing). 429 retries are bounded; a server delay above `max_retry_after` returns immediately instead of retrying sooner than requested. Truncated or malformed bodies are errors. A Pwned Passwords 429 is not retried; it returns a rate-limited outcome with the server retry hint when available.

Key precedence: `HIBP_API_KEY`, caller's `HUNTSMAN_HIBP_KEY` slot (or that environment variable), private `~/.config/hibp/api_key`, then optional build-time embedding. Blank/placeholders are ignored; files are bounded and symlinks refused. Personal builds can embed a key only into Cargo's `OUT_DIR` (and therefore the binary); do not distribute such binaries. `CI`, `HSE_RELEASE`, or `HUNTSMAN_HIBP_NO_EMBED` being set disables embedding. Runtime keys still work.

`hibp::oauth` implements discovery, public registration, PKCE S256 authorization, code exchange and refresh for the documented MCP resource, **not REST v3 bearer authentication**. The caller must verify the returned state before exchanging a code. Authorization-server URLs must stay on HIBP's HTTPS origin. Linux/Termux randomness comes from `/dev/urandom`. Token stores support memory or bounded, atomic mode-600 files. Debug/errors omit keys, tokens and upstream error bodies.

All CI HIBP integration evidence is offline fake-transport testing. Earlier development smoke tests exercised public HIBP endpoints on an antecedent branch, but they are not a qualifying live receipt tied to this final commit. Termux handset acceptance also remains unverified.

## Lineage and the automatic-merge rule

`huntsman_recon::lineage::resolve_with_lineage` takes parsed observations and candidate merge decisions. It derives countable lineage from explicit upstream dataset fields and, where the acquisition path is verified, registry identity; record URLs/ids and collector names do not create independent families. Two collectors relaying one dataset therefore count as one family. It returns every observation and every candidate. A candidate auto-merges only with two independent families and a present, in-range match probability of at least 0.90 (legacy `breach_consensus` parity). Otherwise it is held, with every reason stated. `check` gate 5 runs it, and separately checks a hand-built ancestry graph through `allows_automatic_merge`, the path `resolve::automatic_clusters` uses. See `docs/LINEAGE.md`.
