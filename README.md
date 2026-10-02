# huntsman

One crate, `huntsman-recon`. The current version lives in `src/`; the two legacy zip archives in the repository root and their extracted copies in `legacy/` are permanent read-only reference (see below).

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI, local-HTTP and legacy-reference integration tests, plus `readme.rs` and `dispositions.rs`, which check this README and `docs/DISPOSITIONS.md` against the binary and `legacy/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | `RECONSTRUCTION_2026-10-02.md` (decisions and falsification passes) and `DISPOSITIONS.md` (per-file accounting of every legacy file). |
| `legacy/` | Byte-identical extraction of both archives. Not part of the build. |
| `*.zip` (root) | The two legacy archives. Pinned by hash in `tests/legacy_reference.rs`; never delete, edit or move them. |

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is an explicit opt-in library client, reached from the binary only through the explicit `hibp` command. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

```
cargo test
cargo run -- check                     # self-acceptance; regenerates var/*.json
cargo run -- verify var/ledger.json    # entries, admitted count, tip; non-zero if broken
cargo run -- search "brisbane port"    # built-in fixture
cargo run -- search "brisbane port" docs/
cargo run -- geo -27.4698,153.0251 -33.8688,151.2093
cargo run -- id "53 004 085 616"        # ABN/ACN/BSB, strict grouping
cargo run -- geohash -27.4698,153.0251 9
cargo run -- coarsen -27.4698,153.0251 # one decimal place, ~11 km
cargo run -- classify 200 "<html>just a moment cloudflare</html>"
cargo run -- keys keys.env               # mode 600; prints slot + fingerprint prefix, never the value
cargo run -- fetch https://example.com/  # guarded fetch; run `fetch` without a URL for options
```

`search` needs at least one term of two or more letters or digits (exit 64 otherwise). `search DIR` loads `.txt` and `.md` (any case) from that one directory. Challenge pages, non-UTF-8 files, files over 1 MiB, and symlinks are skipped and listed on stderr. An unreadable directory exits 66; it does not print `hits=0`.

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input, 69 `fetch` got no response, 74 artifact write failure, 77 egress policy refused the destination. `check` uses 2–11 for its individual gates.

`tests/readme.rs` runs every example above (except the internet `fetch`), checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` exercises them as gate 5.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.

## HIBP (`hibp` command)

`huntsman-recon hibp SUBCOMMAND` exposes the HIBP v3 and Pwned Passwords client in
`huntsman_recon::hibp` (blocking, single crate; the async monolith and both legacy
snapshots are unchanged). Requests use the guarded `UreqTransport` and the existing
fetch boundary, with redirects off and only `https://haveibeenpwned.com` and
`https://api.pwnedpasswords.com` accepted. Nothing calls HIBP unless this command is run.

```
cargo run -- hibp help                         # subcommands; offline
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

`password` reads one line from stdin (at most 4096 bytes after the `\n`/`\r\n` terminator
is stripped), SHA-1 hashes it locally and sends only the first 5 hex characters to
`GET https://api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true`. The suffix
is matched locally. The password, the full hash and the suffix are never sent, printed,
logged or included in an error. The password and hash buffers are overwritten with zeros
after use (best effort without `unsafe`; copies in stdin's read buffer are not reached).

Output is `key=value` lines. Each run starts with `source=HIBP`, `service=`
(`api-v3` or `pwned-passwords`), `source_attribution=` (Have I Been Pwned,
CC BY 4.0 for breach and paste data) and `results=N`. Each breach then prints every model
field: `breach` (name), `title`, `domain`, `breach_date`, `added_date`, `modified_date`,
`pwn_count`, `data_classes` (count) plus one `data_class=` line per class, the eight `is_*`
flags, `attribution`, `logo_path` and `description`. `account` requests
`truncateResponse=false`, so it prints full models as well. Pastes print `paste_source`,
`paste_id`, `title`, `date` and `email_count`. `password-range` prints `SUFFIX:COUNT` lines,
with zero-count padding entries dropped. `subscription` prints every status field and
`key_source=` (for example `env:HIBP_API_KEY` or `file:PATH`), never the key. `account`
and `pastes` add `query=` (the trimmed address as sent) after `results=`. A field HIBP sent
as null or omitted prints as `key=<none>`, an empty string prints as `key=`, and a value
that is literally `<none>` prints as `key=\<none>`. Backslash, newline, carriage return
and tab are escaped (`\\`, `\n`, `\r`, `\t`). Results are never truncated.

For `breach`, `breaches`, `account` and `pastes` a 404 is `results=0` with exit 0; for
`subscription` and `password-range` it is an error (exit 69). `hibp` exits 64 usage, 65 invalid input or HTTP 400,
66 no API key for `account`, `pastes` or `subscription`, 69 HIBP unavailable, malformed
response or HTTP 429 (stderr carries `retry_after=Ns` or `retry_after=unknown`),
77 HTTP 401/403 or plan not entitled. `tests/readme.rs` runs only `hibp help` from the
block above. `tests/hibp_cli.rs` runs every subcommand against a fake transport.

Not exposed by the command: domain search, subscribed domains, domain verification,
anything that sends email, stealer-log searches, the k-anonymity account range search,
latest breach, data classes, NTLM mode and OAuth. Domain verification and email-sending
endpoints are not implemented at all.

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
A Pwned Passwords 429 is not retried; it returns `RateLimited` with the server's
`retry-after`.

Key precedence: `HIBP_API_KEY`, caller's `HUNTSMAN_HIBP_KEY` slot (or that environment
variable), private `~/.config/hibp/api_key`, then optional build-time embedding.
Blank/placeholders are ignored; files are bounded and symlinks refused.
Personal builds can embed a key only into Cargo's `OUT_DIR` (and therefore the
binary); do not distribute such binaries. `CI`, `HSE_RELEASE`, or
`HUNTSMAN_HIBP_NO_EMBED` being set disables embedding. Runtime keys still work.
GitHub Actions sets `CI`. Any build meant for publishing that runs outside GitHub
Actions must set `HSE_RELEASE=1`, for example `HSE_RELEASE=1 cargo build --release --locked`.

`hibp::oauth` implements discovery, public registration, PKCE S256 authorization,
code exchange and refresh for the documented MCP resource, **not REST v3 bearer
authentication**. The caller must verify the returned state before exchanging a
code. Authorization-server URLs must stay on HIBP's HTTPS origin. Linux/Termux
randomness comes from `/dev/urandom`. Token stores support memory or bounded,
atomic mode-600 files. Debug/errors omit keys, tokens and upstream error bodies.
Live verification, narrowing the earlier "All integration evidence here is offline
fake-transport testing; live HIBP and Termux handset acceptance remain unverified": as
of 2026-10-03 (PR #676) only `hibp password-range` and
`hibp breach` have succeeded against live HIBP. `account`, `pastes` and `subscription`
have never succeeded live (`subscription` got HTTP 401 with the build box's key), so
their success paths, every other library endpoint and OAuth are covered only by
offline fake-transport tests. Termux handset acceptance has not been done.
