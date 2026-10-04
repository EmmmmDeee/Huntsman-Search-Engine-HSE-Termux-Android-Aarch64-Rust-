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

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is an explicit opt-in library client, and stolen.tax runs only from an explicit `recon stolen-tax` command. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

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
cargo run -- recon crtsh https://example.com/  # crt.sh CT names for the URL's host (network)
```

`search` needs at least one term of two or more letters or digits (exit 64 otherwise). `search DIR` loads `.txt` and `.md` (any case) from that one directory. Challenge pages, non-UTF-8 files, files over 1 MiB, and symlinks are skipped and listed on stderr. An unreadable directory exits 66; it does not print `hits=0`.

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input or missing source key, 69 `fetch` or `recon` got no usable response, 74 artifact write failure, 77 egress policy refused the destination. `check` uses 2–11 for its individual gates.

`tests/readme.rs` runs every example above (except the internet `fetch` and `recon crtsh`), checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` exercises them as gate 5.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.

## Recon sources: crt.sh and stolen.tax

`huntsman_recon::crtsh` and `huntsman_recon::stolen_tax` restore M D's lost local
commit 764ce8e on the guarded fetch layer (port source: the restore commit on the
old tree, not the stale v1 copies in `legacy/`). Both are blocking, sync and
fake-transport tested; `recon` is their command-line caller.

`recon crtsh TARGET` takes a domain, URL or email, queries
`https://crt.sh/?q=…&output=json` with a 30 s timeout, and retries only HTTP 502, 503
and 429, at most three attempts two seconds apart (never a challenge page). It prints
every distinct SAN name and every non-public issuing CA, and caps nothing. Three
filters apply, as in the monolith: wildcard SANs (`*.…`), role or infrastructure
mailboxes (`hostmaster@`, `noreply@`, …), and public-CA issuers (Let's Encrypt,
DigiCert, …). Subdomains of the target's apex are tagged `subdomain`. Output is
`kind<TAB>value<TAB>confidence<TAB>tags`, with control characters escaped.

`recon stolen-tax QUERY [--keys FILE]` needs `HUNTSMAN_STOLEN_TAX_KEY` (keys file or
environment; exit 66 without it, before any request). It POSTs the query to the v2
snusbase, osintcat and hudsonrock paths with a Bearer key sent only to
`https://stolen.tax`. The whole lookup (all three paths) has one 120 s budget, the
monolith's module budget: each request gets only what is left of it, so the worst
case is 120 s, not 3 x 120 s. A path the budget did not reach is not sent and is
printed as `skipped_path=PATH`. (The monolith's engine instead dropped the whole result when the budget ran out, and cut it to 45 s on a resource-constrained device; see `docs/DISPOSITIONS.md`.) It prints emails, usernames and
`breach:`/`stealer:` markers, and never passwords, hashes or `top_passwords`. A path
failure or skip alongside evidence prints `partial=true` and the path. Every path
failing or skipped with nothing collected exits 69. Each run spends paid lookups, so
it is not in the examples above.

`tests/fixtures/legacy_764ce8e/` holds the old-tree output recorded on the committed
inputs. The differential tests require the port to reproduce it. The one intended
difference is the blank-name/host guard: no `breach:osintcat`/`stealer:unknown`
placeholder markers and no `unknown` stand-in facts.

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

`huntsman_recon::lineage::resolve_with_lineage` takes parsed observations and candidate merge decisions. It derives countable lineage from explicit upstream dataset fields and, where the acquisition path is verified, registry identity; record URLs/ids and collector names do not create independent families. Two collectors relaying one dataset therefore count as one family. It returns every observation and every candidate. A candidate auto-merges only with two independent families and a present, in-range match probability of at least 0.90 (legacy `breach_consensus` parity). Otherwise it is held, with every reason stated. `check` gate 5 runs it. See `docs/LINEAGE.md`.
