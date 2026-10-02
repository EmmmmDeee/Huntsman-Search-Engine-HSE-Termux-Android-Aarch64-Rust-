# huntsman

Only the current version of the project lives here. Earlier trees, the HSE monolith, and the uploaded legacy zip archives stay in git history (commit `91f2533`).

Local search over operator-supplied documents. A challenge page is not a hit. No paid source. No network client. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

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
```

`search` needs at least one term of two or more letters or digits (exit 64 otherwise). `search DIR` loads `.txt` and `.md` (any case) from that one directory. Challenge pages, non-UTF-8 files, files over 1 MiB, and symlinks are skipped and listed on stderr. An unreadable directory exits 66; it does not print `hits=0`.

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input, 74 artifact write failure. `check` uses 2–10 for its individual gates.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` exercises them as gate 5.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.
