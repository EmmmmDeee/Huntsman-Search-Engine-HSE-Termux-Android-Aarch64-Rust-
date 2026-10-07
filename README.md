# Huntsman Recon

Huntsman Recon is a Rust command-line toolkit for local search, guarded HTTP
fetches, Australian identifier validation, geospatial utilities, and an
append-only evidence ledger. It is designed to make evidence quality and
uncertainty visible; a lead or verified claim is not an attribution or ATT&CK
score.

> **Status:** this is the `huntsman-recon` reconstruction, not the previous
> `hse` monolith. `people`, `email`, `username`, and `phone` provide subsets of the old monolith's person-lookups.
> Canonical extracted legacy trees are preserved as read-only reconstruction references;
> the two historical ZIP references remain byte-pinned at the repository root. See
> [archive provenance](docs/ARCHIVE_PROVENANCE.md) and [architecture and status](ARCHITECTURE.md).

## Install on Termux (Android arm64)

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases).
Keep Termux and its plugins from the same distribution source. On an ARM64
device, the repository installer refreshes package metadata, aligns the Termux
Rust compiler and host stdlib, installs the current root crate, creates private
state/config paths, and runs offline acceptance before reporting success:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" && bash "$TMPDIR/huntsman-install.sh"
```

No root, proot, system service, or writable Android system partition is used.
The result is `$PREFIX/bin/huntsman-recon`; `~/.huntsman` is mode 700 and
`~/.huntsman.env` is mode 600. Rust 1.87 or newer remains the crate MSRV.
For prebuilt release installation, upgrades, and troubleshooting, see
[`docs/INSTALL.md`](docs/INSTALL.md).

## Deploy on Railway

For a new Railway service, connect this repository's `main` branch. Railway
automatically detects the root `Dockerfile`; configure the healthcheck path as
`/api/health`. The image reads Railway's injected `PORT`, runs the same
offline acceptance before serving, and drops from the container startup user to
uid 10001 for the application process.

Set `HSE_AUTH_TOKEN` as a Railway variable for a stable bearer token. If it is
absent, the container generates a 256-bit token, stores it under
`$HUNTSMAN_DATA_DIR/.huntsman/`, and prints it once to deployment logs.
Attaching a Railway volume at `/data` makes that state durable; the service can
also run without a volume. Current Railway Infrastructure as Code lives at
`.railway/railway.ts`; see [`docs/RAILWAY.md`](docs/RAILWAY.md).

## Repair broken code or files

For any error, bug, broken file, malfunctioning code path, failed refactor, or
repository inconsistency, follow [the repair protocol](docs/REPAIR_PROTOCOL.md).
The terminal local verification command is:

```sh
bash scripts/repair-gate.sh full
```

CI runs the same gate, so local repair acceptance and automated acceptance use
one contract.

## First commands

```sh
huntsman-recon --help
huntsman-recon check
huntsman-recon command
huntsman-recon directive check
huntsman-recon search "brisbane port"
```

`check` runs offline self-acceptance and rejects an invalid engineering-command contract; when run from a source checkout containing the canonical directive, it also rejects directive drift. `command` validates and prints the fixed engineering hierarchy. From the repository root, `huntsman-recon directive check` verifies the pinned canonical directive and every agent-facing mirror, while `huntsman-recon directive sync` rewrites all mirrors byte-for-byte from the canonical file. `search` and `sources` are offline.
`fetch`, `hibp`, `recon`, `seeknow`, `email`, `username`, and `people` make HTTP
requests and use public-only egress by default. `phone` is fully offline. `serve` accepts inbound HTTP on `127.0.0.1:8080` by default.
Review [`docs/INSTALL.md`](docs/INSTALL.md) and the command reference below
before using credentials or network access.

## Repository map

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI, local-HTTP and legacy-reference integration tests; `hibp_build.rs` (build-time key embedding rules); `android_ci.rs` (the CI workflow keeps the aarch64 Android cross-build and its artifact); plus `readme.rs` and `dispositions.rs`, which check this README and `docs/DISPOSITIONS.md` against the binary and `legacy/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | `RECONSTRUCTION_2026-10-02.md` (decisions and falsification passes) and `DISPOSITIONS.md` (per-file accounting of every legacy file). |
| `legacy/` | Canonical extracted historical reference trees. Not part of the build. |
| `docs/ARCHIVE_PROVENANCE.md` | SHA-256/Git identities and extracted-tree mapping for the pinned root ZIP references. |
| `.github/` | `workflows/ci.yml` (tests on Rust 1.87 and stable; aarch64 Android cross-build), `workflows/release.yml` (`main-<sha7>` pre-releases of `huntsman-recon`), `scripts/` (`scan-for-keys.sh`, `install-termux.sh`) and `actions/setup-ndk-aarch64` (NDK compiler and linker environment). |
| `CHANGELOG.md` | Notable changes, Keep a Changelog format. |
| `docs/COMMERCIAL_READINESS.md` | Buyer/client due-diligence index: reusable assets, proof boundaries, commercial-readiness gates, and value-maximizing engineering sequence. |

## Which binary to use

| | `hse` (legacy v1.41.0 monolith) | `huntsman-recon` (this tree, in progress) |
| --- | --- | --- |
| Person lookups | Yes. Provider modules such as `asic_persons`, `asic_director`, `username_search`, `phone_au` and `bluesky_user` (195 `pub mod` entries in `src/modules/mod.rs` at `7dca720b`), plus `hse scan`, `hse investigate` and `hse serve`. Whether each provider works live has not been re-verified. | **Partial.** `people` calls `asic_persons`, `asic_director`, `au_people` and `au_electoral` for names with at least two alphabetic tokens. `email ADDR` canonicalises an address, derives deterministic email pivots, queries the public Gravatar profile, renders evidence lineage, and can save a ledger for `verify`. `username HANDLE` derives bounded normalization variants, queries the public GitHub and Bluesky profiles independently, renders lineage, and can save a ledger for `verify`. `phone NUMBER` canonicalises explicit international syntax or recognised Australian local syntax, resolves the dialling prefix offline, enriches Australian numbering-plan line type/region, and can save a ledger for `verify`. `scan SELECTOR` routes one selector to `people`, `email`, `username`, or `phone` automatically, with `-k` available for an explicit rebuilt kind. `scan --input-file FILE [-k KIND]` runs the same routing once per unique non-comment line, attempts every seed, and reports a non-zero final status if any seed fails. `sources` classifies an input (a person or organisation name, an email address, an `@username`, a domain, an IP address or coordinates) and only prints curated public search or browser URLs for it, offline and `LeadOnly`; nothing is fetched. `search` reads only local documents; `hibp` provides explicit opt-in HIBP lookups. |
| Source | Commit `7dca720b`. The closest copy in this tree is `legacy/hse-monolith-v1.41.0/`, which is read-only and not built; it is not byte-identical to `7dca720b`. | `src/` |
| Where to get it | GitHub pre-release `main-7dca720` (asset `hse-aarch64-linux-android`, built from `7dca720b`) | A GitHub pre-release `main-<sha7>` (asset `huntsman-recon-aarch64-linux-android`), the CI artifact of the same name from a `main` push (see "Downloads"), or a source build |

`huntsman-recon` is the in-progress replacement, with rebuilt person-lookup slices plus a minimal embedded Web UI/API. Since #672, every push to `main` publishes it as a `main-<sha7>` pre-release. There is no rolling `latest` pre-release: the workflow creates or moves `latest` only when the repository variable `PROMOTE_RECON_TO_LATEST` is `true`, and it is unset. GitHub's "Latest release" is the stable legacy `hse` release `v1.41.0`.

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is explicit opt-in via the CLI or library. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

For contributors: one Rust package (`huntsman-recon`), Rust 1.87+, no workspace.
The binary's full command list is available with `huntsman-recon --help`;
run `huntsman-recon COMMAND --help` for command-specific usage.

```
cargo test
cargo run -- check                     # self-acceptance + command invariant; regenerates var/*.json
cargo run -- command                   # validate + print engineering command contract
cargo run -- directive --help          # repository directive verifier/self-repair usage
cargo run -- verify var/ledger.json    # entries, admitted count, tip; non-zero if broken
cargo run -- search "brisbane port"    # built-in fixture
cargo run -- search "brisbane port" docs/
cargo run -- sources example.com       # classify + build curated routes; no network
cargo run -- domain-lifecycle analyze docs/domain-lifecycle-example.json --as-of 1000  # offline timeline comparison
cargo run -- geo -27.4698,153.0251 -33.8688,151.2093
cargo run -- id "53 004 085 616"        # ABN/ACN/BSB, strict grouping
cargo run -- geohash -27.4698,153.0251 9
cargo run -- coarsen -27.4698,153.0251 # one decimal place, ~11 km
cargo run -- classify 200 "<html>just a moment cloudflare</html>"
cargo run -- keys keys.env               # mode 600; prints slot + fingerprint prefix, never the value
cargo run -- fetch https://example.com/  # guarded fetch; run `fetch` without a URL for options
cargo run -- hibp help                   # HIBP subcommands; offline
cargo run -- seeknow --help              # SeekNow subcommands; offline
cargo run -- people Madonna              # skip path: fewer than two alphabetic tokens, no network
cargo run -- people Madonna --save skip.json  # skip still writes nothing; --save needs a lookup
cargo run -- email nobody@example.com     # deterministic pivots + public Gravatar lookup
cargo run -- username octocat             # variants + public GitHub/Bluesky lookups
cargo run -- phone "0412 345 678"           # offline E.164 + AU numbering-plan classification
cargo run -- scan "0412 345 678"            # auto-route to the rebuilt phone front-end
cargo run -- investigate "mail ada@example.com visit https://example.org"  # offline entity extraction
cargo run -- query "OpenAI research"          # network: Bing/Brave/Mojeek subset
cargo run -- sf -M                         # SpiderFoot-style reachable-module listing; offline
cargo run -- serve --help                    # embedded UI/API command options; does not start a listener
cargo run -- modules --json               # only modules currently reachable from the binary
cargo run -- recon crtsh https://example.com/
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

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input or failed credential setup (unconfigured slot or unreadable keys file or a bad URL when `--bearer`/`--header` is given), 69 `fetch`/`recon`/`seeknow`/`email` got no usable response or `people` registers were unusable, 74 artifact write failure, 77 `fetch`/`recon`/`seeknow`/`email` refused the request (egress policy or malformed URL or redirect target; without a credential option a malformed URL lands here) or `people` encountered a network-policy refusal. `check` uses 2–11 for its individual gates. Running the binary with no command runs `check`; `help`, `-h` and `--help` print help and the usage line.

`tests/readme.rs` runs every offline example above, checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`. Network HIBP examples below are exercised through a fake transport by `tests/hibp_cli.rs` rather than against the internet in CI.

`fetch URL` options (defaults in brackets):

| Option | Effect |
| --- | --- |
| `--body` | Print the response body after the status line. |
| `--allow-private` | Lift the egress policy (otherwise only public addresses are reachable; loopback, private, link-local and metadata addresses exit 77). |
| `--keys FILE` | Read credential slots from a `NAME=value` file (mode 600 or stricter, at most 64 KiB); slots it lacks fall back to the process environment. Without it, `$HOME/.huntsman.env` is loaded when it exists and passes the checks above; otherwise slots come from the environment only. |
| `--bearer SLOT` | Send slot `SLOT` as `Authorization: Bearer`. |
| `--header NAME=SLOT` | Send slot `SLOT` in header `NAME`. Only one of `--bearer`/`--header` per fetch. |
| `--max-redirects N` | Follow at most `N` redirects, 0–20 [5]. A credential is only sent to the origin it was approved for. |
| `--timeout SECS` | Per-request timeout, 1–600 [20]. |

Slot names are upper-case environment-variable names (`A-Z`, `0-9`, `_`; starting with a letter; at most 64 characters). Keys are read at run time only: from the environment, from a file you name with `--keys` / `keys FILE`, or, without `--keys`, from `$HOME/.huntsman.env` (see above). Blank values and template placeholders (`insert_key_here`, `<your-key>`, `changeme`, `xxxx`) count as not configured. Output shows a 12-hex-digit fingerprint prefix, never a key value.

`classify` also prints the causal outcome and the source-health action (`outcome=bot_waf`, `action=backoff`). A 403 challenge page is a WAF, not a credential failure. A 200 alone is `inconclusive` until rows are parsed.

The refactor-overlay foundations preserved under `legacy/refactor-overlay-feef60a/` are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` gate 5 exercises four of them: `source_outcome` (a 403 Cloudflare challenge page is `BotWaf`, and its recommended action is not `RequireCredential`); `evidence_ancestry` with `identity_resolution` (two mirrors of one dump cannot auto-merge two identities, while a mirror plus an independent registry root can); and `termination` (delayed retry work is not a fixed point). Gate 5 does not exercise `credential_origin` or `eval`. The binary uses `credential_origin` in `fetch` (the operator-approved credential authority) and for the fingerprints that `fetch` and `keys` print. `eval` is not used by the binary at all; only its unit tests exercise it.

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

## Recon sources: crt.sh, DNS/mail, and stolen.tax

`recon crtsh TARGET` accepts a domain, URL or email and queries crt.sh with a
30-second timeout. HTTP 502, 503 and 429 responses are retried at most twice,
two seconds apart; challenge pages are never retried. Results include distinct
SAN names and non-public issuing CAs. Wildcard names, role or infrastructure
mailboxes, and public-CA issuers are filtered; subdomains of the target apex
carry the `subdomain` tag. Output is
`kind<TAB>value<TAB>confidence<TAB>tags`, with control characters escaped.

`recon dns TARGET` accepts a domain, URL or email and queries Cloudflare, Quad9
and Google DNS-over-HTTPS (JSON) for apex A, AAAA, MX, NS and TXT, plus
`_dmarc` and `_smtp._tls` TXT, through `fetch` with redirects off. One
record-type failure does not abort the others. A challenge page is `bot_waf`,
a truncated body is `truncated`, and HTTP 429 is `rate_limited`; none of those
is parsed as DNS JSON. Quoted TXT presentation is decoded before SPF (RFC 7208),
DMARC (RFC 7489) and TLSRPT (RFC 8460) parsing. Output is
`type<TAB>name<TAB>rdata<TAB>resolver` lines, then `spf_all=`, `dmarc_policy=`
and `tlsrpt_emails=` when those records parse, plus `failed` rows. An invalid
selector exits 65 before any request; no usable answer exits 69. DoH is
keyless. There is no live receipt in CI.

`recon stolen-tax QUERY [--keys FILE]` is an explicit paid lookup requiring
`HUNTSMAN_STOLEN_TAX_KEY`; a missing key exits 66 before any request. The v2
snusbase, osintcat and hudsonrock paths share one 120-second budget. Requests
use the key only for `https://stolen.tax:443`; same-site redirects are bounded,
and the key is not reattached after leaving that origin. HTTP 429 is retried
on the same key up to three attempts per path, with `Retry-After` capped at
four seconds. Partial results name failed or skipped paths. The legacy
persistent multi-key pool is deferred; paid lookups are never automatic.
Differential fixtures record the legacy output, with blank-name/host placeholder
markers intentionally suppressed.

## Build and install

Toolchain: the crate's MSRV is Rust 1.87 (`rust-version` in `Cargo.toml`); CI tests Rust 1.87 and current stable. The owner's reference toolchain is Rust 1.98.0. The repository has no `rust-toolchain.toml`, so rustup uses your default toolchain.

On the device, in Termux (unverified on a handset):

```
pkg install rust clang   # ring (via rustls) needs a C compiler
cargo build --release --locked
./target/release/huntsman-recon check
```

Cross-build for Android aarch64 (what the `android-aarch64` CI job does, API level 24):

```
rustup target add aarch64-linux-android
NDK="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}"   # CI sets ANDROID_NDK_LATEST_HOME
: "${NDK:?set ANDROID_NDK_LATEST_HOME or ANDROID_NDK_HOME to the NDK root}"
export TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android24-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
HUNTSMAN_HIBP_NO_EMBED=1 cargo build --release --locked --target aarch64-linux-android
```

The reference NDK is 27.3.13750724. CI uses the runner's `ANDROID_NDK_LATEST_HOME` and does not pin an NDK version. Set `HUNTSMAN_HIBP_NO_EMBED=1` (CI does) for any binary that leaves your machine, so no key is embedded (see below).

### Downloads

Each push to `main` uploads a CI artifact named `huntsman-recon-aarch64-linux-android`: the binary plus its `.sha256`, kept for 14 days. Download it from the workflow run's page, or with `gh run download <run-id> -n huntsman-recon-aarch64-linux-android`. Check it with `sha256sum -c huntsman-recon-aarch64-linux-android.sha256`, then copy it into Termux's home directory and `chmod +x` it.

Each push to `main` also publishes a `main-<sha7>` pre-release (`.github/workflows/release.yml`, #672) with the `huntsman-recon-aarch64-linux-android` binary, its `.sha256`, a `.provenance.json` naming the commit, a zero-finding `key-scan-report.txt` and `install-termux.sh`. The `main-<sha7>` pre-releases up to `main-7dca720` predate the reconstruction and ship the legacy `hse` binary. No rolling `latest` pre-release exists (see "Which binary to use"). Release policy: only pre-releases (`main-<sha7>` plus a rolling `latest`); a stable release needs the owner's explicit approval and is never automatic.

## Opt-in HIBP library

`huntsman_recon::hibp` ports the HIBP branch onto this single blocking crate; it does not restore the async monolith or modify either legacy snapshot. `HibpClient::production(Auth::ApiKey(key), HibpConfig::default())` uses the guarded `UreqTransport` and the existing fetch boundary without following redirects. An injected `Arc<dyn Transport + Send + Sync>` supports offline tests.

Read endpoints: breach catalogue, individual/latest breach, data classes, breached accounts (including options and local SHA-1 k-anonymity lookup), pastes, verified-domain breaches, subscribed domains, subscription status, all three stealer-log searches, and free SHA-1/NTLM Pwned Passwords ranges with padding. Domain verification and email-sending endpoints are intentionally excluded. Keys never go to public or password endpoints. Entitlements are checked against a cached subscription response; missing flags fail closed. Keyed calls share a 10/minute sliding window (`HIBP_RATE_LIMIT_PER_MINUTE=0` disables local pacing). 429 retries are bounded; a server delay above `max_retry_after` returns immediately instead of retrying sooner than requested. Truncated or malformed bodies are errors. A Pwned Passwords 429 is not retried; it returns a rate-limited outcome with the server retry hint when available.

Key precedence: `HIBP_API_KEY`, caller's `HUNTSMAN_HIBP_KEY` slot (or that environment variable), private `~/.config/hibp/api_key`, then optional build-time embedding. Blank/placeholders are ignored; files are bounded and symlinks refused. Personal builds can embed a key only into Cargo's `OUT_DIR` (and therefore the binary); do not distribute such binaries. `CI`, `HSE_RELEASE`, or `HUNTSMAN_HIBP_NO_EMBED` being set disables embedding. Runtime keys still work.

`hibp::oauth` implements discovery, public registration, PKCE S256 authorization, code exchange and refresh for the documented MCP resource, **not REST v3 bearer authentication**. The caller must verify the returned state before exchanging a code. Authorization-server URLs must stay on HIBP's HTTPS origin. Linux/Termux randomness comes from `/dev/urandom`. Token stores support memory or bounded, atomic mode-600 files. Debug/errors omit keys, tokens and upstream error bodies.

All CI HIBP integration evidence is offline fake-transport testing. Earlier development smoke tests exercised public HIBP endpoints on an antecedent branch, but they are not a qualifying live receipt tied to this final commit. Termux handset acceptance also remains unverified.

## Opt-in ASIC people-register library

`huntsman_recon::asic_persons::lookup` queries three keyless ASIC registers on
data.gov.au CKAN (banned and disqualified persons, financial advisers, credit
representatives) through the shared `fetch` boundary and an injected
`http::Transport`. A name with fewer than two alphabetic tokens makes no
request. Challenge pages, truncated bodies, and CKAN `success: false` envelopes
are not evidence of absence. The binary exposes `people NAME [--save FILE]`
(unquoted words are joined) through `people_cli`, which also runs
`asic_director`, `au_people` and `au_electoral` over the same transport and
feeds emitted evidence through `lineage::resolve_with_lineage`. One source
`Invalid` or BotWaf does not abort the others. `--save FILE` writes an
unverified hash-chained ledger of outcomes and entities that `verify FILE`
reloads byte-identically (`admitted=0`; a register row is not identity
resolution). Skip (fewer than two alphabetic tokens) makes no request and does
not write. Tests use a scripted transport; the README examples are the skip
path. Two-token names query those sources and are not run in CI. There is no
live receipt. Live ASIC Connect is WAF-blocked.

## Lineage and the automatic-merge rule

`huntsman_recon::lineage::resolve_with_lineage` takes parsed observations and candidate merge decisions. It derives countable lineage from explicit upstream dataset fields and, where the acquisition path is verified, registry identity; record URLs/ids and collector names do not create independent families. Two collectors relaying one dataset therefore count as one family. It returns every observation and every candidate. A candidate auto-merges only with two independent families and a present, in-range match probability of at least 0.90 (legacy `breach_consensus` parity). Otherwise it is held, with every reason stated. `check` gate 5 runs it, and separately checks a hand-built ancestry graph through `allows_automatic_merge`, the path `resolve::automatic_clusters` uses. See `docs/LINEAGE.md`.


### Email lookup

`email ADDR [--save FILE]` canonicalises the selector, derives deterministic non-network email pivots, queries the public Gravatar profile, renders lineage, and optionally writes an unverified ledger that `verify` can reload. A missing Gravatar profile is a validated zero result; malformed or incomplete responses are not treated as absence.
\n\n### Username lookup\n\n`username HANDLE [--save FILE]` keeps the operator selector, derives bounded separator/de-decoration variants at candidate confidence, and performs keyless public-profile lookups against GitHub and Bluesky. Provider absence, rate limits, malformed responses, and unsupported handle shapes remain distinct outcomes. `--save` writes an unverified ledger that `verify` can reload.\n

### Phone lookup

`phone NUMBER [--save FILE]` is offline. It canonicalises explicit international syntax and recognised Australian local numbers to E.164, resolves the international dialling prefix from the embedded legacy-compatible table, and enriches Australian numbers with numbering-plan line type plus coarse fixed-line allocation region. It does not guess the country of an ambiguous bare foreign national number and does not infer a mobile carrier. `--save` writes an unverified ledger that `verify` can reload.


### Reachable module catalogue

`modules [--json]` is offline and intentionally conservative: it lists only rebuilt modules that have a current `huntsman-recon` command path. A provider definition or compiled helper is not advertised merely because it exists in the source tree. This avoids presenting unconnected modules as operational capability.


### Offline investigate

`investigate TEXT... | investigate --file FILE` extracts actionable entities through the rebuilt classifier without network access. File input uses the bounded reader, refuses symlinks, and is capped at 1 MiB. The `modules` catalogue includes this path as `classify_module` only because it is now reachable from the binary.


### Web meta-search

`query QUERY...` restores a bounded keyless subset of the legacy multi-engine search path. It currently queries Bing, Brave, and Mojeek independently through the shared fetch boundary, extracts external HTTP(S) result URLs, deduplicates them, and reports each provider outcome separately. One blocked or drifting engine does not erase results from another. Repeated anonymous queries reuse bounded in-process responses for up to five minutes; `no-store` responses are never cached, transient transport/5xx failures get one bounded backoff retry, and a provider circuit suppresses repeated calls while it is cooling down. The broader legacy engine set, dork packs, pagination, ranking, snippets, and live differential receipts remain outstanding.


### SpiderFoot-compatible front end

`sf` restores a tested subset of the legacy SpiderFoot 4.0-compatible command line. `sf -M`, `sf -T`, and `sf -V` are offline; `sf -s TARGET` currently executes rebuilt name, email, username, and phone paths and formats rows as tab, CSV, or JSON. `-u all|footprint|investigate|passive`, `-t TYPE[,TYPE...]`, `-r`, and `-q` are parsed. Passive execution is currently available only where the rebuilt path is entirely offline (phone); unsupported target classes fail explicitly instead of silently changing semantics. The remaining SpiderFoot flags, full event taxonomy, stored-scan correlation, listener mode, and complete legacy differential remain outstanding.


### Embedded Web UI and HTTP API

`huntsman-recon serve` starts a dependency-free embedded UI on `127.0.0.1:8080` by default. `HSE_BIND` or `serve --bind ADDR` selects another socket address. Explicit non-loopback binds require a non-empty `HSE_AUTH_TOKEN`.

The first rebuilt API surface is read-only:

- `GET /api/health` — process name/version and status;
- `GET /api/modules` — the same truthful reachable-module catalogue as `modules --json`;
- `GET /api/command` — the same validated engineering command contract as `command --json`;
- `GET /` — a minimal embedded page that renders those endpoints.

The listener bounds request headers to 16 KiB, applies finite read/write timeouts, supports `GET` and `HEAD`, and closes each connection after one response. The broader legacy scan-control UI, stored-result browsing, write endpoints, and complete API surface remain to be rebuilt.


### Batch scan input

`scan --input-file FILE [-k people|email|username|phone]` accepts UTF-8 files up to 1 MiB with one target per line. Blank lines and lines whose trimmed form starts with `#` are ignored; exact duplicate seeds keep only their first occurrence. A batch is capped at 1000 unique seeds, every accepted seed is attempted even after an earlier failure, and the process exits non-zero after completion if any seed failed. Batch `--save` is refused for now so one seed can never overwrite another seed's ledger artifact.


### Domain lifecycle analysis

`domain-lifecycle analyze INPUT.json --as-of UNIX_SECONDS [--output REPORT.json]` compares imported domain observations entirely offline. It preserves source/upstream boundaries, rejects conflicting duplicate identifiers, records failed/truncated observations as coverage gaps, and emits only conservative observed changes. Ownership, causality, and registration availability remain explicitly unknown unless established elsewhere. See [docs/DOMAIN_LIFECYCLE.md](docs/DOMAIN_LIFECYCLE.md).
