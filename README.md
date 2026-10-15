# Huntsman Recon

Huntsman Recon is a Rust command-line toolkit for local search, guarded HTTP
fetches, Australian identifier validation, geospatial utilities, and an
append-only evidence ledger. It is designed to make evidence quality and
uncertainty visible; a lead or verified claim is not an attribution or ATT&CK
score.

> **Status:** this is the `huntsman-recon` reconstruction, not the previous
> `hse` monolith. `people`, `email`, `username`, and `phone` provide subsets of the old monolith's person-lookups.
> The historical source archives are intentionally absent from the active tree; their SHA-256 and
> Git identities are recorded for recovery from Git history. See
> [archive provenance](docs/ARCHIVE_PROVENANCE.md) and [architecture and status](ARCHITECTURE.md).

## Install on Termux (Android arm64)

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases).
Keep Termux and its plugins from the same distribution source. On an ARM64
device, the repository installer freezes `main` to one immutable commit SHA,
installs the checksum-verified prebuilt build of that commit (or the newest
published one; it compiles from source only when none exists or
`HUNTSMAN_FROM_SOURCE=1`), creates private state/config paths, runs offline
acceptance, and records the accepted revision before reporting success:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" && bash "$TMPDIR/huntsman-install.sh"
```

No root, proot, system service, or writable Android system partition is used.
The result is `$PREFIX/bin/huntsman-recon`; `~/.huntsman` is mode 700,
`~/.huntsman.env` is mode 600, and accepted install provenance is stored at
`~/.huntsman/installed-revision` with mode 600. Rust 1.87 or newer remains the
crate MSRV.
For prebuilt release installation, upgrades, and troubleshooting, see
[`docs/INSTALL.md`](docs/INSTALL.md).

### Check and repair an install

```sh
huntsman-recon doctor            # check everything; each problem names the command that fixes it
huntsman-recon fix               # make every repair that can be undone, then check again
huntsman-recon doctor --probe    # also test each configured key live (spends provider quota)
huntsman-recon doctor --json     # the same report as JSON
huntsman-recon doctor serve      # only the web UI: serve=healthy|not_running|foreign|unauthorized|degraded
```

`doctor` checks that `huntsman-recon` is on `PATH` and which build it is, that
`~/.huntsman/installed-revision` names this binary's commit, `~/.huntsman` (mode
700), `~/.huntsman.env` (yours, mode 600, parses; values are never read out),
which providers have a key, every ledger in `~/.huntsman` and `./var`, the
install acceptance (`check` and `verify` in a fresh directory), a running
`serve` (it answers as Huntsman, its page's policy matches its script, and its
offline analysis works, or another program holds the port), free disk, the
Rust build cache, and the Termux `PREFIX`, `PATH` and `TMPDIR`. It exits 0 when
nothing fails and 78 when something does.

`fix` (the same as `doctor --fix`) creates a missing `~/.huntsman` or empty
`~/.huntsman.env`, tightens loose permissions, re-runs the install acceptance
before recording this binary as installed (the old record is kept as
`installed-revision.bak-TIME`), and removes the build cache only when Cargo
tagged it and it is stale or the disk is nearly full. It never deletes a ledger
or scan data and never writes or prints a key. A problem it cannot repair
safely, such as a binary that needs rebuilding, prints the command to run.

## Deploy on Railway

For a new Railway service, connect this repository's `main` branch. Railway
automatically detects the root `Dockerfile`; configure the healthcheck path as
`/api/health`. The image reads Railway's injected `PORT`, runs the same
offline acceptance before serving, and drops from the container startup user to
uid 10001 for the application process.

Set `HSE_AUTH_TOKEN` as a Railway variable for a stable bearer token. If it is
absent, the container generates a 256-bit token, stores it at
`$HUNTSMAN_DATA_DIR/.huntsman/railway-auth-token`, and never writes its value to
deployment logs; the log names that file instead.
Attaching a Railway volume at `/data` makes that state durable; the service can
also run without a volume. Current Railway Infrastructure as Code lives at
`.railway/railway.ts`; see [`docs/RAILWAY.md`](docs/RAILWAY.md).

## Repair broken code or files

For any error, bug, broken file, malfunctioning code path, failed refactor, or
repository inconsistency, follow [the repair protocol](docs/REPAIR_PROTOCOL.md).
The terminal local verification command is:

```sh
cargo gate full
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

`check` runs offline self-acceptance and rejects an invalid engineering-command contract; when run from a source checkout containing the canonical directive, it also rejects directive drift. `command` validates and prints the fixed engineering hierarchy. `huntsman-recon directive check [ROOT]` verifies a specific checkout when `ROOT` is supplied, auto-discovers a checkout from the current directory or its parents when possible, and otherwise verifies the canonical directive embedded in the installed binary. `huntsman-recon directive sync [ROOT]` requires a real checkout and rewrites all agent-facing mirrors byte-for-byte from the canonical file. `search` and `sources` are offline.
`fetch`, `hibp`, `recon`, `seeknow`, `email`, `username`, and `people` make HTTP
requests and use public-only egress by default. `phone` is fully offline. `serve` accepts inbound HTTP on `127.0.0.1:8080` by default.
TLS is verified against Mozilla's roots built into the binary. On a network that intercepts
TLS with its own CA (a corporate inspection proxy, a sandbox), every lookup fails with
`tls_failure` or `connect_failure`; set `HUNTSMAN_CA_BUNDLE` to a PEM bundle that includes that
CA, and its certificates replace the built-in roots. Verification stays on. A bundle that cannot
be read or holds no certificate fails every request with `tls_failure` naming the variable; it
never falls back to the built-in roots.
Review [`docs/INSTALL.md`](docs/INSTALL.md) and the command reference below
before using credentials or network access.

## Repository map

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI and local-HTTP integration tests; `android_ci.rs` (the CI workflow keeps the aarch64 Android cross-build and its artifact); plus `readme.rs`, which checks this README's examples, usage, exit codes and gate range against the binary, and `architecture_doc.rs`, which checks `ARCHITECTURE.md` against `src/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | Design and operations notes, including `RELEASING.md` (the main-channel release workflow, its key scanner, publish refusals and required attestation). |
| `docs/ARCHIVE_PROVENANCE.md` | SHA-256 and Git identities of the historical source archives, which are absent from the active tree and recoverable from Git history. |
| `.github/` | `workflows/ci.yml` (tests on Rust 1.87 and the pinned stable release; aarch64 Android cross-build), `workflows/release.yml` (`main-<sha7>` pre-releases of `huntsman-recon`), `scripts/` (`scan-for-keys.sh`, `install-termux.sh`) and `actions/setup-ndk-aarch64` (NDK compiler and linker environment). |
| `CHANGELOG.md` | Notable changes, Keep a Changelog format. |
| `changelog.d/` | One fragment per change (`<slug>.<section>.md`), checked by every gate mode and assembled into `CHANGELOG.md` by `cargo run --locked -p xtask -- changelog assemble` when a version heading is cut. |
| `docs/COMMERCIAL_READINESS.md` | Buyer/client due-diligence index: reusable assets, proof boundaries, commercial-readiness gates, and value-maximizing engineering sequence. |

## Which binary to use

| | `hse` (legacy v1.41.0 monolith) | `huntsman-recon` (this tree, in progress) |
| --- | --- | --- |
| Person lookups | Yes. Provider modules such as `asic_persons`, `asic_director`, `username_search`, `phone_au` and `bluesky_user` (195 `pub mod` entries in `src/modules/mod.rs` at `7dca720b`), plus `hse scan`, `hse investigate` and `hse serve`. Whether each provider works live has not been re-verified. | **Partial.** `people` calls `asic_persons`, `asic_director`, `au_people` and `au_electoral` for names with at least two alphabetic tokens. `email ADDR` canonicalises an address, derives deterministic email pivots, queries the public Gravatar profile, renders evidence lineage, and can save a ledger for `verify`. `username HANDLE` derives bounded normalization variants, queries the public GitHub and Bluesky profiles independently, renders lineage, and can save a ledger for `verify`. `phone NUMBER` canonicalises explicit international syntax or recognised Australian local syntax, resolves the dialling prefix offline, enriches Australian numbering-plan line type/region, and can save a ledger for `verify`. `scan SELECTOR` routes one selector to `people`, `email`, `username`, `phone`, `domain` or `ip` automatically, with `-k` available for an explicit rebuilt kind. A selector that is not an email, handle, domain, or recognised phone, and has fewer than two alphabetic tokens of at least two letters, is not inferred as a name: `scan` refuses it with exit 65 rather than reporting a skip as success. `scan -k people WORD` needs a name: a single token exits 65 and the people command is not reached. `people WORD` on its own still skips a single token with exit 0. `scan --input-file FILE [-k KIND]` runs the same routing once per unique non-comment line, attempts every seed, and reports a non-zero final status if any seed fails. `sources` classifies an input (a person or organisation name, an email address, an `@username`, a domain, an IP address or coordinates) and only prints curated public search or browser URLs for it, offline and `LeadOnly`; nothing is fetched. `search` reads only local documents; `hibp` provides explicit opt-in HIBP lookups. |
| Source | Maintained branch `legacy-hse`, seeded from verified monolith commit `98c77fd8dac95082515f0f76cea8f4f0dc7a604b`. | `src/` |
| Where to get it | Maintained `legacy-hse` branch via its installer; its release workflow publishes per-commit `hse-aarch64-linux-android` pre-releases. | A GitHub pre-release `main-<sha7>` (asset `huntsman-recon-aarch64-linux-android`), the CI artifact of the same name from a `main` push (see "Downloads"), or a source build |

`huntsman-recon` is the in-progress replacement, with rebuilt person-lookup slices plus a minimal embedded Web UI/API. Every relevant push to `main` is built and verified; the commit is published as a `main-<sha7>` pre-release only if it is still the current main head when publication occurs. A superseded build remains available as a GitHub Actions artifact for its retention window rather than failing while trying to create a historical tag. There is no rolling `latest` pre-release: the workflow creates or moves `latest` only when the repository variable `PROMOTE_RECON_TO_LATEST` is `true`, and it is unset. GitHub's "Latest release" is the stable legacy `hse` release `v1.41.0`.

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is explicit opt-in via the CLI or library. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

For contributors: one Rust package (`huntsman-recon`), Rust 1.87+, in a workspace with the `xtask` automation crate.
The binary's full command list is available with `huntsman-recon --help`;
run `huntsman-recon COMMAND --help` for command-specific usage. `diagnostics [--json]`
is fully offline, backed by the reusable `diagnostics` library module, and reports only non-secret build/runtime/module/provider state; `build-sha`
prints the source commit embedded by provenance-aware builds and prints `unknown` for
ad-hoc builds that did not supply one.

```
cargo test
cargo run -- check                     # self-acceptance + command invariant; regenerates var/*.json
cargo run -- doctor --help             # checks the whole install; `huntsman-recon doctor` names the fix for each problem
cargo run -- fix --help                # `huntsman-recon fix` makes every repair that can be undone, then checks again
cargo run -- diagnostics --json        # offline build/runtime/module/provider status; no secret values
cargo run -- build-sha                 # exact embedded commit for provenance builds, otherwise unknown
cargo run -- command                   # validate + print engineering command contract
cargo run -- directive --help          # repository directive verifier/self-repair usage
cargo run -- verify var/ledger.json    # entries, admitted count, tip; non-zero if broken
cargo run -- correlate --help          # correlation rules over a dehashed --save-artifact scan, --history DIR pivots it across saved scans; offline
cargo run -- run-history --help        # record test-run results and compare each with the earlier runs
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
cargo run -- credential-status             # offline; per provider: configured?, where to get the key, free tier; never prints values
cargo run -- credential-status --probe     # opt-in live checks for configured providers with registered probes
cargo run -- fetch https://example.com/  # guarded fetch; run `fetch` without a URL for options
cargo run -- hibp help                   # HIBP subcommands; offline
cargo run -- dehashed help               # DeHashed subcommands; offline (search needs a key and --purpose)
cargo run -- seeknow --help              # SeekNow subcommands; offline
cargo run -- people Madonna              # skip path: fewer than two alphabetic tokens of at least two letters, no network
cargo run -- people Madonna --save skip.json  # skip still writes nothing; --save needs a lookup
cargo run -- email nobody@example.com     # deterministic pivots + public Gravatar lookup, plus every configured keyed breach leg
cargo run -- exposure nobody@example.com  # HIBP account + stolen.tax + OathNet evidence, then each breach's summary, flags and source links (keyed; no key = no request)
cargo run -- exposure @some_handle  # the same for a username: stolen.tax + OathNet (HIBP searches addresses only)
cargo run -- username octocat             # variants + public GitHub/Bluesky lookups, plus stolen.tax/OathNet when keyed
cargo run -- phone "0412 345 678"           # offline E.164 + AU numbering-plan classification
cargo run -- domain example.com             # crt.sh names, Cert Spotter certificates, DNS records over DoH, each subdomain resolved; network
cargo run -- ip 1.1.1.1                    # PTR + InternetDB + RIPEstat + GreyNoise, keyed legs when set; network
cargo run -- netblock 1.1.1.0/24            # RDAP + RIPEstat + the PTR names of every address in the block; network
cargo run -- asn AS13335                    # RDAP + RIPEstat holder, every announced prefix and BGP neighbour; network
cargo run -- network 3c:5a:b4:01:02:03      # BSSID: offline OUI vendor, then WiGLE WiFi + Bluetooth search (keyed; no key = no request)
cargo run -- scan "0412 345 678"            # auto-route to the rebuilt phone front-end
cargo run -- investigate "mail ada@example.com visit https://example.org"  # offline entity extraction
cargo run -- plan ada@example.com example.com  # offline spine: entities, relations, planned routes; nothing fetched
cargo run -- query "OpenAI research"          # network: Bing/Brave/Mojeek subset
cargo run -- sf -M                         # SpiderFoot-style reachable-module listing; offline
cargo run -- scans types                   # Spiderfoot 4.0's 172 data-element types plus Huntsman's own; offline
cargo run -- scans rules                   # every correlation rule a saved scan runs: Huntsman's own and Spiderfoot 4.0's 37; offline
cargo run -- serve --help                    # embedded UI/API command options; does not start a listener
cargo run -- modules --json               # only modules currently reachable from the binary
cargo run -- attack status --json          # offline ATT&CK Reconnaissance capability posture
cargo run -- recon crtsh https://example.com/
```

`attack status|coverage|gaps [--json]` restores the MITRE ATT&CK Reconnaissance reporting surface over currently reachable network modules. The TA0043 slice is reconciled through ATT&CK v19.2, including T1681 and T1682; the repository's complete embedded Enterprise matrix remains the older v17.1 baseline and is reported separately rather than mislabeled as current. `attack navigator` emits Reconnaissance Navigator JSON. Coverage is hierarchy-aware and evidence-backed: only module-mapped independent leaf techniques count as covered, parent techniques remain roll-ups, and coverage is not proof that a technique was executed or a measure of detection effectiveness.

`search` needs at least one term of two or more letters or digits (exit 64 otherwise). `search DIR` loads `.txt` and `.md` (any case) from that one directory. Challenge pages, non-UTF-8 files, files over 1 MiB, and symlinks are skipped and listed on stderr. An unreadable directory exits 66; it does not print `hits=0`.

Credentials for `fetch --bearer SLOT` / `--header NAME=SLOT` come from a keys file and the process environment. The file is `NAME=value` lines (`export`, quotes, blank lines and `#` comments allowed; placeholder values count as unset) and is parsed by `keys::Keys::parse`, the parser `--keys FILE` and `keys FILE` use through `Keys::load`.

- `--keys FILE` loads that file, and a slot the file lacks falls back to the process environment (see the `--keys FILE` row in the command table). A file accessible by group/others is an error (exit 66, `run chmod 600`).
- Without `--keys`, `$HOME/.huntsman.env` is parsed with the same parser when it exists. If the file is missing (not found, or a `HOME` path component is not a directory), or `HOME` is unset, nothing changes: only the environment is used and nothing is printed. An empty or relative `HOME` (`HOME=.`, `HOME=relative/dir`, `HOME=`) behaves the same, except that it prints one warning (`HOME is not an absolute path`, without the value), so the default file never depends on the working directory. The path is checked with `lstat` and is never followed. The file is not read, and the run continues with the environment only after one stderr warning naming the path and the reason, if it is:
  - a symlink, even to a valid mode-600 file (fix: remove the symlink and create a regular file owned by you with mode 600, or pass `--keys`; `chmod` would follow the link);
  - not a regular file;
  - owned by a uid other than the process's effective uid (read from `/proc/self/status`; where that is unavailable, the file is refused and `--keys` is the way to supply it);
  - accessible by group/others (`mode & 0o077 != 0`; fix with `chmod 600 ~/.huntsman.env`).

  The file is read through the descriptor that was opened. That descriptor must be the same device/inode `lstat` saw and must pass the same checks, so a swap between the check and the read is refused rather than followed. Every other bounded read in the crate (`fsio::read_bounded`, behind `--keys FILE`, `investigate --file`, `scan --input-file`, the ledger, the session store and the directive files) makes the same device/inode check, as do the run-history writes. `O_NOFOLLOW` is not set: `OpenOptionsExt::custom_flags` is safe Rust, but the flag value differs per architecture and would need the `libc` crate or a hard-coded per-target table. The remaining gap is a regular file swapped for a FIFO between `lstat` and `open`, which would block the open; that requires write access to `$HOME`.
- Fail-closed cases are separate from the refusals above. They apply only to a default file that passes those checks, and they return an error instead of a warning. A fetch that requests a credential then exits 66, even if the slot is set in the environment:
  - a malformed line (`keys line N: ...`, line number only);
  - content that is not UTF-8;
  - a file over 64 KiB;
  - any I/O error other than not found / not a directory (for example a mode-`200` file the owner cannot open, or a `$HOME` that cannot be searched).
- Precedence: a slot present in the loaded file wins over the same environment variable; slots the file lacks fall back to the environment.
- The file is read only when a credential slot is requested. Values never appear in output, warnings or errors; only slot names, line numbers and fingerprint prefixes do.

`sources` is offline routing, not collection. It classifies the input using the existing Huntsman classifier and renders only compatible, independently curated public/browser search routes from `source_registry`. Generated routes are `LeadOnly`: a URL is never corroborating evidence by itself. External catalogue code or data is not embedded.

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input or failed credential setup (unconfigured slot or unreadable keys file or a bad URL when `--bearer`/`--header` is given), 69 `fetch`/`recon`/`seeknow`/`email` got no usable response or `people` registers were unusable, 74 artifact or output write failure, 77 `fetch`/`recon`/`seeknow`/`email` refused the request (egress policy or malformed URL or redirect target; without a credential option a malformed URL lands here) or `people` encountered a network-policy refusal, 78 `doctor` or `fix` found a check that fails, 141 the reader of the output closed it before the command finished (128 + SIGPIPE as a shell reports it; a `--save` file is written before anything is printed). `check` uses 2–11 for its individual gates. Running the binary with no command prints the help and the usage line to standard error, exits 64 and writes nothing; `help`, `-h` and `--help` print them to standard output. `check` writes `var/*.json` into the current directory, so run it in a checkout or an empty directory.

`tests/readme.rs` runs every offline example above, checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to the CLI composition sources under `src/cli/`. Network HIBP examples below are exercised through a fake transport by `tests/hibp_cli.rs` rather than against the internet in CI.

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

The refactor-overlay foundations preserved under historical Git tree `39d9f765f0b58c70b2e30ae6b49538a74042ff1c` are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` gate 5 exercises four of them: `source_outcome` (a 403 Cloudflare challenge page is `BotWaf`, and its recommended action is not `RequireCredential`); `evidence_ancestry` with `identity_resolution` (two mirrors of one dump cannot auto-merge two identities, while a mirror plus an independent registry root can); and `termination` (delayed retry work is not a fixed point). Gate 5 does not exercise `credential_origin` or `eval`. The binary uses `credential_origin` in `fetch` (the operator-approved credential authority) and for the fingerprints that `fetch` and `keys` print. `eval` is not used by the binary at all; only its unit tests exercise it.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See [architecture and status](ARCHITECTURE.md) for the reconstruction decisions and verification approach.

## HIBP (`hibp` command)

`huntsman-recon hibp SUBCOMMAND` exposes the HIBP v3 and Pwned Passwords client in `huntsman_recon::hibp` (blocking, single crate; the async monolith and both legacy snapshots are unchanged). Requests use the guarded `UreqTransport` and existing fetch boundary, with redirects off and only trusted HIBP/Pwned Passwords HTTPS origins accepted. HIBP is contacted only by an explicit HIBP command or `credential-status --probe`; ordinary `credential-status` remains offline.

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

Output is `key=value` lines. Each run starts with `source=HIBP`, `service=` (`api-v3` or `pwned-passwords`), `source_attribution=` and `results=N`. `credential-status --probe` also uses the canonical `/subscription/status` endpoint to validate a configured HIBP key and reports non-secret plan metadata such as `SubscriptionName`, `Rpm`, `IncludesStealerLogs` and `IncludesKAnon`. Breach/account output preserves the complete parsed model; pastes preserve every parsed paste field; `password-range` drops zero-count padding entries; `subscription` reports plan/rate/entitlement fields and `key_source=`, never the key. Results are never intentionally truncated.

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

`recon dns TARGET` accepts a domain, URL or email and queries Cloudflare, DNS.SB
and Google DNS-over-HTTPS (JSON) for apex A, AAAA, MX, NS and TXT, plus
`_dmarc` and `_smtp._tls` TXT, through `fetch` with redirects off. One
record-type failure does not abort the others. A challenge page is `bot_waf`,
a truncated body is `truncated`, and HTTP 429 is `rate_limited`; none of those
is parsed as DNS JSON. Quoted TXT presentation is decoded before SPF (RFC 7208),
DMARC (RFC 7489) and TLSRPT (RFC 8460) parsing. Output is
`type<TAB>name<TAB>rdata<TAB>resolver` lines, then `spf_all=`, `dmarc_policy=`
and `tlsrpt_emails=` when those records parse, plus `failed` rows. An invalid
selector exits 65 before any request, and a blank target is a usage error (exit 64); no usable answer exits 69. DoH is
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

Toolchain: the crate's MSRV is Rust 1.87 (`rust-version` in `Cargo.toml`); CI tests Rust 1.87 and one pinned stable release, currently 1.99; `tests/ci_toolchains.rs` holds the pin, so a new release's lints cannot turn `main` red until the pin is bumped on purpose. The owner's reference toolchain is Rust 1.98.0. The repository has no `rust-toolchain.toml`, so rustup uses your default toolchain.

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
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
cargo build --release --locked --target aarch64-linux-android
```

The reference NDK is 27.3.13750724. CI uses the runner's `ANDROID_NDK_LATEST_HOME` and does not pin an NDK version. The link asks for 16 KiB page alignment, which devices with 16 KiB pages (Android 15 and later on recent hardware) require and which NDK r27 does not give by default; both CI cross-builds refuse a binary whose LOAD segments are aligned to less (`tests/android_ci.rs`). No build reads a key: HIBP keys are read at run time only (see "Opt-in HIBP library" below).

### Downloads

Each push to `main` uploads a CI artifact named `huntsman-recon-aarch64-linux-android`: the binary plus its `.sha256`, kept for 14 days. Download it from the workflow run's page, or with `gh run download <run-id> -n huntsman-recon-aarch64-linux-android`. Check it with `sha256sum -c huntsman-recon-aarch64-linux-android.sha256`, then copy it into Termux's home directory and `chmod +x` it.

Each relevant push to `main` builds and verifies the Termux artifact; when that commit is still the current main head at publication time, `.github/workflows/release.yml` publishes a `main-<sha7>` pre-release with the `huntsman-recon-aarch64-linux-android` binary, its `.sha256`, a `.provenance.json` naming the commit, a zero-finding `key-scan-report.txt` and `install-termux.sh`. Superseded commits keep their verified Actions artifact for the configured retention window instead of attempting a historical-tag release. The `main-<sha7>` pre-releases up to `main-7dca720` predate the reconstruction and ship the legacy `hse` binary. No rolling `latest` pre-release exists (see "Which binary to use"). Release policy: only pre-releases (`main-<sha7>` plus a rolling `latest`); a stable release needs the owner's explicit approval and is never automatic.

## Opt-in HIBP library

`huntsman_recon::hibp` ports the HIBP branch onto this single blocking crate; it does not restore the async monolith or modify either legacy snapshot. `HibpClient::production(Auth::ApiKey(key), HibpConfig::default())` uses the guarded `UreqTransport` and the existing fetch boundary without following redirects. An injected `Arc<dyn Transport + Send + Sync>` supports offline tests.

Read endpoints: breach catalogue, individual/latest breach, data classes, breached accounts (including options and local SHA-1 k-anonymity lookup), pastes, verified-domain breaches, subscribed domains, subscription status, all three stealer-log searches, and free SHA-1/NTLM Pwned Passwords ranges with padding. Domain verification and email-sending endpoints are intentionally excluded. Keys never go to public or password endpoints. Entitlements are checked against a cached subscription response; missing flags fail closed. Keyed calls start with a 10/minute sliding window (or `HIBP_RATE_LIMIT_PER_MINUTE`; `0` disables local pacing), and every successful `/subscription/status` response with a positive `Rpm` retunes the active limiter while preserving already-consumed capacity. 429 retries are bounded; a server delay above `max_retry_after` returns immediately instead of retrying sooner than requested. Truncated or malformed bodies are errors. A Pwned Passwords 429 is not retried; it returns a rate-limited outcome with the server retry hint when available.

Key precedence: `HIBP_API_KEY`, caller's `HUNTSMAN_HIBP_KEY` slot (or that environment variable), then private `~/.config/hibp/api_key`. Blank/placeholders are ignored; files are bounded and symlinks refused. Keys are read at run time only, from the environment or a key file: no build reads one, and the release workflow's key scan (`.github/scripts/scan-for-keys.sh`) must find none in the files it publishes.

`hibp::oauth` implements discovery, public registration, PKCE S256 authorization, code exchange and refresh for the documented MCP resource, **not REST v3 bearer authentication**. The caller must verify the returned state before exchanging a code. Authorization-server URLs must stay on HIBP's HTTPS origin. Linux/Termux randomness comes from `/dev/urandom`. Token stores support memory or bounded, atomic mode-600 files. Debug/errors omit keys, tokens and upstream error bodies.

All CI HIBP integration evidence is offline fake-transport testing. Earlier development smoke tests exercised public HIBP endpoints on an antecedent branch, but they are not a qualifying live receipt tied to this final commit. Termux handset acceptance also remains unverified.

## Opt-in ASIC people-register library

`huntsman_recon::asic_persons::lookup` queries three keyless ASIC registers on
data.gov.au CKAN (banned and disqualified persons, financial advisers, credit
representatives) through the shared `fetch` boundary and an injected
`http::Transport`. A name with fewer than two alphabetic tokens of at least two letters makes no
request. Challenge pages, truncated bodies, and CKAN `success: false` envelopes
are not evidence of absence. The binary exposes `people NAME [--save FILE]`
(unquoted words are joined) through `people_cli`, which also runs
`asic_director`, `au_people` and `au_electoral` over the same transport and
feeds emitted evidence through `lineage::resolve_with_lineage`. One source
`Invalid` or BotWaf does not abort the others. 

Results from all four sources are automatically merged by entity UID: records with identical
UIDs from different sources are consolidated into a single entity whose observation set includes
evidence from all sources. This merge rule detects when one person has records across multiple
Australian public registers (ASIC people, ASIC directors, True People Search AU, electoral rolls)
and surfaces corroborated attributes.

`--save FILE` writes an
unverified hash-chained ledger of outcomes and entities that `verify FILE`
reloads byte-identically (`admitted=0`; a register row is not identity
resolution). Skip (fewer than two alphabetic tokens of at least two letters) makes no request and does
not write. Tests use a scripted transport; the README examples are the skip
path. Two-token names query those sources and are not run in CI. There is no
live receipt. Live ASIC Connect is WAF-blocked.

## Lineage and the automatic-merge rule

`huntsman_recon::lineage::resolve_with_lineage` takes parsed observations and candidate merge decisions. It derives countable lineage from explicit upstream dataset fields and, where the acquisition path is verified, registry identity; record URLs/ids and collector names do not create independent families. Two collectors relaying one dataset therefore count as one family. It returns every observation and every candidate. A candidate auto-merges only with two independent families and a present, in-range match probability of at least 0.90 (legacy `breach_consensus` parity). Otherwise it is held, with every reason stated. `check` gate 5 runs it, and separately checks a hand-built ancestry graph through `allows_automatic_merge`, the path `resolve::automatic_clusters` uses. See `docs/LINEAGE.md`.


### Email lookup

`email ADDR [--save FILE]` canonicalises the selector, derives deterministic non-network email pivots, queries the public Gravatar profile, renders lineage, and optionally writes an unverified ledger that `verify` can reload. A missing Gravatar profile is a validated zero result; malformed or incomplete responses are not treated as absence. Kickbox Open checks, keyless and from the domain alone, whether the address is at a disposable-mail provider. StopForumSpam (forum-spam report count and last report) and XposedOrNot (names of public breaches that included the address, never record content) are also keyless. With keys set in the environment it also runs IPQualityScore email validation (`HUNTSMAN_IPQS_KEY`), the Hunter.io verifier (`HUNTSMAN_HUNTER_KEY`) and Whoxy reverse WHOIS (`HUNTSMAN_WHOXY_KEY`, each registered domain becomes a pivot). It also runs every keyed breach leg that has its key (HIBP, stolen.tax, OathNet, as `exposure` does), with its incidents and `OathNet` sections after the report; a `username` lookup does the same with stolen.tax and OathNet. A source or breach leg whose key is not set makes no request, and the report is then unchanged.

### Username lookup

`username HANDLE [--save FILE]` keeps the operator selector, derives bounded separator/de-decoration variants at candidate confidence, and performs keyless public-profile lookups against GitHub and Bluesky. Provider absence, rate limits, malformed responses, and unsupported handle shapes remain distinct outcomes. `--save` writes an unverified ledger that `verify` can reload.

### Phone lookup

`phone NUMBER [--save FILE]` is offline unless `HUNTSMAN_NUMVERIFY_KEY` is set in the environment; then it also asks Numverify (APILayer, free 100 lookups a month) for the carrier, line type and location, and reports a refused key or exhausted quota as such. With `HUNTSMAN_IPQS_KEY` set it also asks IPQualityScore for the line type, carrier, VOIP and prepaid flags and a fraud score. It canonicalises explicit international syntax and recognised Australian local numbers to E.164, resolves the international dialling prefix from the embedded legacy-compatible table, and enriches Australian numbers with numbering-plan line type plus coarse fixed-line allocation region. It does not guess the country of an ambiguous bare foreign national number and does not infer a mobile carrier. `--save` writes an unverified ledger that `verify` can reload.


### IP lookup

`ip ADDRESS [--save FILE]` looks up one public IPv4 or IPv6 address. Keyless: the address's PTR records over the same DoH resolvers `domain` uses (each record listed on the address as published, each name a pivot tagged `ptr` and the address's own `INTERNET_NAME` in a saved scan, as Spiderfoot's `sfp_dnsresolve` reverse-resolves; its `dnsresolve` row is a validated zero when the reverse zone has none), Shodan InternetDB (open ports, hostnames, CPEs, known CVEs), RIPEstat (covering prefix, origin AS and its holder), GreyNoise Community (internet scanner or benign service) Pulsedive (threat risk, feeds, seen technologies), Netlas (scan data, IOC listings, WHOIS AS), AlienVault OTX (threat pulses, malware families, adversaries), urlscan.io (public page scans and their verdicts), IPinfo (reverse hostname, origin AS, city), Robtex (BGP route, origin AS, passive DNS names), HackerTarget (domains hosted on the address) and StopForumSpam (forum-spam reports, Tor exit). `HUNTSMAN_OTX_KEY`, `HUNTSMAN_URLSCAN_KEY` and `HUNTSMAN_IPINFO_KEY` raise those three limits. Keyed, each whenever its key is set in the environment: AbuseIPDB (`HUNTSMAN_ABUSEIPDB_KEY`, abuse confidence and reports), VirusTotal (`HUNTSMAN_VIRUSTOTAL_KEY`, engine verdicts), Shodan (`HUNTSMAN_SHODAN_KEY`, services, org and hostnames), LeakIX (`HUNTSMAN_LEAKIX_KEY`, exposed services and data leaks), ThreatFox (`HUNTSMAN_THREATFOX_KEY`, IOCs naming the address), URLhaus (`HUNTSMAN_ABUSECH_KEY`, the same abuse.ch key, malware URLs hosted there) and IPQualityScore (`HUNTSMAN_IPQS_KEY`, fraud score and proxy/VPN/Tor flags); `HUNTSMAN_GREYNOISE_KEY`, `HUNTSMAN_PULSEDIVE_KEY` and `HUNTSMAN_NETLAS_KEY` raise those limits. A private, loopback, link-local, CGNAT, documentation or other non-public address exits 65 before any request. `scan` routes a public address to `ip` automatically, and the web UI offers it as a kind. Both `ip` and `domain` also read the registration over RDAP, keyless, from the registry the IANA bootstrap names (`rdap`, Spiderfoot's `sfp_whois`): the record as published (`DOMAIN_WHOIS` or `NETBLOCK_WHOIS` in a saved scan), the registrar (`DOMAIN_REGISTRAR`), every event date, status, name server and network block, and every contact's name, organisation, address, telephone and email, a registry's privacy placeholder included; the registrar, name servers, contact organisations, emails and telephones become entities, a placeholder never does. A host is looked up as its registrable domain; not registered is a validated zero. Both `ip` and `domain` also ask the DNS blocklists Spiderfoot asks, keyless, through the device's own resolver (Spamhaus refuses public resolvers): an address is asked of Spamhaus ZEN (IPv4 and IPv6), SpamCop, UCEPROTECT levels 1 to 3, DroneBL (IPv4 and IPv6), SORBS and SURBL, and a domain of the Spamhaus DBL and SURBL. Each listing is kept on the address or domain with its list, zone, answer and reason (`BLACKLISTED_IPADDR` or `_INTERNET_NAME` and `MALICIOUS_*` in a saved scan, each list its own source), and each list has its row. Before trusting a zone the lookup asks its RFC 5782 test points; a zone that refuses the resolver, misses its test point, lists everything or does not answer says so on its row instead of reporting "not listed". `domain DOMAIN` also asks the eight public filtering resolvers Spiderfoot asks (`adguard_dns`, `cleanbrowsing`, `cloudflaredns`, `comodo`, `dns_for_family`, `opendns`, `quad9` and `yandexdns`), keyless, over DNS-over-HTTPS in its wire form where a filter offers it over HTTP/1.1, so no resolver on the path answers for them, and over UDP to the filter's own servers for Comodo (which has none) and Quad9, DNS for Family and Yandex (whose DoH needs HTTP/2): AdGuard's default and family filters, CleanBrowsing's security, adult and family filters, Cloudflare's malware and family filters, Comodo Secure DNS, DNS for Family, OpenDNS FamilyShield, Quad9 and Yandex's family filter. A block is the filter's block address (OpenDNS's and Yandex's name the category), no address for a name the domain's own records resolve, or an extended DNS error saying the answer was blocked, censored or filtered; each is kept with the filter, the resolver, the answer and its records (`BLACKLISTED_INTERNET_NAME` in a saved scan, and `MALICIOUS_INTERNET_NAME` too when the filter blocks malware, phishing or botnets). Each filter is first asked a name it is known to block; one that does not block it (as when the network answers port 53 itself), errs or does not answer says so on its row, and Comodo, which has no known test point, says its "not blocked" is unverified. That is how the lookup sees that AdGuard's default filter and DNS for Family now answer `0.0.0.0` for what they block, which Spiderfoot, still looking for their old block addresses, misses. `domain DOMAIN` also reads every certificate Cert Spotter (`certspotter`, Spiderfoot's `sfp_certspotter`, keyless; `HUNTSMAN_CERTSPOTTER_KEY` raises its limit) logged for the domain and its subdomains, up to Spiderfoot's 20 pages of 100: each is a record on the domain with Cert Spotter's hashes, issuer, validity, revocation and names, and from the certificate itself its serial, subject, key and signature algorithms and the PEM (`SSL_CERTIFICATE_RAW`, `SSL_CERTIFICATE_ISSUED`, `SSL_CERTIFICATE_ISSUER` and `SSL_CERTIFICATE_EXPIRING` or `_EXPIRED` in a saved scan). Every name it covers is a domain entity (a wildcard as the name under it) listing the certificates that name it, and an OV or EV certificate's organisation is an entity with its place and registration number; the row says where a lookup stopped when the page bound or a rate limit cut it short. A domain lookup reads with crt.sh's 30-second timeout and 16 MiB body limit, so a popular domain's certificate list is not cut off. `domain DOMAIN` likewise asks Pulsedive and Netlas without a key and adds VirusTotal (`HUNTSMAN_VIRUSTOTAL_KEY`), the addresses Hunter.io found published for the domain (`HUNTSMAN_HUNTER_KEY`), Shodan DNS records (`HUNTSMAN_SHODAN_KEY`, one query credit), LeakIX, ThreatFox, URLhaus, SecurityTrails subdomains (`HUNTSMAN_SECTRAILS_KEY`) and the live Whoxy WHOIS record (`HUNTSMAN_WHOXY_KEY`, one credit) when those keys are set. A key that is set always runs its source; subdomains, record targets, name servers and WHOIS contacts become pivots only in canonical form. Last, as Spiderfoot's `sfp_dnsresolve` does, every subdomain any leg found (up to 512, eight at a time, over the same DoH resolvers) is asked for its A and AAAA records: each public address becomes an address entity that is the host's child, every address including a private one is listed on the host, and a host whose zone has neither record is tagged `unresolved`, Spiderfoot's `INTERNET_NAME_UNRESOLVED`. Its `dnsresolve` row counts the hosts resolved, unresolved, unanswered and not asked; when the resolvers did not answer the domain's own queries no host is asked, and four hosts failing before any answers stops the leg. A keyed leg without its key makes no request; `credential-status` lists every slot and where to get the key.

`netblock CIDR [--save FILE]` looks up one public IPv4 or IPv6 address block, Spiderfoot's `NETBLOCK_OWNER` (`NETBLOCKV6_OWNER`) target, written `ADDRESS/PREFIX` with its host bits cleared (`1.1.1.7/24` is `1.1.1.0/24`). Keyless: the RDAP registration of the smallest registered network that holds the block (its `NETBLOCK_WHOIS`, holder, contacts and range), the RIPEstat prefix covering it and its origin AS and holder, and, as Spiderfoot's `sfp_dnsresolve` does for a netblock target, the PTR records of every address in a block of at most 256 addresses (a /24, or a /120 of IPv6, Spiderfoot's limits), eight at a time over the DoH resolvers. Each address with a record is an address in the block, every record listed on it as published, and each name a domain tagged `ptr` that is the address's `INTERNET_NAME`; a larger block's `dnsresolve` row says it was not swept. A block whose first address is private or documentation space exits 65 before any request. `scan` routes a block to `netblock` automatically, `sf -s 1.2.3.0/24` scans it as Spiderfoot's own CLI does, and the web UI offers it as a target type.

`asn AS-NUMBER [--save FILE]` looks up one public autonomous system, Spiderfoot's `BGP_AS_OWNER` target, written `AS13335`, `ASN13335` or `13335`. Keyless, and all four calls at once: the RDAP registration of the AS from the registry the IANA bootstrap names for its range (the record as published, its `NETBLOCK_WHOIS`, holder and contacts), and from RIPEstat, as Spiderfoot's `sfp_ripe` reads it, the holder and registry block (`as-overview`), every prefix the AS announces with every window the collectors saw it in (`announced-prefixes`; each an address block, Spiderfoot's `NETBLOCK_OWNER` or `NETBLOCKV6_OWNER` under the AS), and every AS adjacent to it in the collected BGP paths with its side (`left`, `right` or `uncertain`), how widely it was seen and over which address families (`asn-neighbours`; each a `BGP_AS_MEMBER`, which `sfp_ripe` fetches and drops). Nothing is capped: an AS announcing tens of thousands of prefixes is reported with all of them, and its answer may run to 64 MiB. One `ripestat` row says what each call answered, and names any that failed beside what the others found. A reserved, private-use or documentation AS number (`AS0`, `AS23456`, `AS64496`-`AS131071`, `AS4200000000` and up) exits 65 before any request. `scan` routes `AS13335` to `asn`, and bare digits that are not a phone number too, as Spiderfoot reads `1234`; the web UI offers it as a target type and a New Scan of every AS row.

### Reachable module catalogue

`modules [--json]` is offline and intentionally conservative: it lists only rebuilt modules that have a current `huntsman-recon` command path. A provider definition or compiled helper is not advertised merely because it exists in the source tree. This avoids presenting unconnected modules as operational capability.


### Offline investigate

`investigate TEXT... | investigate --file FILE` extracts actionable entities through the rebuilt classifier without network access. File input uses the bounded reader, refuses symlinks, and is capped at 1 MiB. The `modules` catalogue includes this path as `classifier` only because it is now reachable from the binary.


### Offline investigation plan

`plan [--session-dir DIR] SEED [SEED ...]` runs the offline integration spine described in [docs/RUNTIME_INTEGRATION.md](docs/RUNTIME_INTEGRATION.md): it normalises the seeds into entities and relations, analyses that one state, and plans the external source routes without fetching any of them. `--session-dir DIR` saves the run as a session, written before anything is printed, and `plan --load-session DIR ID` prints a saved one. An option it does not know, a repeated `--session-dir` or one without a directory exits 64 before the run starts, so a request to save is never dropped. This was a separate `investigate` executable, which the prebuilt release did not ship.


### Web meta-search

`query QUERY...` restores a bounded keyless subset of the legacy multi-engine search path. It currently queries Bing, Brave, and Mojeek independently through the shared fetch boundary, extracts external HTTP(S) result URLs, deduplicates them, and reports each provider outcome separately. One blocked or drifting engine does not erase results from another. Repeated anonymous queries reuse bounded in-process responses for up to five minutes; `no-store` responses are never cached, transient transport/5xx failures get one bounded backoff retry, and a provider circuit suppresses repeated calls while it is cooling down. The broader legacy engine set, dork packs, pagination, ranking, snippets, and live differential receipts remain outstanding.


### SpiderFoot-compatible front end

`sf` is Spiderfoot 4.0's `sf.py` command line over Huntsman's saved scans. `sf -M`, `sf -T`, and `sf -V` are offline. `sf -s TARGET` detects the target's Spiderfoot type as `sf.py` does and runs the scan `scans run` runs for it: a domain (`INTERNET_NAME`), an IPv4 or IPv6 address, an email address, a phone number, a username or a quoted name, through the same lookups, keyed sources included whenever their key is set, with an email's breach lookup after it. The scan is saved with the others in `~/.huntsman/scans`, as `sf.py` keeps its scans in its database, so `scans` and `serve` read it and `sf -C ID` runs every correlation rule again over it, as `sf.py -C` does; stderr names its id unless `-q` is given, and `-d` prints the scan's log there. `sf -l IP:PORT` serves the web UI there, as `serve --bind` does. `-u all|footprint|investigate|passive` is the scan's use case (passive skips an email's keyed breach lookup, as `scans run -u passive` does), `-t TYPE[,TYPE...]` keeps only those types in the saved scan, `-f` prints only the `-t` types, `-x` (with `-t`) runs only the lookups that take the target itself and prints only the `-t` types, `-F TYPE[,TYPE...]` prints only those types without changing what the scan keeps, and `--depth N` follows what the scan finds N hops, as `scans run --depth` does. The rows are `sf.py`'s: tab (module and type padded to 30 and 45 characters), CSV (`-D DELIMITER`) or JSON (`-o`), with `-H` leaving out the header, `-r` adding the source data, `-n` turning line breaks in data into spaces and `-S LENGTH` cutting each value to that many characters. A JSON row has `sf.py`'s keys (`generated`, `type`, `data`, `module`, `source`) and the rest of the element too: `event_type`, `id`, `source_id`, `confidence`, `false_positive`, `entity` and the raw evidence. An address block (`1.2.3.0/24`, `2606:4700::/32`) is scanned as a `netblock`. `sf.py` quotes bare digits, so `sf -s 13335` is a username scan as it is in `sf.py`; an AS target comes from `scan`, `scans run` or the web UI and runs `asn`. A scan whose every lookup refused exits with the status and message of the plain lookup. `-f` or `-x` without `-t`, `-x` with `--depth`, and `-D` outside CSV are refused, as `sf.py` refuses them; `-m` and `-max-threads` are not taken yet. `sf -T` lists Spiderfoot 4.0's full 172-type event taxonomy plus Huntsman's own `HSE_` types, and `-t` and `-F` accept any of them.

### Saved scans

`scans` keeps scans the way Spiderfoot does: `scans run TARGET` routes the target exactly as `scan` does (a domain, IP address, email, phone, username, name, BSSID or `LAT,LON`; `-k` picks the lookup), runs every source of that lookup, and saves everything it found under an id: the lookup's report, every entity with its evidence, every source outcome, the typed Spiderfoot data elements (`IP_ADDRESS`, `CO_HOSTED_SITE`, `TCP_PORT_OPEN`, `VULNERABILITY_CVE_*`, `MALICIOUS_IPADDR`, `EMAILADDR_COMPROMISED`, and the rest of `scans types`) linked to the element they came from, and the correlations with Spiderfoot's HIGH/MEDIUM/LOW/INFO risk. Nothing is redacted or dropped; `-t` keeps only the element types named. An email scan also runs the keyed breach lookup unless `-u passive` is given. `--depth N` makes a scan follow what it finds, as Spiderfoot hands every event to the modules that take it: each email, username, domain, phone, IP address and BSSID a lookup finds (at confidence 0.5 or more) is looked up in turn, N hops past the target, under the same lookup and entity budgets as `scan --recurse`; every email it reaches also gets the breach lookup unless `-u passive`. Each element then names the element of the lookup that found it, so the elements, the graph and the GEXF export form the scan's discovery tree; the scan keeps that lineage and why it stopped (`fixed_point`, `max_depth`, `resource_limit`, `cancelled`), and `scans show` and `/api/scans/ID` include both. Depth 0, the default, runs the target's own lookup only. A stop during a deeper scan ends it before the next lookup and keeps everything found so far.

`scans list`, `show`, `summary`, `elements [-t TYPE] [--unique] [--hide-fp]`, `correlations [-f csv|tsv|xlsx|json] [-o FILE]` and `log [--level ERROR]` read a saved scan; `scans export ID [-f csv|tsv|xlsx|json|gexf] [-o FILE]` writes it in Spiderfoot's export layout (`Updated,Type,Module,Source,F/P,Data`; `xlsx`, or `excel`, is Spiderfoot's Excel workbook with a sheet per data type, every value whole and stored as text, never as a formula; several comma-separated ids give one export with `Scan Name` first, JSON unless `-f` names `csv`, `tsv` or `xlsx`); `scans fp ID ELEMENT[,ELEMENT...] [--unset]` flags false positives as Spiderfoot does: flagging an element flags every element found from it, unsetting one unsets them too, and an element whose source is still flagged cannot be unset on its own; `scans rerun ID` runs a scan again with its target and options; `scans compare EARLIER LATER [-f csv|tsv|xlsx|json] [-o FILE]` shows what the later scan found that the earlier one did not and what it no longer found (Spiderfoot cannot compare scans): each data type with its earlier, later, added, removed and kept counts, every added and removed element in full with its module and source, and the correlations that appeared or went away; matching is by type and value, so a value both scans found is kept whatever its id, and `-f` writes the added and removed elements in the export layout with `Change` and `Scan Name` first; `scans search VALUE [ID...] [-t TYPE] [--hide-fp]` searches every saved scan, or the scans named, as Spiderfoot's search box reads a query (Spiderfoot searches one scan at a time): `/regex/` anywhere, a `*wildcard*` as the whole value, or text anywhere, all regardless of case, in each element's data, its source element's data and its module, printing every hit with its scan; `-t` keeps one type, and an empty VALUE with `-t` lists that type in every scan; `scans delete ID` removes it. Scans live in `$HUNTSMAN_HOME/scans`, else `~/.huntsman/scans` (each row and result file is private to you), or under `--dir DIR`. A scan whose process stopped mid-run reads `ABORTED` the next time the store opens; one another live process is still running is left alone. The same store answers `serve`'s `/api/scans` API (`scan_api`), so the web UI lists, starts and reads these scans too.

Each scan's correlations come from Huntsman's own rules and from Spiderfoot 4.0's 37 correlation rules (`src/correlations/spiderfoot`, Spiderfoot's YAML unchanged, MIT), run by a Rust port of Spiderfoot's engine (`sf_correlate`): collections by type, module or data, refined through each element's `source.`, `child.` and `entity.`; aggregation; the `threshold`, `outlier`, `first_collection_only` and `match_all_to_first_collection` analyses; and the headline. Its regular expressions run in linear time, elements flagged false positive are left out, a Spiderfoot module name in a rule also matches the Huntsman source that does that module's work (`sfp_crt` matches `crtsh`), and `publish_collections` is honoured. Your own Spiderfoot-format rules go in `$HUNTSMAN_HOME/correlations`, else `~/.huntsman/correlations`, or `--rules DIR`: a `*.yaml` file there with a shipped rule's id replaces it, and one holding only `enabled: false` turns it off. `scans rules [--json]` lists every rule and exits 65 naming any file it could not read (a scan logs the same as a warning); `scans correlate ID` runs every rule again over a saved scan, as Spiderfoot's `sf.py -C` does, after you flag false positives or add a rule. `scans correlations ID -f csv` exports Spiderfoot's correlation columns (Rule Name, Correlation, Risk, Description) plus the rule id, where it came from and the elements each is about.


### Embedded Web UI and HTTP API

`huntsman-recon serve` starts a dependency-free embedded UI on `127.0.0.1:8080` by default. `HSE_BIND` or `serve --bind ADDR` selects another socket address. Explicit non-loopback binds require a non-empty `HSE_AUTH_TOKEN`.

A loopback bind (the default, and the phone's service) needs no token and ignores `HSE_AUTH_TOKEN`, saying so on stderr; the `Host` guard and the lookup header keep other websites out. On a public bind every endpoint except the page, its icons and `/api/health` needs `HSE_AUTH_TOKEN` as `Authorization: Bearer TOKEN`; a call without it is answered `401` with `WWW-Authenticate: Bearer` and an error that names the variable. `serve` says so on stderr when it starts, without printing the value. `/api/health` reports `"auth": "token"` or `"auth": "none"`, and the page uses it: only when a token is needed does it show the token field under Status and ask for it. It then sends the token on every call, keeps it in the browser's local storage for this address, and also takes it once from the address as `http://HOST/#token=VALUE` (a fragment never reaches the server or its logs), then removes it from the address bar. On a loopback server the page shows no token field and forgets a token an earlier page stored.

The API surface:

- `GET /api/health` — process name/version and status, whether a token is needed (`auth`), and `page`, the id of the page this build serves; a console tab whose own page id differs was loaded from an earlier build and asks to be reloaded;
- `GET /api/modules` — the same truthful reachable-module catalogue as `modules --json`;
- `GET /api/command` — the same validated engineering command contract as `command --json`;
- `GET /api/lookup?kind=auto|people|email|exposure|username|phone|domain|network&q=SELECTOR` — one lookup through the same routing and front-ends as `scan`, returning `{route, text, entities, outcomes}` as JSON. `auto` infers the kind exactly as `scan` does; `exposure` is never inferred because it spends operator keys, and an SSID is never inferred because it is free text (a BSSID or `LAT,LON` routes to `network`). An `email` or `username` lookup runs every exposure leg whose key is configured, so a paid source is never skipped. Its own sources, `SeekNow` and the exposure legs run at the same time, as do the four exposure legs, so a lookup takes as long as its slowest source rather than all of them in turn. When `serve` keeps saved scans (in `$HUNTSMAN_HOME/scans`, else `~/.huntsman/scans`), each lookup runs as a saved scan of its selector, with the target's lookup only, as a depth-0 scan: it is listed under Scans with everything it found and its log, it can be stopped there, and it reads `ABORTED` if `serve` stops in the middle of it. The report then also carries `scan`, the scan's id, which `/api/scans/ID` reads, and `status`, `FINISHED`, or `ABORTED` when it was stopped, with what it had found by then. A request waits at most 150 seconds for its lookup; one still running then is answered `504` with its `scan`, and it goes on and keeps what it finds; the same lookup asked again while it runs waits on that scan instead of starting another. Errors are JSON `{"error": …}`, with `scan` once a scan is kept: 400 bad selector, 422 unusable selector (without saved scans; with them it is 502), 502 every source failed or the lookup saved nothing (with the reason its log gives), 503 lookup capacity in use (without saved scans), 504 still running;
- `GET /api/analyze?seeds=SEEDS` — the offline multi-hop analysis of up to 16 seeds, one per line (the same spine `plan` runs), returning `{accepted, rejected, entities, relations, pivots, correlations, gaps, planned, termination, truncated}` as JSON: the links derived between the seeds, the next pivots ranked by how much of the graph each holds together, the correlations over those links, the seeds left unlinked with what would expand them, and the sources the planner would query next. Errors are JSON `{"error": …}`: 400 for no seeds, more than 16, or one over 512 bytes;
- `/api/scans…`, `/api/eventtypes`, `/api/settings` — Spiderfoot's scan API over the saved scans in `~/.huntsman/scans` (`$HUNTSMAN_HOME/scans`), the ones `scans` reads: `GET /api/scans` lists them; `POST /api/scans?target=T[&name=N][&kind=K][&usecase=U][&types=A,B]` starts one and answers `202` with its id; `GET /api/scans/ID` is its status, options, report and source outcomes, and `/summary`, `/elements[?type=T][&unique=1][&hidefp=1]`, `/correlations`, `/log`, `/graph` and `/export?format=csv|tsv|xlsx|json|gexf[&type=T]` its results; `/correlations?format=csv|tsv|xlsx|json` exports its correlations; `POST /api/scans/ID/stop|rerun|delete`, `POST /api/scans/ID/fp?ids=A,B&fp=1|0` and `POST /api/scans/ID/correlate` (every rule again, as `sf.py -C` does) change it; `GET /api/scans/export?ids=A,B[&format=json|csv|tsv|xlsx]` exports several together; `GET /api/scans/compare?ids=EARLIER,LATER[&format=json|csv|tsv|xlsx]` compares two (each type's counts, the added and removed elements in full, the correlations that appeared or went away); `GET /api/scans/search?value=V[&type=T][&ids=A,B][&hidefp=1]` is Spiderfoot's search over every saved scan or the ones named, each hit as `/elements` gives it with `scan_id`, `scan_name` and `scan_target` (a regex runs on the linear-time matcher the correlation rules use, so no pattern stalls the server); `GET /api/eventtypes` is the data-type catalogue, `GET /api/correlationrules` every correlation rule a scan runs (Huntsman's, Spiderfoot's and those in `~/.huntsman/correlations`, with each rule as written), and `GET /api/settings` the modules with whether each one's key is set (never its value) and the server's settings. They carry the lookup's guards (the `X-Huntsman-Lookup: 1` header, no cross-site or same-site request, the token on a public bind), take their parameters in the query string and refuse a body, and each runs on its own 4 MiB-stack worker. A scan runs in the background, so the page can be closed while it does; a scan that `serve` was stopped in the middle of reads `ABORTED` when it starts again. Errors are JSON `{"error": …}`: 400, 404, 405, 409 (stopping a scan that is not running, deleting one that is, flagging false positives before it finishes, or unsetting one whose source element is still flagged) or 500;
- `GET /` — the HSE console page (`src/web_ui.html`, embedded at build time), laid out as Spiderfoot 4.0's web UI: an app bar with the server's state, a dark/light switch and About (health, modules and the command contract); **Scans** (the saved scans with name, target, started, finished, status, element count and high/medium/low/info correlation counts, a status filter, and stop, re-run, delete and export for one or several at once, the selected scans together as CSV, Excel, JSON or TSV, and Compare for two, and a search of every saved scan whose hits each name their scan and open its Browse); **New Scan** (a name, a target whose type is detected or chosen, how many hops to follow what the scan finds, and Spiderfoot's three ways of choosing what runs: by use case, by required data type or by module); one scan under `#/scan/ID` with Spiderfoot's sections, Summary (total, unique, status and error counters, correlation counters, a bar per data type, every source's outcome), Correlations (each with its risk, its rule and where the rule came from, the rule as written, and its elements; re-run over the saved elements after marking false positives, and export as CSV, Excel, JSON or TSV), Browse (data types, then a type's elements in full or unique view with every element's complete raw record and, for a value that is itself a target (a host, domain, IP address, email, phone, username, name or BSSID), New Scan of it with the scan's use case and depth, or as Spiderfoot's discovery path back to the target, with false-positive marking and hiding, and a filter), Graph (the elements and the elements they came from, random or force layout, tap an element to see it, drag one to move it, pan, pinch and wheel zoom, save as SVG; the layout works a few milliseconds a frame and stops when the page leaves the Graph, so a scan of thousands of elements keeps the page answering on a phone), Scan Settings (the scan's options, its depth and why it stopped following what it found, and its discovery tree: each lookup by hop with every entity it found) and Log (with an errors-only filter and CSV download), a search over the whole scan or the type being browsed that reads Spiderfoot's `/regex/` and `*wildcard*` forms, CSV, Excel, JSON, GEXF and TSV export, Spiderfoot's Clone, which fills New Scan from the scan to change before it runs, and Compare, which Spiderfoot lacks, setting the scan beside the latest earlier scan of its target under `#/compare/EARLIER/LATER`: each type's earlier, later, added, removed and kept counts, the correlations that appeared or went away, and every added and removed element in full, with swap and CSV, Excel, JSON or TSV export; **Analyze** (the offline analysis form and its entities, links, next pivots, correlations, gaps, planned sources and rejected seeds); and **Settings** (every module with its category, access, description and whether its key is set, never the value, and every correlation rule with its risk, origin and logic). A running scan's view refreshes after 1, 2 and 4 seconds, then every five, while the tab is visible and stops when it ends; a reload returns to the same section of the same saved scan. On a phone the tabs are a bottom tab bar and each table row becomes a labelled card; from 768 px they are a top nav. `GET /favicon.svg` is its icon.

`/api/lookup` makes network requests on the operator's behalf, so it is guarded beyond the loopback `Host` check: it needs the `X-Huntsman-Lookup: 1` header (another origin cannot send it without a CORS preflight, which this server never approves), it refuses requests the browser marks `Sec-Fetch-Site` cross-site or same-site, and on a public bind it needs the bearer token. At most two lookups run at once, each on its own 4 MiB-stack worker: with saved scans a third waits its turn behind the scans already running, as a scan started from New Scan does; without them it is answered `503`. Provider text is written into the page as text, never as markup.

`/api/analyze` makes no network request and spends no key: the spine is handed no transport and only plans the sources it would query. It needs no lookup header, but it is refused cross-site or same-site like a lookup and, on a public bind, needs the bearer token. Each analysis runs on its own 4 MiB-stack worker, because it does more than the 256 KiB connection stack holds. Correlations over seeds you entered describe the links derived from them; each stays a hypothesis until a source corroborates it, and every link that rests on a single path also carries an AU-063 corroboration gap. A handle that several seeds share, such as one local part at several domains, is one pathway for all of them: it never corroborates itself (AU-062), and the links only it makes share one gap. The page shows each correlation's finding beside its rule.

Every response carries `X-Frame-Options: DENY` and a `Content-Security-Policy` that loads nothing from elsewhere and forbids framing, so a site open in the same browser cannot lay the page under its own and turn taps into lookups. The page's policy admits only its own inline script and inline style, by SHA-256, and lets it request only this server.

The listener bounds the request line and headers to 33 KiB, enough for the largest analysis it admits (16 seeds of 512 bytes, percent-encoded) with 8 KiB for a browser's headers and a token, applies finite read/write timeouts, supports `GET` and `HEAD`, and `POST` for the scan API's changes, and closes each connection after one response. Each connection has its own thread, at most 32 at a time, so a connection that sends nothing (as a browser's speculative ones do) holds up only itself. A further connection first closes the connection that has waited longest without sending a whole request, once it has waited a second; when none has, it is answered `503` with `Retry-After: 1`. Connections that send nothing, which any app on the phone can open to a loopback port, therefore cannot keep requests out.

On Termux (Android, aarch64, no root) the default bind `127.0.0.1:8080` needs no root and no port below 1024: run `huntsman-recon serve` and open `http://127.0.0.1:8080/` in the phone's browser. If another server already holds 8080, pass `--bind 127.0.0.1:0` and use the address on the `serving=` line; [Keep serve running on Android](docs/INSTALL.md#keep-serve-running-on-android) covers that and keeping the server alive in the background. Keys come from the same environment and `~/.huntsman.env` chain as the CLI, so export them in the Termux session before `serve`. The legacy monolith's other endpoints are not rebuilt.


### Batch scan input

`scan --input-file FILE [-k people|email|exposure|username|phone|domain|ip] [--save-dir DIR]` accepts UTF-8 files up to 1 MiB with one target per line. Blank lines and lines whose trimmed form starts with `#` are ignored; exact duplicate seeds keep only their first occurrence. A batch is capped at 1000 unique seeds, every accepted seed is attempted even after an earlier failure, and the process exits non-zero after completion if any seed failed. Batch `--save` is refused; `--save-dir DIR` writes one ledger per seed instead, named by the seed's position and the seed reduced to safe filename characters (`0001-<seed>.json`), so no seed can overwrite another seed's ledger.


### Domain lifecycle analysis

`domain-lifecycle analyze INPUT.json --as-of UNIX_SECONDS [--output REPORT.json]` compares imported domain observations entirely offline. It preserves source/upstream boundaries, rejects conflicting duplicate identifiers, records failed/truncated observations as coverage gaps, and emits only conservative observed changes. Ownership, causality, and registration availability remain explicitly unknown unless established elsewhere. See [docs/DOMAIN_LIFECYCLE.md](docs/DOMAIN_LIFECYCLE.md).
