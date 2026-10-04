# huntsman

One crate, `huntsman-recon`. The current version lives in `src/`; the two legacy zip archives in the repository root and their extracted copies in `legacy/` are permanent read-only reference (see below).
Target design, module map and per-capability status against legacy `7dca720`: [`ARCHITECTURE.md`](ARCHITECTURE.md).

| Path | Contents |
| --- | --- |
| `src/` | The crate: library modules plus the `huntsman-recon` binary (`main.rs`). |
| `tests/` | Acceptance, CLI, local-HTTP and legacy-reference integration tests; `hibp_build.rs` (build-time key embedding rules); `android_ci.rs` (the CI workflow keeps the aarch64 Android cross-build and its artifact); plus `readme.rs` and `dispositions.rs`, which check this README and `docs/DISPOSITIONS.md` against the binary and `legacy/`. |
| `var/` | Artifacts written by `check` (`ledger.json`, `navigator.json`, `stix-bundle.json`). CI fails if `check` changes them. |
| `docs/` | `RECONSTRUCTION_2026-10-02.md` (decisions and falsification passes) and `DISPOSITIONS.md` (per-file accounting of every legacy file). |
| `.github/` | `workflows/ci.yml` (tests on Rust 1.87 and stable; aarch64 Android cross-build), `workflows/release.yml` (`main-<sha7>` pre-releases of `huntsman-recon`), `scripts/` (`scan-for-keys.sh`, `install-termux.sh`) and `actions/setup-ndk-aarch64` (NDK compiler and linker environment). |
| `CHANGELOG.md` | Notable changes, Keep a Changelog format. |
| `legacy/` | Byte-identical extraction of both archives. Not part of the build. |
| `*.zip` (root) | The two legacy archives. Pinned by hash in `tests/legacy_reference.rs`; never delete, edit or move them. |

## Which binary to use

| | `hse` (legacy v1.41.0 monolith) | `huntsman-recon` (this tree, in progress) |
| --- | --- | --- |
| Person lookups | Yes. Provider modules such as `asic_persons`, `asic_director`, `username_search`, `phone_au` and `bluesky_user` (195 `pub mod` entries in `src/modules/mod.rs` at `7dca720b`), plus `hse scan`, `hse investigate` and `hse serve`. Whether each provider works live has not been re-verified. | **No.** No command accepts a person selector or calls a provider. `search` reads only local documents, and the HIBP client is a library API that no command calls. |
| Source | Commit `7dca720b`. The closest copy in this tree is `legacy/hse-monolith-v1.41.0/`, which is read-only and not built; it is not byte-identical to `7dca720b`. | `src/` |
| Where to get it | GitHub pre-release `main-7dca720` (asset `hse-aarch64-linux-android`, built from `7dca720b`) | A GitHub pre-release `main-<sha7>` (asset `huntsman-recon-aarch64-linux-android`), the CI artifact of the same name from a `main` push (see "Downloads"), or a source build |

Use `hse` if you need person lookups today. `huntsman-recon` is its in-progress replacement. Since #672, every push to `main` publishes it as a `main-<sha7>` pre-release. There is no rolling `latest` pre-release: the workflow creates or moves `latest` only when the repository variable `PROMOTE_RECON_TO_LATEST` is `true`, and it is unset. GitHub's "Latest release" is the stable legacy `hse` release `v1.41.0`.

Local search, recorder and ledger, with a guarded fetch layer (egress policy, credential-origin rules, `fetch` and `keys` commands; `check` exercises egress, origin, placeholder and URL-redaction rules as gate 11, without a socket). A challenge page is not a hit. No paid source is called automatically; HIBP is an explicit opt-in library client. The ledger is a hash chain. A full terminate must name the tip. A verified claim is not an ATT&CK score.

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

Exit codes: 64 usage, 65 bad data or broken ledger, 66 unreadable input or failed credential setup (unconfigured slot or unreadable keys file or a bad URL when `--bearer`/`--header` is given), 69 `fetch` got no response, 74 artifact write failure, 77 `fetch` refused the request (egress policy or malformed URL or redirect target; without a credential option a malformed URL lands here). `check` uses 2–11 for its individual gates. Running the binary with no command runs `check`; `help`, `-h` and `--help` print the usage line.

`tests/readme.rs` runs every example above (except the internet `fetch`), checks that the examples and the CLI usage name the same commands, produces each documented exit code, and matches the gate range to `src/main.rs`.

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

The refactor-overlay foundations from the uploaded zip are library modules: `source_outcome` (causal fetch outcome), `evidence_ancestry` (mirrors of one dump count once), `identity_resolution` (non-compensatory merge gate over ancestry), `termination` (fixed point vs bounds), `credential_origin` (found credentials are evidence, never authority), and `eval` (deterministic scoring, bootstrap, promote/hold verdict). `check` gate 5 exercises four of them: `source_outcome` (a 403 Cloudflare challenge page is `BotWaf`, and its recommended action is not `RequireCredential`); `evidence_ancestry` with `identity_resolution` (two mirrors of one dump cannot auto-merge two identities, while a mirror plus an independent registry root can); and `termination` (delayed retry work is not a fixed point). Gate 5 does not exercise `credential_origin` or `eval`. The binary uses `credential_origin` in `fetch` (the operator-approved credential authority) and for the fingerprints that `fetch` and `keys` print. `eval` is not used by the binary at all; only its unit tests exercise it.

Rebuilt monolith utilities: `au_id` (ABN, ACN, BSB), `geohash`, `confidence` (corroboration, ancestry-aware), `redact` (coordinate coarsening, secret scrubbing). `check` exercises them as gate 10.

See `docs/RECONSTRUCTION_2026-10-02.md`.

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
