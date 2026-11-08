# Consolidation and refactor plan

Status: **IN PLACE** through Phase 5. Phase 6 moves with Stage 9, as **Progress** below records.
**Section 10 is the open REFACTOR and CONSOLIDATE list**, measured on `main` at `094504310`
(2026-11-06). Its items C1, C2, C5 to C8, C10 and R3 are in place; each is marked there. Sections 1 to 9 keep the figures the phases were planned against, measured on `main`
at `e7301b4c6` (2026-11-05); section 3 sets the two side by side. Unless marked *estimate*, every
number here was measured.

**Progress.** Phase 0 is in place:

- `tests/fixtures/source_classification.tsv` holds the classification snapshot, checked in `src/orthogonal_osint/tests.rs`.
- `tests/fixtures/saved_attribution.tsv` holds the attribution snapshot, checked in `tests/saved_attribution.rs`.
- The refusal-contract harness in `src/lookup_modules/tests.rs` covers every lookup but `phone`, whose run type has no refusal to end in. It lists today's 17 breakages as reviewed entries.
- `tests/test_count_floor.rs` holds the test-count floor.

- Phase 2 is in place. `src/source_profile.rs` is the one classification table, and `tests/source_profile.rs` holds G1. G3 is `every_key_slot_has_a_provider_row` in `src/scan_api.rs`.
- Phase 1 is in place for its moves. The inline tests of the six files above now live in `<module>/tests.rs`: 8,926 lines, with every unit test name unchanged (3,223 before and after). `oathnet::non_blank` became `textnorm::nonblank`. A survey of the local transport fakes found them mostly bespoke (scripts, recorders, maps, panicking fakes); only `oathnet`'s blocking fake duplicates a shared double. G4 is therefore not adopted: its allow-list would hold most of the fakes.
- Phase 3 is in place: B1 to B4. The refusal-contract harness holds every lookup but `phone` with no exceptions, and G2 is `a_saved_lookup_credits_each_record_to_the_file_that_made_it`.

- Phase 5 is in place where the endings are identical. One `lookup_report::LookupReport` replaces fourteen identical `Report` structs, each now an alias. Six front-ends end through `lookup_report::finish`. Since B3, every lookup ends through `SourceReach`, which `REFUSAL_ROUTED` in `architecture_boundaries` enforces (G6). The other front-ends keep their own endings, because each does more than this one.

- Phase 4 is in place for the eight legs whose path was identical. They are Lobsters, Chess.com, Lichess, Codeberg, DEV, Codewars, Hugging Face and Hacker News, and they now run on `src/account_leg.rs`. First, `tests/fixtures/account_leg_snapshot.tsv` recorded each leg's outcome and entities in eleven scenarios. All 88 rows are unchanged after the move. The legs that differ in rule, not just wording, stay bespoke, as section 4.3 lists. Those are GitHub, GitLab, Bluesky, Keybase, Mastodon, Docker Hub, crates.io, npm, TikTok and Wikipedia.

- Phase 6 is deferred into Stage 9 of the stage plan.
  - **Phase 1 already cut the files down.** It moved their inline tests out, and `scan_service`, `scan_api` and `graph_exec` now hold 2,018, 1,519 and 1,697 production lines.
  - **Splitting now means moving the same code twice:** into submodules now, then into their `application` and `web` homes when Stages 3 to 9 move them.
  - **It would not be a pure move.** Splitting `impl ScanService` across child modules turns its private helpers `pub(super)`.
  - The split happens with the Stage 9 move instead.

- **Consolidation since the phases.** Each of these landed with its snapshot or differential unchanged, apart from the lines it declared:
  - `09fb628c4`: one Network Survey envelope reader, `rf::survey_csv::read_export`, for the Bluetooth, Wi-Fi, LTE and NR importers. An NR export with malformed CSV is no longer worded under the LTE label.
  - #1773 (`364949fca`): one embedded-metadata reader, `embedded_metadata::inspect`, serves the web inspect view, `investigate --file` and `reverse-image`. `metadata_identifiers` is the one rule that turns metadata values into entities.
  - #1774 (`0913febab`): duplicated coordinate, OID, calendar, bounded-text, subdomain and hex checks each go through one existing helper, across 27 files. It also stopped a crafted APK certificate time from panicking the signer reader. The 98-command CLI snapshot stayed byte-identical.
  - #1775 (`1184b70ae`): one set of Network Survey field readers in `src/rf/survey_csv.rs` serves the four importers. 4,140 edited copies of accepted rows read byte-identically before and after.
  - #1776 (`358c84cc0`): each metadata reader yields at most 256 identifier entities per file and counts the rest.

- **Section 10, first batch.** Eight items are in place, one commit each. Each declared change carries a test that failed before it:
  - C1 (`277542315`): one type per report shape.
  - R3 (`89d4870bf`): `au_id` uses `is_multiple_of`.
  - C6 (`a5963b1ca`): one reported-fix reader for the four Network Survey importers (B7).
  - C5 (`f38a2db07`): one cross-process write lock, for the keys file and the track log (B8).
  - C7 (`d5ac78bd0`): one bounded free-text query rule.
  - C8 (`d864513d0`): one archived-page read summary.
  - C10 (`cff12bff0`): the auth-failure phrases moved to `source_outcome`.
  - C2 (`28149b5a7`): one URL-host reader (B5).
  - **Measured on the branch head after the batch:**
    - duplicated 10-line windows: 143, against 178 on `main` at `094504310`;
    - files declaring `pub struct Report`: 12, against 46;
    - files with a local `fn miss(`: 2, against 21.
  - **New guards.** G7 and G8 are in `tests/architecture_boundaries.rs`, and G7 found five more copies under other names.

**Measured outcome.**
- **Classification.** One table classifies every source, and G1 fails a build that adds an unclassified source. B1 and B2 fixed three wrongly classed sources.
- **Refusals.** Every lookup but `phone` names the source it was refused by or got no answer from (B3); the harness holds all 15 of those lookups (11 scan kinds plus company, gleif, itunes and wikidata) with no exceptions.
- **Attribution.** G2 found and fixed one live misattribution (B4), and fails a source added to a lookup without one.
- **Code size:**
  - Phase 1 moved 8,926 test lines out of production files.
  - Phase 5 removed 78 net lines across 20 files.
  - Phase 4 removed 139 net production lines across the eight legs and the kernel.
- **Duplication.** Cross-file duplicated 10-line windows in production code fell from 244 to 178 between `e7301b4c6` and `094504310`; section 3 gives the rule. Files declaring `pub struct Report` fell from 65 to 46, and files with a local `fn miss(` from 27 to 21.
- **Unchanged output.** Each refactor left the snapshots and contract unchanged, and the test count only rose.

- **Process.** Work under this plan follows [CLAUDE_CODE_REFACTOR_EXECUTION.md](CLAUDE_CODE_REFACTOR_EXECUTION.md).
- **Authority.** The root [`ARCHITECTURE.md`](../ARCHITECTURE.md) and its tests stay authoritative for the module map.

## 1. Scope

This plan removes duplicated logic and duplicated authority. It complements the stage plan in
[ARCHITECTURE.md](ARCHITECTURE.md):

- **The stage plan** decides *where* a module lives.
- **This plan** decides *how many copies* of a rule exist.

**Ordering:**

- Phases 1 to 5 land before Stage 7, which moves the collectors. They shrink and standardise the collector files that Stage 7 moves.
- Phase 5 here delivers the part of Stage 9 that lifts shared logic out of the CLI adapters.
- Section 10's items land before the Stage 7 and Stage 9 moves of the files they touch, so each rule moves once, as one copy.

**Out of scope:**

- **The sibling repositories** (`Huntsman-`, `huntsman-bse-radar`, `huntsman-rcvf`, `HSE-BLE-API-`). They were not analysed: the session that wrote this plan was not given access to them.
- **The SeekNow worker.** It is not reachable from the analysing environment. Only the in-repo collector and [SEEKNOW_CONTRACT.md](SEEKNOW_CONTRACT.md) are covered.
- **Handset acceptance on Termux.** CI covers aarch64 builds and emulation. Device runs stay with the operator.

## 2. Non-regression contract

A change made under this plan is accepted only when all five conditions hold.

1. **Interfaces are frozen.** None of the following may change:
   - CLI grammar, stdout, stderr and exit codes;
   - HTTP routes and response JSON, including the module list that serialises `ReachableModule`;
   - Web UI behaviour;
   - saved-scan and saved-lookup JSON. This covers `provenance.source`, the stored `provenance.source_family` and the saved component paths;
   - evidence attribute names;
   - outcome kinds and reasons.
2. **Results never shrink.** The differential comparator in `src/differential.rs` must pass. A rebuilt command may add results, but it may not lose or re-attribute one. Before a phase changes how a lookup collects, the comparator is extended from `phone` to that lookup.
3. **Tests never shrink.**
   - The `#[test]` count never drops.
   - A pure move keeps every `cargo test -- --list` name.
   - A test is never edited in the commit that changes the production code it guards. Pure path moves are the only exception.
4. **Gates pass.**
   - Local gates:
     - `cargo fmt --all -- --check`
     - `cargo clippy --locked --workspace --all-targets -- -D warnings`
     - `cargo test --locked --workspace`
     - `cargo run --locked -p xtask -- changelog check`
     - `cargo run --locked -p xtask -- gate full`
   - Full CI:
     - Rust 1.87 (the MSRV) and pinned stable;
     - aarch64 and Android;
     - phone browser and container;
     - CodeQL and audit.
   - Because the MSRV is 1.87, new code may not use let-chains.
5. **Behaviour changes are declared.**
   - Only the changes listed in section 6 may alter output.
   - Each one is its own pull request.
   - Each one carries a regression test that fails before the change, and a `fixed` changelog fragment.

## 3. Measured baseline

| Measure | `e7301b4c6` (planned against) | `094504310` (now) |
|---|---|---|
| Production Rust (`src/`) | 233,185 lines in 418 files; 298 `mod` lines in `src/lib.rs` | 244,296 lines in 446 files; 312 `mod` lines |
| Integration tests (`tests/`) | 39,647 lines in 160 files | 41,596 lines in 168 files |
| `#[test]` functions | 3,289 in `src/`, 954 in `tests/` | 3,474 in `src/`, 1,001 in `tests/` |
| Registry rows (`module::reachable_modules()`) | 139 | 143 |
| Collector source-ID constants (`pub const SRC` / `SOURCE`) | 86 | 89 |
| `impl Transport for` blocks | 116 in total, broken down below | 121 |
| Files defining `pub struct Report` / `fn miss(` | 65 / 27 | 46 / 21 |
| CLI adapters (`src/*_cli.rs`) | 19, of which 15 return a `SourceRun` | the same |
| Account legs behind `username` | 19 files, 6,415 lines before their test modules | 19 files, 6,070 lines, and the 210-line kernel |
| Cross-file duplicated 10-line windows in production code | 244 | 178 |

**How the second column was counted.**
- Lines: every `*.rs` file under the directory, counted whole.
- Production lines of a file: the lines before its first `#[cfg(test)]`.
- `#[test]` functions: lines holding `#[test]`.
- Registry rows: `ReachableModule {` entries in `REACHABLE_MODULES`.
- Source-ID constants: lines starting `pub const SRC:` or `pub const SOURCE:`.
- Transport blocks: `impl … Transport for` lines, whatever path precedes `Transport`.
- Duplicated windows:
  - The text scanned is the production lines of every `src/` file except `tests.rs` files, each line trimmed, with blank and `//` lines dropped.
  - A window is 10 consecutive kept lines.
  - A window counts once when its text appears in at least two files.
- The same rules give 87 constants, 955 `tests/` functions, 117 transport blocks and 6,427 account-leg lines at `e7301b4c6`. The first column keeps the figures as first published.

The `impl Transport for` blocks break down as follows:

| Where | `e7301b4c6` | `094504310` |
|---|---|---|
| Production code | 2 | 3: `http::UreqTransport`, and the adapters `module_selection::Selected` and `indicator_sources::DynTransport` |
| Shared doubles in `src/test_support.rs` | 8 | 8 |
| Local fakes in `src/` files | 70 in 48 files | 73 in 49 files |
| Local fakes in `tests/` files | 37 in 32 files | 37 in 32 files |

Oversized production files and their inline tests, counted from the `#[cfg(test)]` line to the end of the file:

| File | Lines | Inline tests | Share | Planned home | Production lines now | `<module>/tests.rs` now |
|---|---|---|---|---|---|---|
| `src/scan_service.rs` | 4,278 | 2,262 | 52% | application | 2,019 | 2,284 |
| `src/scan_api.rs` | 3,273 | 1,756 | 53% | web | 1,521 | 1,962 |
| `src/graph_exec.rs` | 3,110 | 1,415 | 45% | application | 1,695 | 1,435 |
| `src/exposure_cli.rs` | 3,088 | 1,904 | 61% | cli | 1,184 | 1,913 |
| `src/fetch.rs` | 2,214 | 1,265 | 57% | infrastructure | 949 | 1,256 |
| `src/module.rs` | 1,988 | 317 | 15% | analysis | 1,709 | 314 |
| **Total** | | **8,919** | | | | |

## 4. Findings

### 4.1 Defects

**F1. Four classifiers answer one question, and nothing keeps them in step.** Each classifier below
says what kind of source a record came from.

| Classifier | Where | Keyed by | Values | Consumers |
|---|---|---|---|---|
| `ModuleCategory` | each registry row in `src/module.rs` | row name | 14 variants | ATT&CK mapping (`src/attack.rs:98`); GEOINT ROI (`src/roi.rs:137`) |
| `correlator::source_family` | `src/correlator/rules.rs:30` | provenance source ID: 93 exact IDs, then substring tests | 11 strings | `multi_breach` (AU-001); `api_key_exposure` (AU-021); `tagged_matching_sources`; `is_breach_source` |
| `acquisition_modality` | `src/orthogonal_osint.rs:162` | 41 exact IDs (module names and source IDs mixed), then `source_family` | 10 strings | orthogonal-coverage opportunities |
| `canonical_family` | `src/evidence_ancestry.rs:152` | any origin name | the name with its spelling canonicalised | independence counting; persisted as `EvidenceProvenance.source_family` (`src/entity.rs:137`) |

The last row is not a taxonomy; it only shares the word "family". Two unrelated meanings under one
name is a hazard in itself.

These results come from running the classifiers over the 86 collector source IDs.

- **34 source IDs classify as `other` in the correlator.** They never count as a family in AU-021 or in `tagged_matching_sources`.
  - The modality map classifies 19 of them explicitly.
  - Part of that gap is deliberate. `tests/orthogonal_osint.rs:254` pins `wikidata` to `other` so corroboration stays strict.
- **Two correlator arms are typos, so their collectors land in `other`:**
  - `acnc_charities`: the collector writes `acnc` (`src/acnc.rs:37`).
  - `exa_search`: the collector writes `exa` (`src/exa.rs:16`).
- **Three IDs are classified only by substring:**
  - `github_repos` becomes `code`;
  - `ipinfo_lite` becomes `infra`;
  - `wikipedia` becomes `infra`, because "wikipedia" contains "ip".
- **Many exact IDs appear nowhere else in `src/`:** 32 of the correlator's 93, and 4 of the modality map's 41 (`atproto`, `bgpview`, `rdap_legs`, `xposedornot`).
  - A few are documented legacy IDs, such as `see_know`, which `tests/fixtures/legacy_7dca720_breach_consensus.json` uses.
  - The rest name providers that were removed or never added.
  - Saved scans from older builds can still hold them, so they are **legacy aliases, not dead code**.
- **Only one test ties two classifiers together.** Every `ModuleCategory::Breach` row must classify as `breach` (`src/correlator.rs:840`).
  - Nothing checks that a new collector is classified at all.
  - An unclassified collector falls through to the substring tests without any error.

**F2. Saved lookups attribute unknown sources to the CLI file.** `src/lookup_save.rs` maps each
source ID to the Rust file that produced it. Its own comment says the component is "the Rust
collector that made it, not the shared lookup front-end".

- Five production maps end in a fallback that names the CLI adapter instead, at lines 43, 73, 114, 334 and 350.
- A collector added without a row is saved, permanently, as produced by the CLI file.
- The people map also matches string literals, not the collectors' constants. A renamed `SRC` is therefore not caught at compile time.

**F3. The key-slot list is kept by hand.** `scan_api::key_slots` builds its keyed sources from:

- `indicator_legs::SOURCES`;
- a hand-written `[&Api; 7]` array;
- extra rows.

A keyed leg left out of it is caught: a `scan_api` test reads every keyed `API` constant from the
source text and requires its slots on the Settings page. No test, though, checks that each slot it
lists has a `provider_credentials::PROVIDERS` row, which is where the operator learns how to get
the key.

**F4. Three mechanisms decide "no source answered", and seven lookups end it without naming the
module.** The 15 CLIs that return a `SourceRun` finish in different ways.

| Mechanism | CLIs | When every source failed |
|---|---|---|
| `SourceReach::unanswered` | asn, domain, email, ip, netblock, username | refusal: exit 77; otherwise exit 69 with the transport reason, else the first configured reason |
| `SourceReach::stopped` | exposure, network | refusal: exit 77; no response: exit 69; answered with errors: prints |
| `source_outcome::none_accepted` | company, crypto, gleif, itunes, wikidata | exit 69 with the first configured reason, including for a refusal recorded as a row |
| hand-rolled `is_accepted` check | nominatim, people | `nominatim`: exit 69 with no reason; `people`: its own refusal (77) and failure (69) messages |

The refusal-contract harness in `src/lookup_modules/tests.rs` drives each module, chosen alone, over
a refusing, a silent and a failing network. Measured with it:

- **The eight `SourceReach` lookups keep the contract.** A refusal exits 77 naming the refused module, and no response exits 69 naming it.
- **The other seven name no module on a refusal.** People, crypto, place, company, gleif, itunes and wikidata also exit 77 on a refusal, because their legs' guarded fetch returns an error that ends the lookup at once. The message is the bare egress reason, so the operator cannot tell which source was refused.
- **People and place also end an unanswered lookup without the module or its reason.**
- **`none_accepted` turns a refusal recorded as a row into exit 69.** Only `api_leg` legs record a refusal as a row. From the command line `company` runs its registers first, which end the lookup as a refusal, so this path is reached today only by choosing ABN Lookup alone.

### 4.2 Duplication

**D1. Registering a source touches many places.**

- A keyless username source (`codewars_user`) appears on 15 lines in 10 files:
  - `src/lib.rs` and the registry row in `src/module.rs`, plus that file's test list;
  - `src/username_cli.rs`;
  - `src/lookup_modules.rs`;
  - the attribution map in `src/lookup_save.rs`, plus its test copy;
  - both classifiers (`src/correlator/rules.rs` and `src/orthogonal_osint.rs`);
  - the dispositions TSV and `ARCHITECTURE.md`.
- A keyed source (`abn_lookup`) appears on 47 lines in 20 files.
- The username sources are listed twice: the `public_sources` array in `src/username_cli.rs`, and the `ScanKind::Username` list in `src/lookup_modules.rs`. The refusal-contract harness holds the two to the same set.
- **Measured again after the phases.** One offline numbering-plan reading, `phone_ae` (#1780), named its source in 12 files, and bumped the entry count in `tests/closed_output.rs`:
  - `src/phone_intl.rs` and `src/phone_cli.rs`;
  - `src/entity.rs`, `src/lookup_modules.rs` and `src/lookup_save.rs`;
  - `src/module.rs` and its tests, and `src/source_profile.rs`;
  - `tests/cli.rs`, `tests/source_label_homes.rs` and two snapshot fixtures.

  A test now names whatever is missing from each of those places. C11 removes the hand lists among them.

**D2. Account-leg boilerplate.** The 19 account legs each repeat the same steps:

- fetch;
- the 404-is-a-clean-miss guard;
- the identity check;
- assembling the `Report`.

Folding that into one kernel removes about 650 to 750 lines (*estimate*). It also removes 11
near-identical interpret blocks.

**D3. CLI tails.** Each `SourceRun` CLI repeats the same finish sequence: merge by UID, the no-answer
decision, and rendering. That is about 280 lines (*estimate*).

**D4. Transport fakes.**

- **In-crate fakes.** 70 local fakes in 48 `src/` files sit beside eight shared doubles in `src/test_support.rs` that they could already use. Those doubles are `ScriptedTransport`, `RoutedTransport`, `Refusing`, `Silent`, `Failing`, `Recording`, `CannedRecorder` and `OneResponse`.
- **Integration-test fakes.** The 37 fakes in `tests/` exist because `test_support` is `#[cfg(test)]` and private, so integration tests cannot reach it. 25 integration test files already share code through `#[path = "support/…"]`.

**D5. Small helpers. Most of these look alike but must stay separate.**

- **Exact duplicate.** `oathnet::non_blank` (`src/oathnet.rs:638`) is the same as `textnorm::nonblank` followed by `to_owned`.
- **Same shape, different semantics, so they stay:**
  - `coverage::non_empty` returns the untrimmed text.
  - `hibp::client::non_empty` returns an error.
  - `radar::clean_name` also rejects `<unknown>`.
- **Too small to share.** The identical one-line `provenance(scan_id)` wrappers in `asic_persons`, `asic_orgs` and `acnc` are not worth a shared function.

### 4.3 Deliberately not consolidated

Each of these differences is a rule with a reason, so this plan keeps each one separate:

- **The three register name matchers** (`acnc`, `asic_orgs`, `asic_persons`). `acnc` matches each alternate name on its own, and that is an anti-fabrication rule (`src/acnc.rs:119`).
- **The account legs that differ:**
  - `bluesky_user` treats a 400 or 404 as a miss only with explicit XRPC not-found evidence.
  - `hacker_news` treats a 200 with a `null` body as a miss, and compares the user ID with exact case.
  - `keybase` treats a 400 or 404 as a miss only when the outcome is a plain `Upstream4xx`.
  - `docker_hub_user` falls back from users to organisations.
  - `mastodon_user` matches `acct@host`.
  - `gitlab_user` and `duolingo` treat an empty list as the miss.
  - `wikipedia` checks across several records.
  - `tiktok_public_contact` shares only the report shape.
- **Redirect policy.** CKAN register fetches follow redirects, while account legs refuse them.
- **The lineage `VERIFIED_REGISTRY_SOURCES` gate.** It decides independence, and must not be derived from a convenience table.
- **The dispositions TSV.** Each row carries a human rationale.
- **Provider sign-up information** in `provider_credentials`.
- **The persisted spelling family** (`canonical_family`).
- **Checked in the `094504310` survey and kept**, because each is one authority already or differs by rule:
  - `canonical::canonical_domain`, `canonical_domain_host`, `canonical_phone` and `is_domain_label` call their `value_syntax` namesakes: one authority, two paths.
  - `canonical::is_public_ip` is stricter than `egress::is_public_ip` for IPv6 selectors (Teredo, 6to4 and the documentation block), on purpose.
  - The lookup CLIs' `*Args::parse` already share `LookupTokens::single`; each keeps a three-line adapter.
  - Each source's `url`, `user_url`, `profile_url`, `search_url`, `API` and `INTEL` declarations are its own data.
  - `base_rpc` and `eth_rpc` are one-line chain adapters over `evm_rpc`, kept so each chain keeps its module path.
  - The kernel legs' `lookup` functions (identical in `codewars_user` and `devto_user`) and the `api_leg` wrappers (`otx`, `hackertarget`, `stopforumspam`, `urlscan`) are identical by construction: each names its own module's items.
  - `exif` and `docmeta` word their summaries for their own file kinds.
  - `x509::one_line` (SpiderFoot's form) and the APK signer's `ATTR=value` list (apksigner's order, each value bounded) are two output contracts. C3 shares the reading under them, not the rendering.
  - `apk_intel::signing_block` finds the APK signing block; `apk_intel::signer::signing_block` reads the signers inside it.

## 5. Target design

**T1. One source profile table.** Create `src/source_profile.rs` in the `core` home. It holds one
row per provenance source ID:

```rust
pub struct SourceProfile {
    pub id: &'static str,                    // provenance.source, exactly as written
    pub family: Family,                      // correlator class, today's value
    pub modality: Option<Modality>,          // None: same as family
}
pub const PROFILES: &[SourceProfile] = &[/* generated from today's classifier output */];
pub const LEGACY: &[SourceProfile] = &[/* the IDs no current collector writes */];
```

- **Why keep it off `ReachableModule`:**
  - That struct is serialised into the HTTP module list, so new fields would change JSON.
  - Its rows are named by module. One module can write several source IDs, and `apk_intel` and `apk_set` have no row of their own.
- **Dependency direction.** The table lives in `core` and holds literals. `analysis` may depend only on `core` and `evidence`, so it cannot import the collectors' constants. A guard test in `tests/` cross-checks the literals against the constants instead (G1).
- **Consumers:**
  - `correlator::source_family` reads `PROFILES`, then `LEGACY`. It keeps the substring tests only for IDs in neither table, such as unknown IDs in old saved scans.
  - `acquisition_modality` reads the `modality` column.
  - `lookup_save` keeps its per-policy maps. G2 ties them to what each lookup writes (B4). A `component` column was not adopted: every record a lookup writes but one already had an explicit attribution, so a guard is the smaller durable fix.
- **Not adopted.** Merging the two username source lists: the refusal-contract harness already holds them to the same set, and only `username_cli` fixes the order. Renaming the correlator function: the churn buys only a clearer word.

**T2. Account-leg kernel.** Create `src/account_leg.rs` in the `collection` home:

```rust
pub struct AccountContract {
    pub source: &'static str,
    pub not_found: NotFound,     // Plain404 | Plain400Or404 | NullBody | EmptyList | XrpcNotFound
    pub identity: IdentityMatch, // IgnoreAsciiCase | Exact | AcctAtHost
}
```

- The kernel keeps the rule that a 404 is a clean miss only when the outcome is a plain `Upstream4xx`, so a challenge page stays `BotWaf`.
- Each leg keeps its own URL, decoding and emitted entities. Each module re-exports `pub type Report = crate::account_leg::Report`, so existing paths still resolve.
- A leg moves to the kernel only when its contract can say exactly what it does today. Otherwise it stays bespoke.
- **As built**, the contract is `account_leg::AccountLeg`, with `Absent`, `Identity` and `HandleCase` in place of the sketch's `NotFound` and `IdentityMatch`.

**T3. One CLI finish path.**

- Every `SourceRun` CLI finishes through `SourceReach`, choosing `unanswered` or `stopped` to keep its current semantics.
- A shared `lookup_report::finish` does the merge, the no-answer decision and rendering.
- `none_accepted` is removed once B3 is decided.

**T4. Shared test transports.**

- In-crate tests use `src/test_support.rs`.
- Integration tests use one `tests/support/transport.rs` through `#[path]`.
- A fake with unique behaviour stays local and is allow-listed, for example the `username` concurrency probe.

**T5. Module splits along existing seams.** These are pure moves; `pub use` keeps every
`huntsman_recon::…` path.

- **`scan_service`:**
  - plan types (lines 78 to 245);
  - admission (252 to 296);
  - collector (302 to 820);
  - correlate (937 to 1008);
  - lifecycle (1032 to 1246);
  - status (1263 to 1338);
  - crawl (1402 to 1616);
  - save (1616 to 1824);
  - stop, delete and rerun (1824 to 1930).
- **`scan_api`:** split by route group (lines 284 to 1322).
- **`graph_exec`:**
  - model (39 to 460);
  - validation (468 to 700);
  - run (702 to 1084);
  - checkpoint (1084 to 1126);
  - executor (1130 to 1696).
- **Tests.** Each file's tests first move to `<module>/tests.rs`, the pattern `src/web_server.rs` and `src/lookup_modules/` already use.
- **The seams above were read at `e7301b4c6`.** Re-read them at the commit the Stage 9 move starts from.

## 6. Declared behaviour changes

These are the only changes allowed to alter output. Each one lands on its own: B1 to B4 after
Phase 2 as pull requests, B5 to B9 as commits after the pure items of section 10 that touch the
same files.

| ID | Change | Visible effect |
|---|---|---|
| B1 | The correlator classifies `acnc` as `identity_registry` and `exa` as `search`, fixing the typo arms | The family counts in AU-001 and AU-021 messages, and `tagged_matching_sources`, for entities carrying that evidence |
| B2 | `wikipedia` stops classifying as `infra` and becomes `other`, matching `wikidata` | The same counts drop by one where Wikipedia evidence was counted as infrastructure |
| B3 | People, crypto, place, company, gleif, itunes and wikidata route their legs' failures into rows that `SourceReach` reads, as the other eight lookups do | A refusal or an unanswered lookup names its module (and, for people and place, its reason); a refusal recorded as a row exits 77, not 69; no other exit code changes |
| B4 | Saved phone lookups credit North American numbering-plan rows (`phone_nanp`) to `src/phone_intl.rs`, which writes them, not to `src/phone_cli.rs`. G2 holds every record each lookup writes to an explicit attribution | Two rows of the attribution snapshot: `phone_nanp`, outcome and entity |
| B5 | `sf_elements` reads a URL's host through the one URL-host reader (C2), which drops one trailing root dot | A link on the target's domain written with a trailing root dot, which canonical form cannot read (not `http` or `https`, such as `ftp://example.com./pub`), is typed `LINKED_URL_INTERNAL`, not `LINKED_URL_EXTERNAL`. An `http` or `https` link already lost the dot to canonical form |
| B6 | The APK signer reads certificate validity through the shared DER reader and `x509`'s calendar rule (C3) | A validity time that is not a calendar date, such as UTCTime `991340256161Z`, reads as empty instead of `1999-13-40T25:61:61Z`. A certificate with any unreadable validity time is kept with that time empty, where today it is dropped |
| B7 | Network Survey LTE and NR rows check their reported location with `geohash::valid_fix`, as RF sightings do (C6) | A row reporting latitude 0 and longitude 0 keeps no reported location, instead of placing the device at 0°, 0° |
| B8 | `keys::store_slots` takes the cross-process write lock (C5) | A CLI `keys` save and a Web UI Settings save made at once both keep their change; a save that finds the lock held past its wait fails with an explicit busy-or-stale-lock error and writes nothing |
| B9 | `run_history` opens its history through the shared checked opener (C4), which refuses a path that is not a regular file before opening it | A history path holding a FIFO is refused at once as not a regular file, where the open used to wait for a reader |
| B10 | `DeHashed` searches share one process-wide budget at its documented 10 a second, and go through `fetch`'s per-host breaker | A 429 or a run of failures pauses `DeHashed` for the process: a held-back search sends nothing and reads `Paused` |
| B11 | A `DeHashed` 400, 401 or 403 is read by its body's documented words | A rejected key, no subscription and no credits each read as what they are, instead of the status's one reading |
| B12 | `DeHashed` records are read through `breach_record`, as `OathNet`'s are | Every non-credential value a record holds is shown and kept as evidence; the credits left are shown; credentials stay by name only |
| B13 | `DeHashed`'s documented paging: size up to 10,000, page × size at most 10,000 | A page past the depth is refused before sending; the exposure leg reads 1,000 records a search; a complete later page is not partial |
| B14 | Every `DeHashed` path resolves the key one way | A key only in `~/.config/dehashed/api_key` now reaches the lookups too |
| B15 | `credential-status`, its probe and the web UI's key settings read each slot by the lookups' rule | A key only in `~/.config/dehashed/api_key` shows as set and is probed; a refused one is named with its own fix. The web UI also shows the shared abuse.ch key on URLhaus and ThreatFox, and HIBP's `HIBP_API_KEY`, as set, with where each key is |
| B16 | HIBP's `~/.config/hibp/api_key` is a provider key file | `credential-status`, its probe and the web UI report the key HIBP's lookups read from it. A refused one is named with its fix, and `hibp subscription` still names the file as the key's source |
| B17 | The evidence matrix counts only modules that ran | `module_execution_counts` no longer counts a module that never sent a request (`not_configured`, `refused_before_sending`). `module_outcome_kinds` says, for each module, what its outcomes were |
| B18 | Australian `13` and `190x` numbers are phone numbers | The canonicaliser accepts every range the AU plan types; E.164 is 8 to 15 digits |
| B19 | crt.sh waits 75 s | Large domains' certificate histories are read instead of timing out |
| B20 | `Limited`, `Ltd`, `PLC` and `LLP` names are organisations; `sources` routes a one-word name | Routes and classification of company names change |
| B21 | Every keyed leg without its key leaves `not_configured` | VirusTotal, AbuseIPDB and Hunter rows appear in `ip` and `domain` |
| B22 | A depth scan's frontier is fair across pivot kinds | A kind takes at most half a generation; dispatch is round-robin by kind |
| B23 | An FBI notice attaches only to the person it names | A notice is kept only when its title or an alias contains every name token of the query; otherwise the leg is `valid_zero` |
| B24 | A public figure's Wikidata X handle becomes a pivot | Account identifiers accept qualifiers that only describe the account (follower count, its time, start, numeric id, verified); restrictive or unknown qualifiers still suppress |
| B25 | A Wikidata name search never picks one of several namesakes | Two or more exact-label hits make the leg `inconclusive` with the candidates named; one exact-label hit wins over rank |
| B26 | A person scan checks FBI wanted notices | `fbi_wanted` is a registered module and a people leg (CLI, web UI, scans, coverage, matrix); notices must name the person (B23) |
| B27 | A breach row attributes only when it names the searched value | See-Know rows must carry the selector in a field of its kind (domain: host on it); other rows attribute nothing and are counted in the outcome |
| B28 | A person scan checks ICIJ Offshore Leaks | `icij_offshore` is a registered Corporate module and people leg; nodes kept only when their name carries every query word, as Document leads |
| B29 | A person scan checks the OFAC and UN sanctions lists | `sanctions` downloads both lists through the shared feed cache (one authority, `CachedList`) and matches every name word locally; an XML list declares its root so it is not mistaken for a page |
| B29b | The EU sanctions list joins OFAC and UN | `sanctions.eu_fsf` reads the EU consolidated CSV through the same cache, grouping its rows by subject; the shared CSV splitter takes a separator |
| B30 | A DeHashed domain search works against the live API | Domain is sent unquoted (the API refuses a quoted domain with 400); email and username stay quoted (unquoted email is fuzzy). Opt-in live test proves decode, fidelity and masking against the raw answer |
| B31 | A public-office holder is flagged politically exposed | P39 positions classified by their own P31/P279 records (public/elective office, head of state or government, minister, legislator, ...), never the generic "position" type; current or former kept per office |
| B32 | The sanctions lists count every match and row they leave out | A capped match is reported in the detail; unparseable rows make an unmatched list inconclusive, never a clean valid_zero |
| B33 | The PEP check ignores deprecated office classifications and reports P39 truncation | Deprecated P31/P279 are filtered; the total positions held is kept and coverage past the 20-cap is called incomplete |
| B34 | The ICIJ and FBI-notice collectors count every match and row they leave out | An over-cap or unreadable ICIJ node, or an FBI page whose `total` exceeds the rows fetched, makes an unmatched result `inconclusive` and reports the shortfall on a match, never a clean `valid_zero` that reads as the whole corpus |
| B35 | SeekNow's key is supplyable by its own private file like DeHashed's and HIBP's | `~/.config/seeknow/api_key` joins `PROVIDER_KEY_FILES`; the credential builder and both run gates read it through the slot rule, so a Termux install driven through the web UI needs no persistent env var |
| B36 | The SEC EDGAR leg counts the filings a page cap leaves unscanned | EDGAR's reported match total is read; a zero with filings unscanned beyond the page is `inconclusive`, and a match reports filers past the cap, filings unscanned and filers naming others, so neither reads as the whole of EDGAR |
| B37 | The FBI-wanted module is documented in ARCHITECTURE.md | `fbi_wanted` was registered in module.rs but lacked its L5 clause; added to the module list and described as a keyless collector folded into people scan, keyed by notice URL, reporting incomplete pages and unread content as inconclusive (not clean zero), not overshadowed by the `public_osint` parent module |

B10 to B14 are `DeHashed`'s, and [DEHASHED.md](DEHASHED.md) has the contract and tests behind them.

## 7. Phases

Each phase lands as small pull requests. A pure-move pull request never also changes logic.

| Phase | Work | Exit condition |
|---|---|---|
| 0. Safety net | Commit a classification snapshot (source ID to family and modality, for every live, legacy and probe ID) and an attribution snapshot (every save policy's pair for every ID). Bring every lookup under the refusal-contract harness, listing today's breakages as reviewed entries. Add a `#[test]` count floor. Before the first phase that changes how a lookup collects (Phase 4), extend the differential comparator to that lookup, using recorded responses for public, non-personal selectors only. | Snapshots and contract entries committed; no production change |
| 1. Test-only consolidation | Move the inline tests of the six files above to `<module>/tests.rs`, one commit per file. Point the in-crate fakes at `test_support`. Add `tests/support/transport.rs`. Replace `oathnet::non_blank`. | `cargo test -- --list` names unchanged; count never lower |
| 2. Source profile table (T1) | Generate `PROFILES` and `LEGACY` from today's classifier output and route both classifiers through them. Add G1 and G3. | Phase 0 snapshots byte-identical; G1 and G3 green |
| 3. Declared fixes | B1, B2, B3 and B4, one commit each. B4 fixes the one live misattribution and adds G2. | Each regression test fails before and passes after; snapshot and contract diffs limited to the declared rows |
| 4. Account-leg kernel (T2) | Move one leg per commit, with that leg's existing tests unchanged in the same commit; the divergent legs go last or stay bespoke | `username` differential output identical |
| 5. One finish path (T3) | Move every `SourceRun` CLI to `SourceReach` plus `finish`, then delete `none_accepted` | Phase 0 exit-code tests unchanged (B3 rows updated in Phase 3); G6 green |
| 6. Splits (T5) | Pure moves along the seams, with `ARCHITECTURE.md` rows updated in the same pull request; then hand over to Stages 3 to 10 | Paths still resolve; architecture tests green |
| 7. Remaining list (section 10) | The pure items C1, C7 to C11 and R3 first, each its own commit; then the declared items C2 (B5), C3 (B6), C4 (B9), C6 (B7) and C5 (B8), one commit each; R1 and R2 with Stage 9 | Each item's acceptance in section 10; G7 to G9 green; the duplicated-window count of section 3 only falls |

## 8. Guards

New guards go in `tests/architecture_boundaries.rs`, written in its token-scanning style with a
self-test, or as plain tests where the rule needs runtime data.

| Guard | Rule |
|---|---|
| G1 | Each source ID that a collector constant names (`SRC`, `SOURCE`, `COLLECTOR_ID`, `Api.source`) has exactly one `PROFILES` row. Each `PROFILES` row is named by a constant. Each `LEGACY` row is named by no constant. |
| G2 | Every record each lookup writes, with every source answering, is credited by its save policy to the file that made it. Only the lookup front-end's own records (`MADE_BY_THE_LOOKUP` in `src/lookup_modules/tests.rs`) take the CLI file. |
| G3 | Every slot `scan_api::key_slots` lists is declared by a `provider_credentials::PROVIDERS` row or is one's fallback alias. Key slots stay on each source's `Api` constant, so the profile table holds no copy of them. |
| G4 | No new `impl Transport for` exists outside `src/test_support.rs`, `tests/support/` and an allow-list. |
| G5 | The six oversized files may not grow past a committed line ceiling. This guard is optional and can be dropped once Phase 6 lands. |
| G6 | No `*_cli.rs` decides "no source answered" except through `SourceReach`. |
| G7 | No `pub struct Report` or `pub struct Leg` with exactly `SourceReport`'s, `LookupReport`'s or `Leg`'s fields exists outside `src/lookup_report.rs` (C1). |
| G8 | No `fn host_of` or `fn url_host` exists outside `src/circuit.rs`, whose `host_of` is the one URL-host reader (C2). |
| G9 | One DER reader: no `struct Tlv`, `fn tlv(` or `struct Der` exists outside it (C3). |
| G10 | No production string literal of any kind holds a run the release key scan reports. Such a run is 32 lowercase hex with a letter and five different digits in a window, and the release refuses a binary holding one. Only the two values the scan strips are known: the directive digest and the AU register's digest. A digest the code needs is worked out at run time. In place: `no_production_literal_holds_a_key_shaped_hex_run`, after the DeHashed probe's SHA-256 literal failed the pre-release key scan. |
| G11 | Every reachable module sits in exactly one OSINT matrix group, and every module a group names is reachable. In place: `osint_matrix::tests::every_reachable_module_sits_in_exactly_one_group`. Before it, the matrix named 44 of 144 reachable modules and had no phone, email or blocklist group. |

The Phase 0 snapshots stay as regression locks after the phases finish.

## 9. Expected outcome and risks

**Expected outcome.** All figures are *estimates* until each phase measures them.

- **Registration.** A keyless username source still touches about 9 places, but one `PROFILES` row replaces two classifier arms, and every place is now checked by a test that names what is missing: G1 the profile row, G2 the attribution row, the refusal-contract harness the lookup lists.
- **Lines removed:**
  - about 650 to 750 lines of leg boilerplate;
  - about 280 lines of CLI tails;
  - most of the 107 test fakes;
  - for section 10, about 300 lines of report structs and `miss` helpers (C1) and about 150 lines across C2 to C11.
- **Lines moved.** 8,919 lines of inline tests leave production files. They are moved, not deleted.
- **Classification.** Classifying a source becomes one row, not three match arms in three files.

**Risks and mitigations.**

| Risk | Mitigation |
|---|---|
| Concurrent sessions merge to `main` while this work runs (five other pull requests merged during the work that led to this plan) | Small pull requests, frequent rebases, pure moves kept separate |
| Hidden consumers of family strings | The classification snapshot covers every live and legacy ID, and the B1 and B2 effects are enumerated |
| Persisted data | `provenance.source_family` and the saved component paths are untouched or snapshot-locked; legacy IDs stay as aliases |
| Test-only work weakens tests | The count floor, preserved test names, and no test edited beside the code it guards |
| A self dev-dependency to expose `test_support` to integration tests | Not adopted; it needs a spike first, and `#[path]` sharing works today |
| A type alias hides a later divergence (C1) | A module whose report needs another field declares its own struct again, and G7 then no longer matches it; an alias never gains a field |
| The APK signer reads a certificate the shared DER reader refuses (C3) | The move keeps whichever reader passes both modules' existing tests, and every certificate builder in `src/apk_intel/signer.rs`'s tests is read by both before and after |

## 10. Remaining REFACTOR and CONSOLIDATE list

Measured on `main` at `094504310` (2026-11-06). The survey ran section 3's window count, an
exact-body scan of production functions and structs, and a scan of same-named rule functions across
files. Every line reference is to that commit.

- **Order.** Highest return first within each list.
- **Pure or declared.** A pure item changes no output. A declared item alters output only as its row in section 6 says.
- **Queue.** Items marked **queue** are already tasks in [`implementation/queue.json`](implementation/queue.json). They are listed so the two lists agree, and the queue's acceptance governs them.
- **Contract.** Section 2 applies to every item.

### 10.1 CONSOLIDATE: one authority per rule

**C1. One per-source report type.** Pure. **In place** (`277542315`).
- **What landed.**
  - The 34 copies listed below are aliases.
  - G7 (`report_shapes_have_one_definition`) then found five more under other names, and they are aliases too: `embedded_metadata::Inspected`, `indicator_legs::Legs`, `recursion::Step`, `seeknow_collector::LookupLeg` and `netblock_cli::Swept`.
  - `LookupReport` gained `Serialize` for the inspect view, whose JSON is unchanged, and `asked`, the SeekNow leg's only method.
  - `account_leg`'s inherent `miss` and `found` moved to `SourceReport`.
- **Duplication.** Twenty-nine modules declare the same `pub struct Report { pub entities: Vec<Entity>, pub outcome: SourceExecutionOutcome }` with the same derives (`Debug, Clone, PartialEq`):
  - `account_leg`, `acnc`, `archived_page`, `blockchain`, `bluesky_user`, `certspotter`, `crates_io`, `docker_hub_user`, `duolingo`, `evm_rpc`;
  - `github_repos`, `github_user`, `gitlab_user`, `gleif`, `gravatar`, `itunes`, `keybase`, `mastodon_user`, `nominatim`, `npm_author`;
  - `openpgp_keys`, `opensky`, `peeringdb`, `sec_edgar`, `solana_rpc`, `stac`, `tiktok_public_contact`, `wikidata` and `wikipedia`.
- **More copies.**
  - Nineteen modules define the same `fn miss(outcome: SourceExecutionOutcome) -> Report`, which returns that report with no entities.
  - `asic_director`, `asic_orgs`, `asic_persons`, `docmeta` and `exif` declare `lookup_report::LookupReport`'s exact fields (`src/lookup_report.rs:28`).
  - `mnemonic::Leg` (`src/mnemonic.rs:216`) and `rdap_legs::Leg` (`src/rdap_legs.rs:33`) are the same struct.
  - None of them has an inherent or trait impl, so each can become an alias.
- **Change.**
  - In `src/lookup_report.rs`, add `pub struct SourceReport` with the 29's fields and derives, and `pub fn miss(outcome) -> Self` on it.
  - Also add `pub struct Leg` there, with `mnemonic::Leg`'s fields and derives (`Debug, Default`).
  - Make each of the 29 `pub type Report = crate::lookup_report::SourceReport;`. That includes `account_leg::Report`, so the eight legs that alias it are untouched.
  - Replace each `miss(…)` call with `Report::miss(…)`, and delete the 19 local functions.
  - Alias the five to `LookupReport`. `asic_director` and `asic_persons` gain `Default`, which only adds.
  - Alias both `Leg`s to `lookup_report::Leg`.
- **Guard.** G7.
- **Acceptance.** Every test passes unchanged, and so do the `cargo test -- --list` names. Files declaring `pub struct Report` fall from 46 to 12.

**C2. One URL-host reader.** Declared change B5. **In place** (`28149b5a7`), with G8. `topology` reads the canonical form through `canonical_url_host`.
- **Duplication.** Five functions answer "which host does this URL name", by different rules:

| Function | Schemes | IPv6 literal | Trailing root dot | Used by |
|---|---|---|---|---|
| `value_syntax::host_only` (`src/value_syntax.rs:379`) | `http` and `https`; anything else is read as a bare host | kept in brackets | kept | `host_from_url` (`:404`), which also requires a `.`; `dns`, `crtsh`, `validation` |
| `circuit::host_of` (`src/circuit.rs:232`) | any `scheme://` | kept in brackets | one dropped | `fetch` breakers, `threatfox`, `public_osint` |
| `web_query::host_of` (`src/web_query.rs:1062`) | any | **cut at its first colon**, giving `[2001` | dots trimmed at both ends | web meta-search hits |
| `sf_elements::url_host` (`src/sf_elements.rs:210`) | any | **cut at its first colon** | kept | SpiderFoot element export |
| `relation::builders::topology::url_host` (`src/relation/builders/topology.rs:19`) | `http` and `https`, through `canonical_url` | refused: `canonical_url` gives no host | every one dropped | hosted-on relations |

  All five drop the port and lower-case the host. Four drop the userinfo; `canonical_url` refuses a URL that has one.
  The cut IPv6 literal changed no output: `web_query` only tests the host against engine domains,
  and `sf_elements` only against the target's domain. The trailing dot did, for a link canonical
  form cannot read: `sf_elements` typed `ftp://example.com./pub` as external to `example.com`.
  An `http` or `https` URL entity is already canonical, so it has no root dot by then.
- **Change.**
  - `circuit::host_of` stays the one reader, with its rule: any scheme, userinfo and port dropped, an IPv6 literal kept in brackets, one trailing root dot dropped, ASCII lower case, empty gives `None`.
  - It stays in `circuit` (L0): the breakers key on it, and L0 can depend on nothing above it. A first placement in `value_syntax` (L3) made the layering test in `tests/architecture_doc.rs` find a new upward edge, `circuit` -> `value_syntax`.
  - `sf_elements` calls it.
  - `topology` calls it after `canonical_url`, as now, so its refusals stay.
  - `web_query` calls it and keeps its own trim of dots at both ends.
  - `host_only` and `host_from_url` keep their bare-host and dotted-name rules.
- **Guard.** G8.
- **Acceptance.**
  - A new `sf_elements` test for `http://example.com./` against target `example.com` fails before and passes after (B5).
  - New `web_query` and `sf_elements` tests for `http://[2001:db8::1]:8080/x` pass before and after.
  - `circuit`'s `host_of` tests pass unchanged.

**C3. One DER reader for X.509 and the APK signer.** Declared change B6.
- **Calendar/identity correction in place separately.** The signer delegates validity rendering to `x509::time`, rejecting impossible dates. An unreadable validity value becomes an empty string without discarding the certificate, its raw-DER digest, public-key digest or other readable fields. Valid certificate output and the existing leap-second policy stay unchanged. The DER/name-reader consolidation remains queued; this correction does not claim G9.
- **Measured root-cause correction, not a pure dedupe:** same-path Rust 1.99 host release is 17,211,904 to 17,214,696 bytes (+2,792). The output change is limited to malformed certificate validity: unknown dates are empty and otherwise readable signer identities are retained. No raw APK bytes or stored reports are rewritten.
- **Duplication.**
  - `src/x509.rs` reads DER with `Der` (`:171`). `src/apk_intel/signer.rs` reads it with its own `Tlv` and `tlv` (`:82`, `:91`) and `children`.
  - Each has its own distinguished-name reader: `x509::name` (`:241`) and `signer::name` (`:160`).
  - Each has its own time reader. `x509::time` (`:444`) checks the month, the day against `timefmt::days_in_month`, the hour, the minute and the second.
  - `signer::time` (`:184`) checks only that the text is digits, so UTCTime `991340256161Z` prints as `1999-13-40T25:61:61Z`.
- **Change.**
  - Keep one crate-private DER reader, used by both modules: whichever of `Der` and `tlv` passes both modules' existing tests.
  - `signer::certificate` (`:210`) reads validity through `x509`'s time rule. An unreadable time becomes an empty string. Today `certificate` returns `None` for one, which drops the whole certificate; keeping it only adds a result.
  - Keep both renderers (section 4.3).
- **Guard.** G9.
- **Acceptance.**
  - Every `apk_intel`, `apk_set_cli`, `x509` and `certspotter` test passes unchanged.
  - A new test, `a_certificate_time_outside_the_calendar_is_not_printed_as_a_date`, fails before and passes after.

**C4. One checked open for in-place writes.** Declared change B9.
- **Current implementation.** `fsio::open_checked` owns the preflight, exclusive missing-file creation and descriptor checks for both `run_history` and `scan_store`. Each caller retains its own error wording and permissions. The shared opener also uses the existing platform-specific `O_NONBLOCK | O_NOFOLLOW` table: on its supported Linux/Android architectures, a FIFO planted after the preflight cannot block the open, and a final symlink cannot be followed. Other platforms retain the metadata checks without claiming these open-flag guarantees.
- **Regression evidence.** `scan_store::tests::append_does_not_block_when_a_fifo_replaces_the_checked_file` replaces a checked regular file with a FIFO at the check/open seam; it failed before the shared protected open and passes afterwards. The pre-existing FIFO preflight correction from #1790 is retained, not repeated. `fsio` tests also preserve missing-path creation policy and refuse a file planted after a missing check without overwriting it.
- **Historical rationale and contract:**
- **Defect found while preparing it.**
  - `run_history`'s check refuses only a symbolic link. It learns the file type after the open, so a FIFO at the history path blocks the open, waiting for a reader.
  - `scan_store` refuses anything but a regular file before it opens.
  - The shared opener takes `scan_store`'s order. A new `run_history` test with a FIFO at the path must fail before (it hangs) and pass after: it is refused at once.
- **Duplication.** Two functions implement the same rule on top of `fsio::check_not_symlink` (`src/fsio.rs:44`) and `fsio::same_inode` (`:86`):
  - `run_history::open_checked` (`src/run_history.rs:57`), with its `require_opened` (`:73`);
  - `scan_store::checked_open_for_append_with` (`src/scan_store.rs:933`).
- **The rule.** `lstat` the path, create it exclusively when it is absent, open it, then refuse a descriptor that is not the checked inode or not a regular file.
- **Change.**
  - Add `fsio::open_checked(path, &mut OpenOptions, create) -> Result<File, OpenRefusal>`, where `OpenRefusal` is `Linked`, `Changed`, `NotRegular` or `Io(std::io::Error)`.
  - Both callers map each refusal to their existing error and wording: `run_history` keeps `fsio::CHANGED_WHILE_OPENING` and `NOT_REGULAR_FILE`, and `scan_store` keeps its own.
- **Acceptance.** Every `run_history` and `scan_store` test passes unchanged, including their refusal messages.

**C5. One cross-process write lock.** Declared change B8. **In place** (`f38a2db07`).
- **A sharper holder check.** The lock now holds "pid sequence", and a holder removes it only while it is the same inode and still holds that name. A new `fsio` test showed that the inode check alone removes a lock deleted and created again by another writer, because the filesystem reuses the inode.
- **The one lock today.** `radar::TrackWriteGuard` (`src/radar.rs:770`) is the only cross-process lock:
  - an exclusively created, mode-600 `<file>.lock` holding the PID;
  - a 5-second wait;
  - removed on drop only while it is still the same inode;
  - failing closed on a stale lock.
- **Defect.** `keys::store_slots` (`src/keys.rs:612`) serialises saves only with an in-process `static SAVING: Mutex<()>` (`:613`).
  - The CLI's `keys` command (`src/cli/meta.rs:377`) and the Web UI Settings page (`src/web_server/settings.rs:101` and `:132`) run in different processes.
  - Two saves made at once can both read the old file, and the later rename drops the other's change.
- **Change.**
  - Lift `TrackWriteGuard` into `fsio::ExclusiveLock::acquire(path, wait) -> Result<ExclusiveLock, LockBusy>`.
  - `radar` keeps its wording by mapping `LockBusy`.
  - `store_slots` holds the lock on `<keys file>.lock` around its read, check and rename, and keeps the in-process mutex.
- **Acceptance.**
  - `radar`'s lock tests pass unchanged.
  - A new CLI test fails before the change:
    - It creates `<keys file>.lock` as another process would.
    - It runs `huntsman-recon keys remove SLOT` with `HOME` set to a temporary directory.
    - It requires the busy-or-stale-lock error, a failing exit and an unchanged file. Today the save goes through, ignoring the other writer.
  - Without the lock file, `keys set SLOT --stdin` and `keys remove SLOT` behave as now.

**C6. One reported-location rule for Network Survey cells.** Declared change B7. **In place** (`a5963b1ca`).
- **Four copies, not two.** The Wi-Fi (`src/wifi_radar/network_survey.rs`) and Bluetooth (`src/rf/network_survey.rs`) importers held the same block, with `valid_fix`. All four now call `reported_fix(latitude, longitude, accuracy)`, which takes the three fields' text.
- **Duplication.** The LTE and NR importers read the same latitude, longitude and accuracy triple with the same bounds:
  - `src/cell_radar/network_survey.rs:119` to `:132`;
  - `src/cell_radar/network_survey/nr.rs:143` to `:156`.
- **Inconsistency.** They check the triple with `geohash::valid_coordinate`, which accepts 0°, 0°. RF sightings use `geohash::valid_fix` (`src/geohash.rs:147`, through `rf.rs:161`), which refuses it.
- **Change.**
  - Add `rf::survey_csv::reported_fix(row, columns) -> Option<(f64, f64, f64)>`: accuracy in (0, 100,000] metres, the point through `valid_fix`.
  - Both importers call it.
- **Acceptance.**
  - Every LTE and NR importer test passes unchanged.
  - A new test, with a row reporting 0, 0 and an accuracy, fails before and passes after.

**C7. One bounded free-text query rule.** Pure. **In place** (`d5ac78bd0`), as `textnorm::bounded_query` and `textnorm::within_query_bound`.
- **Duplication.** Four functions apply the same rule with different bounds and nouns:
  - `wikidata_cli::canonical_query` (`src/wikidata_cli.rs:46`): 300 bytes;
  - `gleif_cli::canonical_query` (`src/gleif_cli.rs:45`): 300 bytes;
  - `nominatim_cli::canonical_query` (`src/nominatim_cli.rs:51`): 256 bytes;
  - `itunes_cli::canonical_keyword` (`src/itunes_cli.rs:48`): 100 bytes, worded "keyword".
- **The rule.** Trim, refuse empty, refuse over the bound, refuse a control character.
- **A partial copy.** `company_cli::CompanyArgs::parse` (`src/company_cli.rs:32`) repeats only the length and control-character checks. It runs them on the untrimmed text, before `Query::parse` decides emptiness, and must keep that order.
- **Change.**
  - Add `textnorm::bounded_query(raw, max_bytes, noun) -> Result<String, Error>`, which writes today's messages with `noun`.
  - The four functions become calls to it.
  - `company_cli` calls only the shared length and control-character check.
- **Acceptance.** Every CLI test passes unchanged, including the refusal messages.

**C8. One archived-page read summary.** Pure. **In place** (`d864513d0`), as `archived_page::record_reads`.
- **Duplication.** `common_crawl` (`src/common_crawl.rs:457` to `:494`) and `wayback_cdx` (`src/wayback_cdx.rs:170` to `:213`) share the same tail:
  - read each chosen capture, and count contacts against technology signals;
  - merge by UID;
  - write the `{read} of {n} page(s) read, {contacts} contact detail(s) found` detail.
- **The differences.** Only the label differs ("crawled content" against "archived content"). Wayback also adds its no-web-page count.
- **Change.** Move the loop and the detail into `archived_page`, which already owns their `Report`. The function takes the label and an optional extra note.
- **Acceptance.** Every `common_crawl` and `wayback_cdx` test passes unchanged.

**C9. One handle rule for the account legs.** Pure.
- **Duplication.**
  - Eleven legs define `valid_handle`. Lichess, Chess.com, Hacker News and Lobsters have the same body: ASCII letters, digits, `-` and `_`, within the leg's own `MIN_HANDLE_LEN` and `MAX_HANDLE_LEN`. Only those bounds differ.
  - The bespoke `mastodon_user` and `tiktok_public_contact` repeat one prelude (`src/mastodon_user.rs:67` to `:98`, `src/tiktok_public_contact.rs:45` to `:73`).
    - A `lookup` calls `lookup_with_options` with paced options.
    - That trims the handle, strips a leading `@`, checks the shape, and otherwise ends inconclusive.
  - That prelude is what the kernel's `AccountLeg::handle` (`src/account_leg.rs`) already does for the kernel legs. It is the largest duplicated family left: 17 windows.
- **Change.**
  - Add `account_leg::handle_shape(handle, min, max, extra: &[u8]) -> bool`. The four identical `valid_handle`s call it with their own bounds. They stay public, because their tests call them.
  - Lift the body of `AccountLeg::handle` into a free `account_leg::checked_handle(source, invalid, case, username, valid, now_unix)`. `AccountLeg::handle` calls it, and so do `mastodon_user` and `tiktok_public_contact`, with their own messages.
- **Acceptance.** `tests/fixtures/account_leg_snapshot.tsv` (88 rows) and every leg's tests pass unchanged.

**C10. Auth-failure phrases at the outcome layer.** Pure. **In place** (`cff12bff0`). `service_defs` re-exports it, so its old path still resolves.
- **Placement.** `service_defs::looks_like_auth_failure_text` (`src/service_defs.rs:171`) sits in L4, the keyed service registry. `stolen_tax` (`src/stolen_tax.rs:472`) calls it to classify a collector's own response.
- **Change.** Move the phrase list to `source_outcome` (L2), beside the other outcome rules. `service_defs` and `stolen_tax` call it there.
- **Acceptance.** Every `service_defs`, `provider_credentials` and `stolen_tax` test passes unchanged.

**C11. One list of numbering-plan readings.** Pure.
- **Duplication.** The plan sources (`phone_au`, `phone_nanp`, and `phone_ae` from #1780) are hand-listed in more than one place:
  - `src/entity.rs`'s `ENRICHMENT_ONLY_SOURCES`, as literals;
  - `src/lookup_modules.rs`'s offline `Phone` runs;
  - `src/module/tests.rs`;
  - `tests/source_label_homes.rs`.
- **Change.**
  - Add `phone_intl::PLAN_SOURCES: [&str; N]`.
  - `lookup_modules`, `module/tests.rs` and `source_label_homes` iterate it.
  - `entity.rs` keeps its literal list, checked against `PLAN_SOURCES` by a test.
  - The registry rows, the profile rows and the attribution map stay per-source on purpose: each carries its own description, class or file.
- **Acceptance.** Adding a reading changes `PLAN_SOURCES` and the per-source rows only. Every test passes unchanged.

**Already queued, listed here so the two lists agree:**
- **queue `unify-provider-failure-pacing`.**
  - DeHashed builds a fresh `RateLimiter::per_minute(DEFAULT_REQUESTS_PER_MINUTE)` per client (`src/dehashed/client.rs:248`). That budget is HIBP's ten a minute, and it is borrowed from `crate::hibp::rate_limit`.
  - HIBP shares one process-wide limiter (`RateLimiter::shared`).
  - The queue task gives DeHashed a process-wide budget and one failure-pacing rule. When it lands, move `RateLimiter` out of `hibp` to a neutral module, so no collector reaches into another's.
  - **DeHashed's part is in place** (B10, `1066873b5`): one process-wide budget at DeHashed's documented rate, the per-host breaker, and `RateLimiter` moved to `src/rate_limit.rs`. HIBP's and stolen.tax's failure pacing remain.
- **queue `build-parity-capture-tooling`.** It adds `tests/support/replay.rs`: the integration-test half of T4, which Phase 1 never added (`tests/support/` has no `transport.rs`).
- **queue `bound-apk-inflation-attempts`.** The owner's draft #1781 carries it, and it does not touch `src/apk_intel/signer.rs`. C3 rebases over it if it lands first.

### 10.2 REFACTOR: structure, no behaviour change

**R1. Phase 6 splits, with Stage 9.**
- `scan_service`, `scan_api` and `graph_exec` hold 2,019, 1,521 and 1,695 production lines.
- Re-read T5's seams at the commit the move starts from, then split each file along them as a pure move in its Stage 9 pull request.

**R2. Transport fakes (T4).**
- `src/` holds 73 local fakes in 49 files, and `tests/` holds 37 in 32 files.
- G4 stays not adopted (Phase 1).
- An in-crate test moves to a `test_support` double only when it is edited for another reason and the double reproduces it exactly.
- The integration replay double is the queue task above.

**R3. A stale MSRV note in `au_id`.** **In place** (`89d4870bf`).
- `src/au_id.rs:61` allows `clippy::manual_is_multiple_of`, saying that `is_multiple_of` needs Rust 1.90.
- It is stable from 1.87: `main` already calls it in `src/rf/network_survey.rs:115` and `src/rhinser_nfc.rs:33`, and the MSRV job builds both.
- Write `sum.is_multiple_of(89)` and drop the allow and the note.
- Acceptance: every `au_id` test passes unchanged on 1.87 and stable.

**R4. Large production files: watch, do not split ahead of their stage.**
- After Phase 1 the largest production files are:
  - `src/attack_catalog.rs`: 4,118 lines, the ATT&CK table its tests hold to ATT&CK's structure;
  - `src/address_au.rs`: 2,269;
  - `src/docmeta.rs`: 1,873;
  - `src/apk_intel.rs`: 1,555;
  - `src/doctor.rs`: 1,484;
  - `src/cli/scans.rs`: 1,377.
- None is a G5 file. Each splits, if at all, along its own seams in the stage that moves it.
