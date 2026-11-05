# Consolidation and refactor plan

Status: **PROPOSED**. Unless marked *estimate*, every number here was measured on `main` at
`e7301b4c6` (2026-11-05).

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

**Measured outcome.**
- **Classification.** One table classifies every source, and G1 fails a build that adds an unclassified source. B1 and B2 fixed three wrongly classed sources.
- **Refusals.** Every lookup but `phone` names the source it was refused by or got no answer from (B3); the harness holds all 15 of those lookups (11 scan kinds plus company, gleif, itunes and wikidata) with no exceptions.
- **Attribution.** G2 found and fixed one live misattribution (B4), and fails a source added to a lookup without one.
- **Code size:**
  - Phase 1 moved 8,926 test lines out of production files.
  - Phase 5 removed 78 net lines across 20 files.
  - Phase 4 removed 139 net production lines across the eight legs and the kernel.
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

| Measure | Value |
|---|---|
| Production Rust (`src/`) | 233,185 lines in 418 files; 298 `mod` lines in `src/lib.rs` |
| Integration tests (`tests/`) | 39,647 lines in 160 files |
| `#[test]` functions | 3,289 in `src/`, 954 in `tests/` |
| Registry rows (`module::reachable_modules()`) | 139 |
| Collector source-ID constants (`pub const SRC` / `SOURCE`) | 86 |
| `impl Transport for` blocks | 116 in total, broken down below |
| Files defining `pub struct Report` / `fn miss(` | 65 / 27 |
| CLI adapters (`src/*_cli.rs`) | 19, of which 15 return a `SourceRun` |
| Account legs behind `username` | 19 files, 6,415 lines before their test modules |

The 116 `impl Transport for` blocks break down as follows:

| Where | Blocks |
|---|---|
| Production code | 2 |
| Shared doubles in `src/test_support.rs` | 8 |
| Local fakes in 48 `src/` files | 70 |
| Local fakes in 32 `tests/` files | 37 |

Oversized production files and their inline tests, counted from the `#[cfg(test)]` line to the end of the file:

| File | Lines | Inline tests | Share | Planned home |
|---|---|---|---|---|
| `src/scan_service.rs` | 4,278 | 2,262 | 52% | application |
| `src/scan_api.rs` | 3,273 | 1,756 | 53% | web |
| `src/graph_exec.rs` | 3,110 | 1,415 | 45% | application |
| `src/exposure_cli.rs` | 3,088 | 1,904 | 61% | cli |
| `src/fetch.rs` | 2,214 | 1,265 | 57% | infrastructure |
| `src/module.rs` | 1,988 | 317 | 15% | analysis |
| **Total** | | **8,919** | | |

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

## 6. Declared behaviour changes

These are the only changes allowed to alter output. Each one lands after Phase 2, as its own pull
request.

| ID | Change | Visible effect |
|---|---|---|
| B1 | The correlator classifies `acnc` as `identity_registry` and `exa` as `search`, fixing the typo arms | The family counts in AU-001 and AU-021 messages, and `tagged_matching_sources`, for entities carrying that evidence |
| B2 | `wikipedia` stops classifying as `infra` and becomes `other`, matching `wikidata` | The same counts drop by one where Wikipedia evidence was counted as infrastructure |
| B3 | People, crypto, place, company, gleif, itunes and wikidata route their legs' failures into rows that `SourceReach` reads, as the other eight lookups do | A refusal or an unanswered lookup names its module (and, for people and place, its reason); a refusal recorded as a row exits 77, not 69; no other exit code changes |
| B4 | Saved phone lookups credit North American numbering-plan rows (`phone_nanp`) to `src/phone_intl.rs`, which writes them, not to `src/phone_cli.rs`. G2 holds every record each lookup writes to an explicit attribution | Two rows of the attribution snapshot: `phone_nanp`, outcome and entity |

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

The Phase 0 snapshots stay as regression locks after the phases finish.

## 9. Expected outcome and risks

**Expected outcome.** All figures are *estimates* until each phase measures them.

- **Registration.** A keyless username source still touches about 9 places, but one `PROFILES` row replaces two classifier arms, and every place is now checked by a test that names what is missing: G1 the profile row, G2 the attribution row, the refusal-contract harness the lookup lists.
- **Lines removed:**
  - about 650 to 750 lines of leg boilerplate;
  - about 280 lines of CLI tails;
  - most of the 107 test fakes.
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
