# HUNTSMAN adversarial review — 2026-10-24

## Verified scope and acceptance

Baseline: `368500dfeb975ec8f0a40742641b64ccb45e93e2` on `main`.
Scope: recent Exa, Censys and shared abuse.ch integrations, their credential/transport boundaries, source outcomes, and deterministic repository gates. This is a bounded review, not a claim that every historical module or provider has been exercised live.

The user's HUNTSMAN protocol authorizes discovery, justified repairs, tests and verified integration. Existing repository constraints require Rust-first implementation, rootless Android Termux AArch64 compatibility, no new expenditure, and evidence before release claims. The repository's `docs/REPAIR_PROTOCOL.md` supplies the host and platform acceptance contracts.

Acceptance:

- Censys organization entities use the managing-organization field; AS labels remain metadata.
- Malformed consumed service/DNS/routing/location values produce `schema_drift` and no evidence, rather than successful observations.
- Documented sparse service objects and omitted/null collections remain supported; no invented mandatory fields.
- Shared abuse.ch key availability agrees across runtime execution and the shipped server settings; unrelated credential requirements remain intact.
- Existing no-key, host identity, HTTP status, origin binding and explicit Exa budget contracts continue to pass.
- Full host gate, independent review and PR CI pass before merge; actual merged revision and main CI are checked afterward.

## Findings and falsification

### F1 — AS labels asserted as organizations

- **Target / assumption:** `src/censys.rs::decode` assumes `autonomous_system.name` identifies the managing organization.
- **Mechanism:** AS label and organization are distinct fields. Turning the former into an organization pivot emits an unsupported organization entity and loses the supplied operator.
- **Evidence / provenance:** [Official Censys v3 host OpenAPI](https://docs.censys.com/reference/v3-globaldata-asset-host.md), version 1.0.156, updated 2026-04-23: `Routing.name` is the friendly AS name; `Routing.organization` is its managing organization. A separately compiled offline harness against the unmodified library returned `organization_pivots=["AS-LABEL"]` for a response also supplying `organization="Actual Operator Ltd"`.
- **Severity / likelihood:** Medium evidence-integrity defect; triggered whenever these fields differ. Live frequency is unmeasured.
- **Falsification / reproducible procedure:** `cargo test --locked --test ip_censys`; differing labels must yield only `Actual Operator Ltd` as an organization and retain `AS-LABEL` as `as_name`; absent/blank organization must yield no organization entity.
- **Correction / alternatives:** Read `organization` for the organization pivot and preserve `name` as AS metadata. Inferring an operator from an AS label has no supporting contract; a larger schema rewrite adds unnecessary risk.
- **Status:** Reproduced on baseline; corrected in this repair, with executed regression results recorded below.
- **Residual uncertainty:** The fixture follows the published schema; no authenticated live provider response was fetched.

### F2 — Invalid provider fields become successful evidence

- **Target / assumption:** `src/censys.rs::decode` assumes silently dropping malformed service/DNS fields or optional metadata preserves the malformed-response failure contract.
- **Mechanism:** `services:[null]` or a string-valued port is counted as a service while its details are discarded; `dns.names:[7]` is silently ignored. The shared indicator fold then records `Success` and creates seed evidence. Independent final review also identified malformed optional DNS, routing and location parents/fields being mistaken for absence; twelve additional fixtures reproduced that gap before correction.
- **Evidence / provenance:** Original compiled decoder returned success for all three fixtures in an independent offline harness. The official v3 schema and [pinned Censys SDK Service model](https://github.com/censys/censys-sdk-go/blob/e6e58d0c0b30e50b9999c2ebe736b10194f598c7/docs/models/components/service.md) specify object service rows, integer ports when present, and string DNS names. Service has no required fields.
- **Severity / likelihood:** Medium evidence-integrity defect; low for conforming responses, relevant to malformed replies or schema drift.
- **Falsification / reproducible procedure:** The integration tests feed malformed consumed values through the real provider and indicator fold. Pass means one `SchemaDrift` outcome with no entities/evidence, including a mixed valid/invalid response. Valid empty/null collections, sparse objects, optional absent fields, and valid port boundaries must still succeed.
- **Correction / alternatives:** Validate consumed elements before counting/aggregation. Retain existing tolerance of null optional primitives. Requiring every service to contain a port or protocol was rejected because the published schema does not require them; silently accepting invalid present values conceals data loss.
- **Status:** Reproduced on baseline; corrected in this repair, with executed regression results recorded below.
- **Residual uncertainty:** This intentionally validates consumed shapes rather than implementing the provider's entire OpenAPI schema. It does not reject unknown fields or future protocol strings.

### F3 — Shared abuse.ch keys disagree between runtime and UI

- **Target / assumption:** `src/cli/scans.rs::slot_check` assumes a raw stored-key lookup represents whether a provider can run.
- **Mechanism:** Runtime accepts either abuse.ch key slot for ThreatFox/URLhaus. Raw `Keys::get` misses that fallback, so `/api/settings` marks an enabled source unconfigured and technique selection can exclude it.
- **Evidence / provenance:** `Keys::provider_key` and `provider_credentials::secret_for_slot` implement the shared-key rule. A separate real-binary loopback server test using only `HUNTSMAN_ABUSECH_KEY` failed with `urlhaus: threatfox left:false right:true`; HIBP/WiGLE compatibility passed.
- **Severity / likelihood:** Medium integration defect; deterministic for operators using only either one of the shared abuse.ch slots.
- **Falsification / reproducible procedure:** `cargo test --locked --test shared_provider_settings`. Launch the shipped server with isolated synthetic credentials; either single slot must configure both sources, neither must configure neither. HIBP aliases remain accepted; WiGLE still needs both distinct slots.
- **Correction / alternatives:** Reuse the existing canonical resolver in the production server adapter. Duplicating symmetric aliases in the settings fallback table risks disagreement and cycles; broad credential refactoring adds cost without verified benefit.
- **Status:** Reproduced on baseline; corrected in this repair, with executed regression results recorded below.
- **Residual uncertainty:** Settings confirms local credential availability, not remote entitlement or authentication success.

### Retired objections and remaining boundaries

- **Disproven objection:** The Censys decoder uses a v2 envelope against v3. Official v3 explicitly contains `result.resource`, `dns.names`, `Routing.name` and `transport_protocol`; no schema migration is justified.
- **Disproven objection in reviewed paths:** Exa runs automatically or spends an unbounded result budget. Only explicit `query --exa` invokes it; the request asks for five Lite results through the shared no-redirect, bounded-timeout layer. No paid provider call was made during this review.
- **Unverified security hypothesis retired as a blocker:** Exa may return nonpublic lead URLs, but reviewed CLI code only prints escaped leads and never fetches them; no SSRF path was demonstrated. Its public-URL comment is broader than its URL validator.
- **Existing documented trade-off:** `issue-fix.yml` runs model-authored Cargo code with a model key available and a same-user checker copy. Source comments and `docs/ISSUE_FIX.md` acknowledge this boundary. Potential impact is high if malicious code executes; probability is unknown and activation is triage/dispatch-controlled. A synthetic-key isolation test could falsify the objection only by proving that executed code cannot read the key or replace the checker; that isolation test was not run. Redesigning workflow authority is outside these provider repairs; the risk remains.
- **Deferred governance gaps:** Bundled maintainer-defense auditor found 0 critical/high workflow matches and three local leads: missing security policy (medium), dependency-update policy (low), and documented branch-protection expectations (note). These are not evidence of exploitation. Live branch-protection reads returned HTTP 403 (`Resource not accessible by integration`), so protections could not be independently established.

## Decision and implementation record

Select three small repairs with deterministic offline reproductions. They improve attribution, fail-closed outcomes and source availability without adding dependencies, spending provider credits, changing public interfaces or altering automatic source selection.

Strategic/architecture, integration/verification and security specialist reviews were performed by actual delegated agents. Repository council names are responsibility labels; no named external person was consulted.

An isolated fresh clone and repair branch protect the original main revision. Baseline and final gate outputs live under `target/repair-gate/`; transport fixture tests make no external provider requests. Reproducers and benchmark binaries are kept outside the checkout to preserve the gate's immutable-tree contract.

## Verification and performance record

Executed before the final host gate:

- Baseline `cargo gate full`: PASS; 3,474 tests, zero failures/ignored; all 26 gate steps passed and the checkout remained unchanged.
- Original Censys regression: 3 failures, 1 compatibility pass, with eleven malformed row fixtures accepted as success before correction.
- Independent review's optional-metadata regression: failed as expected; all twelve malformed fixtures were accepted before correction. DNS-parent-only reproducer also failed as expected.
- Shipped-server credential regression: expected abuse.ch alias failure, existing HIBP/WiGLE compatibility passed; correction made both tests pass.
- Final targeted `cargo test --locked --test ip_censys --test shared_provider_settings`: 7 passed, zero failures/ignored.
- Initial integration lint caught `checked_conversions`; correction uses checked `u16::try_from` without weakening lint policy. Test setup's `format_collect` was likewise corrected. The initial green attempt also exposed an incorrect uppercase ASN expectation in the new test; the assertion now respects the existing shared lowercase entity canonicalization.
- Independent whole-branch review: no Critical issues; its Important partial-decode finding was reproduced, corrected and included in the seven passing tests. No additional code-review gate is being substituted for executed regression evidence.
- RustSec audit [40125564458](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/runs/40125564458): PASS on 2026-10-24; 1,352 advisories loaded, 56 locked dependencies scanned. Its Cargo.lock Git blob `971580bd5df090fa6a18c627836176a156529b79` exactly matches this repair's unchanged lockfile. No new dependencies were introduced.

Final local `cargo gate full`: **PASS**, 3,481 tests across 151 test-result records; zero failures/ignored. All 26 steps passed, including strict Clippy, offline self-acceptance and immutable-tree verification. Logs: `target/repair-gate/001792870974-0053568-0000-full/`. An intermediate test-documentation `doc_markdown` lint was corrected without weakening the gate. PR checks, actual merge SHA, main CI, artifact checks and remaining limitations are recorded in the final delivery receipt; this source document records the pre-merge state.

No bottleneck or production speedup has been established. A matched decoder microbenchmark used identical fixed input and the same debug-library build profile, with three alternating baseline/fixed pairs; each process measured the median of 15 batches of 2,000 decodes after warm-up. The median of process medians was 26.068 microseconds before and 26.556 microseconds after (+1.9%). This includes extra validation and organization metadata. Shared-host timing is noisy; these diagnostic measurements must not be extrapolated to optimized handset performance. Network calls, source budgets and algorithmic complexity are unchanged. No speculative optimization was retained.

Android cross-build and aarch64 emulation do not establish real-device Termux behavior. No connected handset or authenticated live-provider acceptance was available; those claims remain unverified.
