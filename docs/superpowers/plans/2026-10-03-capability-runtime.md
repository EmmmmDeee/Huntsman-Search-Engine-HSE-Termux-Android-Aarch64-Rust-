# Capability Runtime Reconstruction — Implementation Plan

> Execute this plan incrementally. Each retained change must have claim-specific evidence and remain reversible until the replacement path is verified.

**Goal:** Replace Huntsman's disconnected provider/source metadata surfaces with one executable capability contract and migrate the existing source-routing behavior through it without weakening provenance, evidence or Android constraints.

**Architecture:** Keep the current single Rust crate and guarded transport/evidence core. Introduce one `capability` owner for executable descriptors and pivot-only routes. Make `source_registry` a compatibility facade over that contract, then build planner/executor functionality in later slices. Preserve current behavior only where it satisfies the new proof obligations.

**Tech stack:** Rust 1.87+, serde/serde_json/thiserror/ureq already in-tree; GitHub Actions for executable verification; Android NDK aarch64 cross-build.

---

## Task 1 — Establish RED contracts for unified pivot capabilities

**Files:**
- Create: `tests/capability_runtime.rs`

**Tests first:**

1. Import `huntsman_recon::capability` and assert a domain seed routes through a registry-owned `PivotOnly` capability.
2. Assert exact web-search username routing preserves `@octocat` while GitHub routing transforms it to `octocat`.
3. Assert `EXAMPLE.com.` is canonicalised to `example.com` for domain-specific routes.
4. Assert pivot capabilities expose `EvidenceRole::LeadOnly` and cannot construct evidence-bearing result payloads.
5. Assert duplicate capability IDs are rejected by registry construction.

**RED proof:** Push only the tests; CI must fail because the `capability` module/contract does not yet exist. A compile failure for that missing contract is the expected failure boundary.

## Task 2 — Implement the minimum authoritative capability contract

**Files:**
- Create: `src/capability.rs`
- Modify: `src/lib.rs`

**Contract:**

- `RetrievalMode { Local, HttpApi, HttpPage, PivotOnly, Dns, Sensor }`
- `ValueTransform { Preserve, CanonicalDomain, BareUsername }`
- `EvidenceRole { LeadOnly, EvidenceBearing }`
- `VerificationLevel { ReferenceOnly, Reachable, QueryAccepted, ResultParsed, EvidenceVerified }`
- `CapabilityDescriptor` with stable id/name/category/accepted kinds/retrieval mode/transform/evidence role/reference URL/verification state.
- `CapabilityRegistry::new(&[CapabilityDescriptor]) -> Result<..., RegistryError>` rejects empty/duplicate IDs and invalid pivot/evidence combinations.
- `CapabilityRegistry::routes_for(kind, value)` performs descriptor-specific canonicalisation and RFC3986 component encoding.

**Invariant:** `PivotOnly` + `EvidenceBearing` is invalid at registry construction. This turns “URLs are not evidence” into an enforced contract rather than a README convention.

**GREEN proof:** Task 1 tests pass. Add in-module invariant tests for malformed IDs, empty values, invalid handles and transform behavior.

## Task 3 — Migrate source registry to the capability owner

**Files:**
- Modify: `src/source_registry.rs`
- Modify: `tests/source_registry_cli.rs`
- Modify: `tests/source_registry_metadata.rs`

**Change:**

- Remove local `SourceCategory`, `ExecutionMode`, `SourceAccess`, `EvidenceRole` ownership where superseded.
- Represent each existing source route as a `CapabilityDescriptor` with `RetrievalMode::PivotOnly`.
- Keep `source_registry::routes_for` as a compatibility facade during migration.
- Give each descriptor its own transform; do not globally strip `@`.
- Canonicalise domains before route rendering.
- Correct Shodan metadata to the minimum demonstrated retrieval requirement; do not claim browser-only if ordinary HTTP retrieval is known to work.
- Keep urlscan public for ordinary domain field search; do not infer authentication requirements from unrelated search modes.

**Tests:** Pin exact route sets for domain, IPv4, email, username and coordinates. Assert every route remains lead-only and carries a first-party/reference locator.

## Task 4 — Close classifier/input defects exposed by the new production path

**Files:**
- Modify: `src/classifier.rs`
- Modify: `src/main.rs`
- Modify: `tests/source_registry_cli.rs`

**Tests first:**

- `+1.+2.+3.+4`, `01.02.03.04` are not accepted as IPv4.
- `999.1.1.1` and `1.2.3` do not become routable numeric pseudo-domains.
- `90.00000000000000001,0.0` and equivalent longitude overflow are not coordinates.
- `@@octocat` is rejected rather than guessed.
- `sources example.com junk` exits usage instead of discarding `junk`.
- quoted multiword person/organisation queries still work as one argument.

**Implementation:**

- Parse IPv4 with `std::net::Ipv4Addr`.
- Add a textual exact-bound check for coordinate maxima.
- Reject all-numeric domain-like labels where classification would create bogus infrastructure routes.
- Reject malformed multi-`@` handles in source transforms/classification.
- Reject unconsumed CLI arguments for `sources`.

## Task 5 — Make emitted routing semantics machine-visible

**Files:**
- Modify: `src/capability.rs`
- Modify: `src/main.rs`
- Modify: `README.md`
- Modify: `tests/source_registry_cli.rs`

**Output contract:**

Each source route prints at least:

`source=... category=... mode=pivot_only access=... evidence=lead_only verification=... ref=... url=...`

Keep `url` last so encoded user content cannot alter prior fields. Document supported seed kinds and explicit exit behavior.

## Task 6 — Verify and falsify the first slice

Run through CI on the exact head:

- `cargo fmt --check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test --locked` on stable
- `cargo test --locked` on Rust 1.87
- `cargo run --locked -- check` + `git diff --exit-code -- var/`
- Android aarch64 release cross-build + ELF/linker verification

Then inspect the full diff and independently attack:

- URL/template injection
- UTF-8/non-ASCII encoding
- descriptor duplication
- unknown/empty seed values
- transform mismatches
- pivot/evidence role bypass
- stale verification claims
- extra CLI arguments
- route count vs actual executable coverage Goodhart failure

Do not merge this slice if any important finding remains open.

## Task 7 — Next slice after the contract proves itself

Only after Task 6 is green:

1. Add `ExecutionContext`, `CapabilityResult`, `Observation` provenance and `Capability::execute`.
2. Build a deterministic frontier planner over registered executable capabilities.
3. Use fake capabilities/transport for an end-to-end integrated scan test before adapting real providers.
4. Migrate HIBP, DNS and postcode as the first actual executors.
5. Add observed health/yield metrics and retire heuristic default priors from runtime ranking.

The old `dependency::Module`, `module::ModuleSpec/ProviderDescriptor` and `ServiceDef` surfaces remain temporary migration sources until equivalent production behavior is demonstrated; they are not removed merely because a replacement type exists.
