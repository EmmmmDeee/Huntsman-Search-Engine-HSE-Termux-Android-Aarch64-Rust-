# Credential audit — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

Found independently on this branch during the retention-manifest pass of an
autonomous Rust-migration/remediation run, and cross-verified against a
**concurrent session's identical finding** on a separate branch
(`claude/migrate-codebase-rust-qen2pn`, PR #483) — both sessions were given
the same task against this repository at roughly the same time and reached
the same result independently. That PR's `docs/CREDENTIAL_AUDIT_2026-08-27.md`
has the full writeup (disclosure-window analysis, structural root cause,
recommended follow-ups for the repo/SeekNow account owner); this document
records the same fix applied here, since this branch forked from `main`
*before* that PR's redaction commit and so still carried the live value.

## Finding

`.agent/state.json`'s `cycle_23_provenance` entry (this branch, line 816)
quoted a SeekNow-shaped bearer token verbatim: `seek-` + 48 lowercase hex
characters. Verified before acting:

- **Not a known-revoked credential.** Computed the value's SHA-256 and
  compared against all 11 entries in `COMPROMISED_EMBEDDED_DIGESTS`
  (`src/util/keys/constants.rs`) — no match. Treated as potentially live.
- **Single occurrence.** `grep -rn "seek-[0-9a-f]{32,}"` across the working
  tree (excluding `target/`/`.git/`) found exactly one other hit —
  `src/util/see_know/tests.rs:285`, an obviously-synthetic sequential
  fixture (`seek-1234567890aaaabbbbccccdddd...`) already covered by
  `.gitleaks.toml`'s `tests.rs` path allowlist.
- **No AID-shaped WiGLE key** (the other session's second finding class) is
  present on this branch.

## Actions taken (consequential-action protocol: recovery point, then act, then log)

1. **Recovery point**: tagged pre-change HEAD locally as
   `pre-secret-redaction-huntsman-consolidation-czrqs1` (this branch's HEAD
   at the time, `7c1bdf291`). No git-push access was available this session
   (see the session's own status notes) to also push the tag, so it ships in
   this branch's git bundle in the final deliverable instead.
2. **Redacted the value in place**, replacing only the quoted secret with a
   dated redaction note pointing at this document and the recovery tag —
   the surrounding ledger narrative is otherwise untouched.
3. **Closed the detection gap** in `.gitleaks.toml`: added the same two
   `[[rules]]` the parallel session's audit designed (`hse-seeknow-key`,
   `hse-wigle-api-name`), mirroring the shapes `tests/architecture.rs`
   already guards in `src/`. Verified the one remaining `seek-[0-9a-f]{32,}`
   match in the tree (the test fixture above) stays allowlisted.

## Deliberately not done here, matching the parallel session's rationale

- **No git history rewrite.** The value remains recoverable from this
  branch's own history prior to the redaction commit. Purging it needs
  `git filter-repo`/BFG, which rewrites every downstream SHA — an
  owner-authorized, cross-branch decision, not something either session
  should do unilaterally, and doubly true with two branches now both
  carrying (and now both having redacted) the same historical leak.
- **No live-key validation.** Not attempted, for the same reason the
  parallel session gave: using a possibly-real third-party secret without
  the account owner's authorization is out of scope for a read-then-redact
  audit.

## Follow-up (for the repo/SeekNow account owner — applies once regardless of which branch merges first)

1. Rotate/revoke the SeekNow credential at the SeekNow dashboard.
2. Decide on a history-rewrite pass (affects both this branch and PR #483's
   — coordinate once, not per-branch).
3. Consider widening `no_provider_credential_is_embedded_in_source`
   (`tests/architecture.rs`, currently `src/**/*.rs`-scoped) or adding a
   sibling check for git-tracked non-`src/` narrative files — the gitleaks
   rule closes the repo-wide gap, but a local `cargo test`-gated net is what
   caught the equivalent class in `src/` in the first place.
