# Credential audit — 2026-08-27

Ad hoc audit performed as Phase 0 of an autonomous Rust-migration review. The
codebase turned out to already be 100% Rust (see the accompanying migration
report), so the "retention manifest" work redirected into what it's actually
for here: verifying every credential the codebase touches is present,
documented, wired to a real consumer, and nowhere it shouldn't be. This
document covers the one finding serious enough to need its own record and
immediate action; the full manifest (every `HUNTSMAN_*` var, its consumer,
and its module) lives in the migration report.

## Finding: a live-shaped SeekNow key in `.agent/state.json`

**Severity:** Critical. **Status:** Redacted 2026-08-27. **Disclosure window:**
commit `419da67` (2026-08-10) through the redaction commit — approximately 17
days.

`.agent/state.json` (the autonomous engineering loop's per-cycle ledger,
git-tracked, 218 KB) carried a narrative log entry (`cycle_23_provenance`)
quoting a "mid-turn user message" verbatim. That quoted message was a
SeekNow-shaped bearer token: `seek-` followed by 48 lowercase hex characters
(fingerprinted here as `seek-0199c53c…9994468`, matching this project's own
`key_fingerprint` convention rather than repeating the full value in a second
committed file). The surrounding text shows a prior agent session receiving
what looks like a real operator credential pasted into chat, correctly
declining to act on it or guess its purpose — and then, as a side effect of
routine record-keeping, writing the raw value into a file that got committed.

This directly violates `docs/AUTONOMY_CHARTER.md`'s INV-6 ("API keys live
only in an untracked `~/.huntsman.env`; they never enter git, source, tests,
commits, PRs, or chat"), and it evaded every existing safeguard for
structural reasons, not bad luck:

- `tests/architecture.rs`'s `no_provider_credential_is_embedded_in_source`
  only walks `src/**/*.rs` (by design — it's a fast, always-on complement to
  the real scanner, not a replacement). `.agent/` is outside that scope.
- `.github/workflows/secret-scan.yml` runs gitleaks across the *whole* tree,
  which would have covered this file — but neither gitleaks' default
  ruleset nor this repo's `.gitleaks.toml` defined a detection rule shaped
  for SeekNow's `seek-<hex>` format. The scanner had nothing to match on.

**Verification before acting:** the value was compared (SHA-256) against all
11 entries in `COMPROMISED_EMBEDDED_DIGESTS`
(`src/util/keys/constants.rs:213-262` — the retired/revoked defaults this
project has purged before). No match. This is not a known-dead credential
being harmlessly quoted; it must be treated as a real, potentially-live
operator key until whoever controls the SeekNow account says otherwise.

### Actions taken (consequential-action protocol: act, stay recoverable, log it)

1. **Recovery point first.** Tagged pre-change HEAD:
   `pre-secret-redaction-2026-08-27` → `26fe12229262d0ae939c5a70f5f691d0b53ac77a`.
   Nothing about this fix touches history — the tag exists purely so the
   exact prior state is one `git checkout` away without needing to hunt
   through `git log`.
2. **Redacted the value in place** in `.agent/state.json`, replacing only the
   quoted secret with a dated redaction note pointing back to this document
   and the recovery tag. The surrounding ledger narrative (a real record of
   9 correctness fixes across cycles 21-23) is untouched — this is a
   targeted redaction, not a rewrite of the project's own history log.
3. **Closed the detection gap, not just the instance.** Added two custom
   `[[rules]]` to `.gitleaks.toml` — `hse-seeknow-key` (`seek-[0-9a-f]{32,}`)
   and `hse-wigle-api-name` (`AID[0-9a-f]{24,}`) — mirroring the exact shapes
   `tests/architecture.rs` already guards in `src/`, but scanned repo-wide
   through the CI job that actually owns this job. Verified before adding:
   grepping both patterns across the working tree turns up nothing live (the
   one `seek-[0-9a-f]{32,}`-shaped hit left is `src/util/see_know/tests.rs`,
   already covered by the existing test-fixture allowlist), and neither
   pattern collides with the documentation-placeholder strings already
   allowlisted (`seek-your-api-key-here` etc. aren't hex, so they never
   matched and still don't).
4. **This document**, committed alongside the fix, as the log the task's own
   failure policy requires ("log the action, its rationale, and the recovery
   point in the batch report") — kept as a standing repo record rather than
   only a chat transcript, since the next person to touch `.agent/state.json`
   or `.gitleaks.toml` needs the "why" to still be there.

### What was deliberately *not* done, and why

- **No git history rewrite.** The value is still recoverable from commit
  `419da67` onward via plain `git log -p`/`git show`. Scrubbing it from
  history entirely would need `git filter-repo`/BFG, which rewrites every
  downstream commit SHA — this project's own `secret-scan.yml` already
  states the house position on this exact tradeoff ("history cannot be
  un-published... revocation, not history-rewriting, is the actual remedy"),
  and rewriting shared history without the repo owner's explicit go-ahead is
  exactly the kind of hard-to-reverse, other-people-affecting action this
  run's own instructions require pausing on rather than doing unilaterally.
  If the operator wants it purged from history too, that's a deliberate,
  separate, owner-authorized operation — noted as a follow-up, not performed
  here.
- **No attempt to validate the key against the live SeekNow API.** Doing so
  would use a possibly-real third-party secret without the account owner's
  authorization — outside what a read-only-then-redact audit should do on
  its own initiative.
- **The value itself is not reproduced in full anywhere in this document**,
  by design — the point of a credential audit is to shrink the set of places
  a live secret sits, not add one.

### Recommended follow-up (for the repo/SeekNow account owner, not performed here)

1. **Rotate/revoke** the SeekNow credential at the SeekNow dashboard as a
   precaution — treat as compromised regardless of whether it turns out to
   have been real, since 17 days of public git exposure is enough to warrant
   that on its own.
2. **Decide on history rewrite.** If the account owner wants the value fully
   gone (not just superseded by rotation), a `git filter-repo` pass removing
   it from every historical commit is the mechanism — coordinate with anyone
   else who has a clone, since it changes every downstream SHA.
3. **Consider widening `no_provider_credential_is_embedded_in_source`'s
   scope**, or adding a sibling check, to cover git-tracked non-`src/` files
   that carry free-text narrative (`.agent/state.json` chief among them) —
   the gitleaks rule added here is the primary fix, but a second, local,
   `cargo test`-gated net was what caught the equivalent bug class for `src/`
   in the first place (see `docs/AUTONOMY_CHARTER.md`'s cycle 1/2 history).
