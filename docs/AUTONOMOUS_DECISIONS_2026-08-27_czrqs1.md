# Autonomous Decision Log — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

Every judgment call made without pausing for approval, per the run's
autonomy mandate. Consequential/irreversible-shaped actions are marked with
their recovery point.

## Migration scope

**Decision**: treat the migration phase as complete/no-op rather than
inventing porting work. **Rationale**: the codebase is verifiably 100% Rust
(checked directly: file extensions, `Cargo.toml` package definition, git
history, `#![forbid(unsafe_code)]`) — there is no legacy source in any
other language to characterize, port, or bridge. Independently corroborated
by a concurrent session reaching the identical conclusion on a separate
branch. **Reversible**: trivially — nothing was ported, so nothing to undo.

## Credential redaction (consequential/credential-adjacent)

**Decision**: redact the leaked SeekNow token found in `.agent/state.json`
in place, rather than leaving it or asking for confirmation first.
**Recovery point**: local git tag `pre-secret-redaction-huntsman-consolidation-czrqs1`
at the pre-change HEAD, created before any edit. **Rationale**: the run's
own protocol requires acting on credential-adjacent findings (creating a
recovery point first) rather than pausing, and leaving a confirmed-live-shaped
credential exposed for even one more commit compounds the exposure window.
**What was deliberately not done**: no git history rewrite (would affect
every downstream commit SHA on a branch with 2,700+ commits of divergence
from `main`, and is an owner-authorized decision per the run's own
"hard-to-reverse, affects others" carve-out); no attempt to validate the
key against the live SeekNow API (would use a possibly-real third-party
secret without authorization).

## Choosing a redaction shape over an outright deletion

**Decision**: replace only the quoted secret with a dated redaction note,
leaving the surrounding ledger narrative (a real record of prior work)
untouched. **Rationale**: "never silently degrade functionality, never
delete code to clean up" — the narrative entry documents real prior
engineering work; only the secret itself needed to go.

## Fixing 3 modules' placeholder-filter gap without auditing all ~30

**Decision**: fix `opencellid`/`cell_intel`/`abn_lookup` (the three the
retention audit specifically investigated and confirmed) and record the
broader ~30-module pattern as a documented follow-up, rather than either
(a) ignoring the broader pattern entirely or (b) blocking this run on a
full audit of all ~30 call sites. **Rationale**: cost/value — the three
confirmed instances are fixed with tests now; the other ~30 need their own
verification (some may have independent guards this pattern-match alone
can't confirm) and are sized as their own batch of remediation work, not
something to rush inside this run's remaining scope. Logged explicitly in
the issue ledger as won't-fix-yet, not silently dropped.

## Documenting operational vars as commented/optional, not auto-provisioned

**Decision**: for both the SeekNow credential pair (IL-3) and the 14
operational vars (IL-4), add them to `.env.example` as commented-out
optional entries rather than `env_template.txt`'s auto-provisioned
uncommented section. **Rationale**: `env_template.txt`'s uncommented lines
get written live into a fresh `~/.huntsman.env` by `hse provision` — for a
password-shaped credential or a rarely-needed tuning knob, auto-provisioning
an uncommented placeholder would recreate exactly the injection risk class
just fixed in IL-2, for zero operator benefit (these aren't primary,
commonly-needed keys). Commented/optional matches this repo's own existing
convention for tuning knobs (`HUNTSMAN_SEEKNOW_BASE`, `HUNTSMAN_SEARCH_PROXY`,
etc.).

## Verifying every documented default value against source before writing it

**Decision**: before adding any example/default value to `.env.example`,
grep the actual source default rather than write a plausible-looking guess.
**Rationale**: this run's own "never invent... proceed on the safest
assumption consistent with observed behavior" principle, applied to
documentation as much as code — three drafted values were caught and
corrected this way (OathNet session cap, SeekNow session cap, the five
WiGLE per-kind caps, and the DoH default URL all differed from the first
plausible guess). Publishing a wrong default is itself a stale-doc defect
of exactly the kind this run exists to fix.

## Not registering SeekNow email/password in `KNOWN_KEYS`

**Decision**: document the credential pair in `.env.example` but do not
add it to `util::keys::KNOWN_KEYS` (the Settings-UI paste grid).
**Rationale**: that grid's existing UX is built around single API-key
strings; a plaintext password may need different handling (masking, a
distinct field type) that is a UI design decision, not a mechanical
documentation fix — bundling a design change into a documentation-gap fix
would be exactly the "drive-by refactor" the remediation loop's own rules
forbid. Logged as a follow-up.

## Branch hygiene under a shared, externally-modified working tree

**Decision**: verify `git branch --show-current` immediately before every
commit for the remainder of this run, after discovering (via `git reflog`)
that something outside this session's own actions had checked the shared
working tree out to `main` and back at least twice. **Rationale**: one
commit did land on `main` by mistake as a direct result of this
(`fix(fuzz): regenerate stale fuzz/Cargo.lock`, originally committed as
`4385e0cc7`); caught immediately, cherry-picked onto the correct branch,
and local `main` reset to exactly `origin/main` to remove the stray commit.
No further misplaced commits occurred after adopting the verify-first
habit.

## Unshallowing the clone before building the history bundle

**Decision**: run `git fetch --unshallow` before generating the final
deliverable's git bundle, once `git rev-parse --is-shallow-repository`
confirmed this session's checkout was shallow. **Rationale**: the mandate
requires the bundle to preserve "complete history"; a bundle built from a
shallow clone would silently satisfy `git bundle verify` (which only checks
internal consistency, not completeness against the real upstream) while
actually omitting history beyond the shallow boundary — a defect that would
only surface for whoever tried to use the bundle later. Re-verified after
unshallowing: `merge-base` resolution and ahead/behind counts against
`origin/main`, which had failed outright on the shallow clone ("no merge
base"), both worked correctly afterward, and the regenerated bundle was
byte-for-byte close to the same size (28M both times), confirming the
shallow boundary hadn't actually been hiding much — but "probably fine"
isn't the same as verified, so the unshallow-and-regenerate step was done
regardless rather than assumed unnecessary.

## Merging `main` into the branch before opening the remediation PR

**Decision**: once GitHub write access was restored (unexpectedly, after
being down most of the run), merge `origin/main` into
`claude/huntsman-consolidation-czrqs1` — rather than opening a PR straight
from a branch that was 7 commits behind — and resolve the 3 resulting
conflicts by evaluating each on its merits rather than mechanically
preferring either side. **Rationale**: `README.md`'s conflict was a true
duplicate (both sides added the same table row at different positions) —
resolved by keeping one copy. `.agent/state.json`'s conflict was two
closure notes for the same already-fixed issue — kept `main`'s version
since it named the specific landing PR/commit, a strict superset of the
information in this branch's version. `scripts/doc_coverage.sh`'s
conflict was the doc-coverage ratchet baseline itself (1051 vs. 1063) —
kept this branch's lower, more-recently-re-verified figure, then
re-ran the full doc-coverage check against the actually-merged tree
(not assumed) to confirm 1051 still held after pulling in `main`'s
zoomeye/proxycurl changes. All three resolutions were verified by a full
`scripts/gate.sh --quick` run on the merged tree before pushing, not just
inspected by eye.

## Continuing after GitHub write access failed

**Decision**: continue producing and committing remediation work locally
rather than treating the access failure as a run-ending blocker.
**Rationale**: "blocked is not stopped" — git push and the GitHub API's
write endpoints both returned 403 (verified: read access, `git ls-remote`,
and GitHub API reads all still worked; explicit-bearer-token push was also
tried and failed identically, ruling out a local credential-wiring bug).
The final deliverable is a self-contained zip with a git bundle, which
does not require push access to produce — so the actual deliverable
requirement remains achievable, and work continued toward it rather than
halting. Logged as a known risk/external blocker in the audit report
rather than silently worked around or hidden.
