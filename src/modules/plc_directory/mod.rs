//! AT Protocol identity history from the public PLC directory (free, keyless).
//!
//! `GET https://plc.directory/{did}/log/audit`
//!
//! Every `did:plc:` identity on the AT Protocol network — Bluesky's ~40M
//! accounts and every independently-hosted one alongside them — is defined by an
//! **append-only, publicly readable log of signed operations**. Each operation
//! records the handle the account went by and the server hosting its data at
//! that moment. The directory serves the whole log to anyone, with no key, no
//! registration and no rate-limit account.
//!
//! # The gap this closes
//! Everything else HSE knows about a Bluesky account comes from the profile API,
//! which reports only the account's state *right now*. That view is silent on
//! the two facts an investigator most wants:
//!
//!   * **Every handle the account has ever used.** A rename is invisible in the
//!     profile — the old name simply stops existing. In the PLC log it is
//!     permanent. Observed live: `pfrazee.com` was `paul.bsky.social`;
//!     `danabra.mov` was `danabramov.bsky.social`; `bnewbold.net` was
//!     `bnewbold.bsky.social` and then `bnewbold.bsky.team`. Each recovered
//!     name is an ordinary username pivot into the rest of the engine.
//!   * **Every server that has hosted the account.** A self-hosted or
//!     independently-hosted personal data server is a *domain* — infrastructure
//!     that answers to DNS, certificate-transparency and netblock recon.
//!     Observed live: `bnewbold.net` moved to `pds.robocracy.org` in June 2025;
//!     `danabra.mov` to `eurosky.social` in June 2026. Neither appears anywhere
//!     in the profile.
//!
//! It also recovers what nothing else can: the account's true creation date, the
//! fact that a *deleted* account existed at all (the log outlives the account),
//! and any operation reverted through the PLC recovery window — the mechanism
//! used to undo an unauthorised key rotation, so its presence is a takeover
//! signal.
//!
//! # Recursion, as this codebase adopts it
//! One dispatch reads one identity's log. Depth comes from the engine
//! re-dispatching against what this returns: a recovered former handle is a
//! `Username`, which the whole social band re-queries — including this module,
//! which resolves it afresh. A recovered PDS host is a `Domain`, which the DNS
//! and certificate band takes up. Each expansion round advances one generation,
//! bounded by the engine's own depth and budget rather than by a call stack.
//!
//! # What these findings do NOT mean
//! The log is authoritative about the network; the inferences drawn from it are
//! where a confident wrong finding could come from, so each is gated:
//!
//!   * A **released handle can be re-registered by a stranger.** A former handle
//!     was the subject's while it was in force and may belong to someone else
//!     now; the window it was held in rides on every one of them.
//!   * A **platform-issued handle is not a domain.** `alice.bsky.social` is a
//!     name Bluesky gave out; treating it as infrastructure would attribute a
//!     company's domain to an individual. Only handles outside the known
//!     platform namespaces become domains, graded by how registrable they are.
//!   * A **hosting server is not necessarily the subject's.** Servers operated
//!     by Bluesky are recorded but never emitted as domains. Others are emitted
//!     because they are worth fingerprinting, with the caveat that a shared
//!     third-party host looks identical to a self-hosted one from here.
//!   * A **rotation key is often the host's, not the person's.** Verified live:
//!     three unrelated Bluesky-hosted accounts carry byte-identical rotation
//!     keys, because they are Bluesky's. Those are withheld by name; the rest
//!     are emitted as a correlator with the caveat attached.
//!
//! Each caveat is stamped into the evidence of the entity it governs, not left
//! in this file, because the operator reads the dossier and not the source.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::atproto::web_did_host;

mod history;
mod resolve;
mod transform;
mod types;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "plc_directory";

/// The public PLC directory. Append-only and readable without a key — its
/// operating premise is that identity history must be independently auditable.
const PLC_BASE: &str = "https://plc.directory";

/// Handle → DID resolution, served by the public AppView (keyless).
const RESOLVE_API: &str = "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle";

/// `EntityKind::Other` discriminant for an AT Protocol DID.
///
/// Deliberately identical to the string `bluesky_user` already emits, so the two
/// modules corroborate one entity through the noisy-OR agreement model instead
/// of producing two spellings of the same identifier that never meet.
const DID_KIND: &str = "bluesky-did";

/// `EntityKind::Other` discriminant for a PLC rotation key.
const ROTATION_KEY_KIND: &str = "atproto-rotation-key";

/// Cap on handles turned into entities for one identity.
///
/// A real log holds a handful; the cap exists for the pathological case. It
/// never fires silently — the true total is stamped onto the DID entity's
/// evidence, so a partial enumeration is legible as partial in the dossier
/// itself (the discipline `gleif_lei`'s `MAX_CHILDREN` and `sanctions_ofac`'s
/// `MAX_HITS` follow).
const MAX_HANDLES: usize = 50;

/// Cap on hosting servers considered for one identity. Same discipline.
const MAX_PDS: usize = 25;

/// Cap on rotation keys considered for one identity. Same discipline.
const MAX_ROTATION_KEYS: usize = 10;

/// Rotation keys belonging to a hosting provider rather than to any account
/// holder.
///
/// Verified live in July 2026: `bsky.app`, `jay.bsky.team` and `pfrazee.com` —
/// three unrelated accounts — carry these two keys byte-for-byte, because they
/// are Bluesky Social PBC's operator keys and every Bluesky-hosted account
/// shares them. Emitting one as a correlator would assert a link between the
/// subject and tens of millions of strangers, which is exactly the confident
/// false finding this codebase refuses to produce.
///
/// The list is necessarily incomplete — other providers have their own shared
/// keys — which is why every key that *is* emitted carries
/// [`ROTATION_KEY_CAVEAT`] rather than relying on this list alone.
const SHARED_ROTATION_KEYS: &[&str] = &[
    "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg",
    "did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK",
];

/// The DID is read straight from the registry that defines it, so it is as
/// certain as a public identifier gets.
const DID_CONF: f64 = confidence::VERY_HIGH_PLUSPLUS;

/// A handle in force now, matching what `bluesky_user` grades the same handle,
/// so the two sources corroborate rather than contradict.
const CURRENT_HANDLE_CONF: f64 = confidence::HIGH_PLUSPLUS_PLUS;

/// A handle the account has since dropped. Above the noisy-OR expansion floor —
/// recovering a former username is the point of the module and burying it would
/// make the walk decorative — but well below a current one, because the identity
/// it names may since have moved.
const FORMER_HANDLE_CONF: f64 = confidence::MEDIUM_PLUS;

/// The server hosting the account now.
const PDS_CONF: f64 = confidence::MEDIUM_PLUS;

/// A server that used to host the account. Still above the floor: infrastructure
/// the subject once chose is worth fingerprinting even after they leave it.
const PDS_CONF_FORMER: f64 = confidence::MEDIUM_HIGH;

/// A rotation key, emitted as a cross-account correlator.
const ROTATION_KEY_CONF: f64 = confidence::MEDIUM_PLUS;

/// Rides on every former handle.
const FORMER_HANDLE_CAVEAT: &str = "This handle is NO LONGER in use by this identity. AT Protocol \
     releases a handle when it is changed, so it may since have been registered by an unrelated \
     party — the window above is when it demonstrably belonged to this account, and any later \
     account bearing it is a separate finding requiring separate corroboration.";

/// Rides on every hosting server emitted.
const PDS_CAVEAT: &str = "A personal data server may be run by the subject or be a shared host \
     serving many unrelated accounts; the two are indistinguishable from the directory alone. \
     Treat as infrastructure ASSOCIATED with the account, not as infrastructure the subject owns, \
     until DNS/WHOIS/certificate evidence says otherwise.";

/// Rides on every rotation key emitted.
const ROTATION_KEY_CAVEAT: &str = "A PLC rotation key can control this identity. Keys shared by \
     large hosting providers are withheld (see the DID's evidence for the count), but a key that \
     survives that filter may still belong to a smaller provider rather than to the subject. It \
     correlates accounts under one KEY HOLDER, which is not the same claim as one person.";

pub struct PlcDirectory;

#[async_trait]
impl Module for PlcDirectory {
    fn name(&self) -> &'static str {
        "plc_directory"
    }

    fn description(&self) -> &'static str {
        "AT Protocol identity history (free, keyless) — recovers every handle and hosting server a Bluesky/atproto account has ever used from the public, append-only PLC audit log"
    }

    fn priority(&self) -> u8 {
        // Social band, immediately after `bluesky_user` (104): that module
        // establishes the account exists and what it looks like now; this one
        // reconstructs what it used to be. Running second means a scan that
        // budgets out still gets the cheaper present-tense answer.
        103
    }

    fn accepts(&self, t: &Target) -> bool {
        // Username covers both entry points: an ordinary handle or username, and
        // a `did:plc:`/`did:web:` value scanned directly (which skips
        // resolution entirely). DIDs are `EntityKind::Other`, which the engine
        // never re-dispatches, so a raw DID reaches this module only when the
        // operator seeds one deliberately.
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1589.001 Gather Victim Identity Information: Credentials — no.
        // T1593.001 Search Open Websites/Domains: the directory is an open,
        // keyless registry. T1590.002 Gather Victim Network Information: DNS —
        // the hosting servers and domain handles it recovers are network
        // infrastructure, which the Social default does not claim.
        &["T1590.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("bluesky-did")` and `Other("atproto-rotation-key")`,
        // neither of which can appear in a `const` slice (they own a `String`).
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Up to two sequential keyless requests — one handle resolution against
        // the AppView, one audit-log read against plc.directory — plus room for
        // a long log on a mobile connection. Being killed between them would
        // discard the resolution and return nothing at all.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let seed = target.value.trim();
        if seed.is_empty() || seed.len() > 253 {
            return Ok(ModuleResult::new());
        }

        let Some(did) = resolve::resolve_did(ctx, seed).await else {
            return Ok(ModuleResult::new());
        };

        // A `did:web` identity has no PLC log at all. Saying so — and keeping
        // the domain it is anchored to — beats returning nothing because the
        // identity used the other DID method.
        if let Some(host) = web_did_host(&did) {
            let mut out = ModuleResult::new();
            out.extend(transform::web_did_entities(&did, host, &ctx.scan_id));
            return Ok(out);
        }

        let Some(log) = resolve::audit_log(ctx, &did).await else {
            return Ok(ModuleResult::new());
        };

        let history = history::fold(&log);
        if history.ops == 0 {
            return Ok(ModuleResult::new());
        }
        if history.handles.len() > MAX_HANDLES {
            tracing::warn!(
                "{SRC}: {did} has {} handles on record; emitting {MAX_HANDLES} — the rest are NOT \
                 in this scan's results",
                history.handles.len()
            );
        }

        let mut out = ModuleResult::new();
        out.extend(transform::history_to_entities(&did, &history, &ctx.scan_id));
        Ok(out)
    }
}
