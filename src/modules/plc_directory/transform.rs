//! Pure transform: identity history → entities.
//!
//! No network, no IO. Every rule that decides whether a finding is attributable
//! to the subject lives here, so all of them are testable against fixtures.

use std::collections::BTreeSet;

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::atproto::{
    DOMAIN_HANDLE_ATTRIBUTION, DOMAIN_HANDLE_CAVEAT, bare_handle, handle_domain_confidence,
    is_bluesky_operated_pds, platform_handle_suffix,
};

use super::history::{History, Spell};
use super::{
    CURRENT_HANDLE_CONF, DID_CONF, DID_KIND, FORMER_HANDLE_CAVEAT, FORMER_HANDLE_CONF, MAX_HANDLES,
    MAX_PDS, MAX_ROTATION_KEYS, PDS_CAVEAT, PDS_CONF, PDS_CONF_FORMER, ROTATION_KEY_CAVEAT,
    ROTATION_KEY_CONF, ROTATION_KEY_KIND, SHARED_ROTATION_KEYS, SRC,
};
use crate::core::confidence;

/// Everything the audit log establishes, as entities.
pub(super) fn history_to_entities(did: &str, h: &History, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut emitted_usernames: BTreeSet<String> = BTreeSet::new();

    // Current handles first, so a value shared with a former handle keeps the
    // higher grade rather than whichever the log happened to mention first.
    let (current, former): (Vec<&Spell>, Vec<&Spell>) =
        h.handles.iter().partition(|s| !h.is_former(&s.value));
    for spell in current
        .iter()
        .copied()
        .chain(former.iter().copied())
        .take(MAX_HANDLES)
    {
        let is_current = !h.is_former(&spell.value);
        push_handle(
            &mut out,
            &mut emitted_usernames,
            did,
            spell,
            is_current,
            scan_id,
        );
    }

    let mut bluesky_hosts: Vec<&str> = Vec::new();
    let mut pds_emitted = 0usize;
    for spell in h.pds.iter().take(MAX_PDS) {
        if is_bluesky_operated_pds(&spell.value) {
            bluesky_hosts.push(&spell.value);
            continue;
        }
        let is_current = h.current_pds.as_deref() == Some(spell.value.as_str());
        out.push(pds_entity(did, spell, is_current, scan_id));
        pds_emitted += 1;
    }

    let mut keys_withheld = 0usize;
    let mut keys_emitted = 0usize;
    for key in h.rotation_keys.iter().take(MAX_ROTATION_KEYS) {
        if SHARED_ROTATION_KEYS.contains(&key.as_str()) {
            keys_withheld += 1;
            continue;
        }
        out.push(rotation_key_entity(did, key, scan_id));
        keys_emitted += 1;
    }

    // The DID last, so its evidence can report what the rest of the walk did.
    out.push(did_entity(
        did,
        h,
        scan_id,
        &Coverage {
            bluesky_hosts: &bluesky_hosts,
            pds_emitted,
            keys_emitted,
            keys_withheld,
        },
    ));
    out
}

/// A `did:web:` identity has no PLC log, but its host is the domain the subject
/// serves `/.well-known/did.json` from — control demonstrated by the same
/// mechanism as a custom handle, and worth saying so rather than returning
/// nothing because the DID method was the other one.
pub(super) fn web_did_entities(did: &str, host: &str, scan_id: &str) -> Vec<Entity> {
    let mut d = Entity::new(EntityKind::Domain, host, confidence::HIGH_PLUSPLUS, scan_id);
    d.tag(SRC);
    d.tag("atproto");
    d.tag("did-web");
    d.tag("verified-control");
    d.add_evidence(
        Evidence::new(
            SRC,
            format!("AT Protocol identity {did} is anchored to {host}"),
        )
        .with_attr("did", did)
        .with_attr("did_method", "web")
        .with_attr(
            "attribution",
            "did:web resolves by fetching /.well-known/did.json from this host, so the \
                 subject controlled it when the identity was created",
        )
        .with_attr(
            "coverage",
            "did:web identities have NO PLC audit log — there is no handle or hosting \
                 history to recover, and its absence is not evidence the identity has none.",
        ),
    );

    let mut id = Entity::new(EntityKind::Other(DID_KIND.into()), did, DID_CONF, scan_id);
    id.tag(SRC);
    id.tag("atproto");
    id.tag("did");
    id.tag("did-web");
    id.add_evidence(
        Evidence::new(SRC, format!("AT Protocol decentralised identifier {did}"))
            .with_attr("did", did)
            .with_attr("did_method", "web")
            .with_attr("host", host),
    );

    vec![d, id]
}

/// What the walk covered, so [`did_entity`] can state it rather than leave the
/// reader to assume the enumeration was complete.
struct Coverage<'a> {
    bluesky_hosts: &'a [&'a str],
    pds_emitted: usize,
    keys_emitted: usize,
    keys_withheld: usize,
}

fn did_entity(did: &str, h: &History, scan_id: &str, cov: &Coverage<'_>) -> Entity {
    let mut e = Entity::new(EntityKind::Other(DID_KIND.into()), did, DID_CONF, scan_id);
    e.tag(SRC);
    e.tag("atproto");
    e.tag("bluesky");
    e.tag("did");
    e.tag("plc");
    if h.created_at.is_some() {
        e.tag("account-age");
    }
    if h.tombstoned.is_some() {
        e.tag("deleted-account");
    }
    if h.nullified_ops > 0 {
        e.tag("plc-recovery");
    }

    let mut ev = Evidence::new(
        SRC,
        format!(
            "AT Protocol identity {did}: {} operation(s) in the public PLC audit log, {} handle(s) \
             and {} hosting server(s) on record",
            h.ops,
            h.handles.len(),
            h.pds.len()
        ),
    )
    .with_attr("did", did)
    .with_attr("did_method", "plc")
    .with_attr("plc_operations", h.ops.to_string())
    .with_attr("handles_observed", h.handles.len().to_string())
    .with_attr("pds_observed", h.pds.len().to_string());

    if let Some(created) = h.created_at.as_deref() {
        ev = ev.with_attr("account_created", created).with_attr(
            "account_created_note",
            "First operation in the PLC log. Independent of any profile field, and it survives \
             both profile edits and account deletion.",
        );
    }
    if let Some(handle) = h.current_handles.first() {
        ev = ev.with_attr("current_handle", handle);
    }
    if let Some(pds) = h.current_pds.as_deref() {
        ev = ev.with_attr("current_pds", pds);
    }
    if let Some(date) = h.tombstoned.as_deref() {
        ev = ev.with_attr("tombstoned", date).with_attr(
            "tombstoned_note",
            "The account was DELETED, yet its identity history remains public and permanent — \
             the PLC log is append-only and deletion does not erase it.",
        );
    }
    if h.nullified_ops > 0 {
        ev = ev
            .with_attr("nullified_operations", h.nullified_ops.to_string())
            .with_attr(
                "nullified_note",
                "One or more operations were REVERTED through the PLC recovery window, which is \
                 the mechanism used to undo an unauthorised key rotation. Their contents are \
                 excluded from the history above because the account never legitimately held \
                 them. The reversal itself is a signal worth pursuing.",
            );
    }
    if !cov.bluesky_hosts.is_empty() {
        ev = ev
            .with_attr("pds_bluesky_operated", cov.bluesky_hosts.join(", "))
            .with_attr(
                "pds_bluesky_operated_note",
                "Hosting servers operated by Bluesky Social PBC. Recorded here because they date \
                 the account's migrations, but NOT emitted as domains: they are one company's \
                 shared infrastructure, not the subject's.",
            );
    }
    ev = ev.with_attr("pds_emitted", cov.pds_emitted.to_string());
    if cov.keys_emitted > 0 || cov.keys_withheld > 0 {
        ev = ev
            .with_attr("rotation_keys_emitted", cov.keys_emitted.to_string())
            .with_attr("rotation_keys_withheld", cov.keys_withheld.to_string());
    }
    if cov.keys_withheld > 0 {
        ev = ev.with_attr(
            "rotation_keys_withheld_note",
            "Withheld keys are known hosting-provider keys shared by millions of unrelated \
             accounts. Emitting them as a correlator would link the subject to every account on \
             that provider.",
        );
    }
    if h.handles.len() > MAX_HANDLES {
        ev = ev.with_attr(
            "handles_truncated",
            format!(
                "{} handles are on record; {MAX_HANDLES} are in this scan. The remainder were NOT \
                 emitted.",
                h.handles.len()
            ),
        );
    }
    if h.pds.len() > MAX_PDS {
        ev = ev.with_attr(
            "pds_truncated",
            format!(
                "{} hosting servers are on record; the first {MAX_PDS} were considered. The \
                 remainder were NOT emitted.",
                h.pds.len()
            ),
        );
    }
    if h.rotation_keys.len() > MAX_ROTATION_KEYS {
        ev = ev.with_attr(
            "rotation_keys_truncated",
            format!(
                "{} distinct rotation keys are on record; the first {MAX_ROTATION_KEYS} were \
                 considered. The remainder were NOT emitted.",
                h.rotation_keys.len()
            ),
        );
    }
    e.add_evidence(ev);
    e
}

/// Emit the `Username` (and, where the handle is a domain, the `Domain`) for one
/// handle spell.
fn push_handle(
    out: &mut Vec<Entity>,
    seen: &mut BTreeSet<String>,
    did: &str,
    spell: &Spell,
    current: bool,
    scan_id: &str,
) {
    let handle = spell.value.as_str();
    let username = bare_handle(handle);
    if username.is_empty() {
        return;
    }

    if seen.insert(username.to_string()) {
        let conf = if current {
            CURRENT_HANDLE_CONF
        } else {
            FORMER_HANDLE_CONF
        };
        let mut u = Entity::new(EntityKind::Username, username, conf, scan_id);
        u.tag(SRC);
        u.tag("atproto");
        u.tag("bluesky");
        u.tag("social");
        let mut ev = handle_evidence(did, spell, current);
        if current {
            u.tag("account-age");
        } else {
            u.tag("former-handle");
            u.tag("historical");
            ev = ev.with_attr("coverage", FORMER_HANDLE_CAVEAT);
        }
        u.add_evidence(ev);
        out.push(u);
    }

    // A platform-issued handle is a name the operator gave out, not a domain the
    // subject controls — emitting it as one would attribute Bluesky's (or
    // Google's) domain to an individual.
    if platform_handle_suffix(handle).is_some() {
        return;
    }
    let mut d = Entity::new(
        EntityKind::Domain,
        handle,
        handle_domain_confidence(current, handle),
        scan_id,
    );
    d.tag(SRC);
    d.tag("atproto");
    d.tag("bluesky");
    d.tag("custom-handle");
    d.tag("verified-control");
    if !current {
        d.tag("former-handle");
        d.tag("historical");
    }
    d.add_evidence(
        handle_evidence(did, spell, current)
            .with_attr("attribution", DOMAIN_HANDLE_ATTRIBUTION)
            .with_attr("coverage", DOMAIN_HANDLE_CAVEAT),
    );
    out.push(d);
}

fn handle_evidence(did: &str, spell: &Spell, current: bool) -> Evidence {
    let state = if current { "current" } else { "former" };
    let mut ev = Evidence::new(
        SRC,
        format!(
            "'{}' is the {state} AT Protocol handle of {did} (public PLC audit log)",
            spell.value
        ),
    )
    .with_attr("did", did)
    .with_attr("handle", &spell.value)
    .with_attr("handle_state", state);
    if !spell.first_seen.is_empty() {
        ev = ev.with_attr("first_seen", &spell.first_seen);
    }
    if !spell.last_seen.is_empty() {
        ev = ev.with_attr("last_seen", &spell.last_seen);
    }
    ev
}

fn pds_entity(did: &str, spell: &Spell, current: bool, scan_id: &str) -> Entity {
    let state = if current { "current" } else { "former" };
    let conf = if current { PDS_CONF } else { PDS_CONF_FORMER };
    let mut e = Entity::new(EntityKind::Domain, &spell.value, conf, scan_id);
    e.tag(SRC);
    e.tag("atproto");
    e.tag("atproto-pds");
    e.tag("infrastructure");
    if !current {
        e.tag("historical");
    }
    let mut ev = Evidence::new(
        SRC,
        format!(
            "{} is the {state} personal data server hosting {did}",
            spell.value
        ),
    )
    .with_attr("did", did)
    .with_attr("pds_host", &spell.value)
    .with_attr("pds_state", state)
    .with_attr("coverage", PDS_CAVEAT);
    if !spell.first_seen.is_empty() {
        ev = ev.with_attr("first_seen", &spell.first_seen);
    }
    if !spell.last_seen.is_empty() {
        ev = ev.with_attr("last_seen", &spell.last_seen);
    }
    e.add_evidence(ev);
    e
}

fn rotation_key_entity(did: &str, key: &str, scan_id: &str) -> Entity {
    let mut e = Entity::new(
        EntityKind::Other(ROTATION_KEY_KIND.into()),
        key,
        ROTATION_KEY_CONF,
        scan_id,
    );
    e.tag(SRC);
    e.tag("atproto");
    e.tag("rotation-key");
    e.tag("correlator");
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("PLC rotation key authorised to control the AT Protocol identity {did}"),
        )
        .with_attr("did", did)
        .with_attr("rotation_key", key)
        .with_attr("coverage", ROTATION_KEY_CAVEAT),
    );
    e
}
