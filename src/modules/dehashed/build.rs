//! Pure helpers for DeHashed entity construction.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    scan::TargetKind,
    tags,
};
use crate::util::target_match::TargetMatch;

pub(super) const SRC: &str = "dehashed";

/// Top breach databases to surface by frequency.
pub(super) const MAX_DATABASES: usize = 5;

/// The DeHashed query selector for a target kind, or `None` for a kind this
/// module does not search. **Pure** — kept in lockstep with [`super::DeHashed`]'s
/// `accepts` implementation.
/// The v2 selector syntax is unchanged from v1 (`email:`, `username:`, …).
pub(super) fn selector_for(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "email",
        TargetKind::Username => "username",
        TargetKind::Phone => "phone",
        TargetKind::FullName => "name",
        TargetKind::IpAddress => "ip_address",
        TargetKind::Domain => "domain",
        _ => return None,
    })
}

/// Flatten a v2 `database_name` value (`string | [string] | null`) into the
/// source-database names it carries. Non-string array members are skipped.
pub(super) fn db_names(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Render the v2 `balance` value for display, accepting either a JSON number
/// or string and rejecting anything else (or a blank string) as absent.
pub(super) fn balance_str(v: &Option<Value>) -> Option<String> {
    match v {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

/// The source database(s) a single v2 record came from, joined for display.
fn record_dbname(item: &Value) -> String {
    let names = item.get("database_name").map(db_names).unwrap_or_default();
    if names.is_empty() {
        "dehashed".to_string()
    } else {
        names.join(", ")
    }
}

/// Every non-empty string a v2 field carries. v2 wraps most fields in an ARRAY
/// (`"email": ["a@b.com"]`, `"hashed_password": ["5f4d…"]`) and a record can hold
/// several values per field (multiple emails/passwords), so this returns ALL of
/// them — a bare string, every string member of an array, or a stringified
/// number. Nothing is dropped to the first element.
fn field_strings(item: &Value, key: &str) -> Vec<String> {
    match item.get(key) {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Number(n)) => vec![n.to_string()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                Value::String(s) if !s.is_empty() => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A scalar-flattened view of a v2 record: each array field collapses to its sole
/// member (or its members joined by `", "`), so the shared scalar-oriented
/// helpers — `val_str`, and above all [`crate::modules::breach_rich::extract_rich_detail`]
/// — see the same flat shape OathNet/SeekNow records arrive in, and a single hash
/// reads as the bare digest (`5f4d…`, not `["5f4d…"]`) so it matches the same hash
/// from another provider for AU-105 linking.
fn flatten_record(item: &Value) -> Value {
    let Some(obj) = item.as_object() else {
        return item.clone();
    };
    let flat: serde_json::Map<String, Value> = obj
        .iter()
        .map(|(k, v)| {
            let nv = match v {
                Value::Array(_) => {
                    let strs = field_strings(item, k);
                    match strs.len() {
                        0 => v.clone(),
                        1 => Value::String(strs.into_iter().next().unwrap()),
                        _ => Value::String(strs.join(", ")),
                    }
                }
                other => other.clone(),
            };
            (k.clone(), nv)
        })
        .collect();
    Value::Object(flat)
}

/// Build the subject's breach-presence **headline** entity from a v2 response, or
/// `None` when nothing in the response is attributable to the subject. **Pure**
/// (no network/IO).
///
/// No-fabrication gate. The engine pre-seeds a subject anchor, so minting a confidence::EXPERT
/// `breach`-tagged headline that doesn't reflect the subject would merge a false
/// "breach hit" straight onto that anchor — the exact failure `oathnet_pro`'s
/// `breach_parent_entity` guards against by returning `None` on a zero-match
/// page. DeHashed's selectors split cleanly:
/// - **identity-exact** (`email`/`username`/`phone`/`ip_address`/`domain`) match
///   the queried value EXACTLY, so every returned row is that value and the
///   server's `total` (which can exceed `entries.len()`) is a true count for it —
///   a count-only response is still a genuine signal.
/// - **`name`** is the sole loose selector: a `name:` query returns same-name
///   STRANGERS, so only the rows that actually match the subject count, aggregates
///   fold over those rows only, and a bare count with no rows to verify is not
///   attributable to the subject at all (→ `None`).
///
/// The per-record identity/credential detail is surfaced separately by
/// [`extract_records`], which quarantines strangers independently.
#[must_use]
pub(super) fn build_breach_entity(
    kind: EntityKind,
    value: &str,
    selector: &str,
    entries: &[Value],
    total: u64,
    balance: Option<&str>,
    scan_id: &str,
) -> Option<Entity> {
    // `name` is DeHashed's only selector that can return strangers; every other
    // selector matches `value` exactly, so its `total` needs no per-row proof.
    let is_exact = selector != "name";
    let (hits, rows): (u64, Vec<&Value>) = if is_exact {
        (total, entries.iter().collect())
    } else {
        let matcher = TargetMatch::new(value);
        let matching: Vec<&Value> = entries
            .iter()
            .filter(|item| matcher.matches(&flatten_record(item)))
            .collect();
        (matching.len() as u64, matching)
    };
    // Gate: never mint the confidence::EXPERT breach headline off a subject-less response.
    if hits == 0 {
        return None;
    }

    let mut entity = Entity::new(kind, value, confidence::EXPERT, scan_id);
    entity.tag(tags::BREACH);
    entity.tag("dehashed");

    // Top databases by frequency. v2 lists a record's source(s) in
    // `database_name` (an array), so flatten across the counted rows.
    let top = crate::util::freq::top_n(
        rows.iter()
            .flat_map(|e| e.get("database_name").map(db_names).unwrap_or_default()),
        MAX_DATABASES,
    );

    let mut ev = Evidence::new(
        SRC,
        format!("DeHashed: {hits} breach record(s) for {selector}={value}"),
    )
    .with_attr("hits", hits.to_string())
    .with_attr("returned", entries.len().to_string())
    .with_attr("selector", selector);
    if !top.is_empty() {
        ev = ev.with_attr("top_databases", top);
    }
    if let Some(b) = balance {
        ev = ev.with_attr("credit_balance", b);
    }
    entity.add_evidence(ev);
    Some(entity)
}

/// Build the full-fidelity evidence for a single record: EVERY scalar field of
/// the raw v2 record is preserved as an attribute — nothing redacted, truncated,
/// or omitted — plus the provenance (`provider`, the elided `api_key_origin`
/// fingerprint, and the source database). This is what carries the `password` /
/// `hashed_password` the hash-reuse identity linker (AU-105, which reads the
/// `hashed_password` / `password_hash` / `hash` attributes) and reverse-search
/// operate on, and what makes a finding traceable to its exact source record.
fn record_evidence(item: &Value, key_fp: &str) -> Evidence {
    let db = record_dbname(item);
    let ev = Evidence::new(SRC, format!("DeHashed record from {db}"))
        // `dbname` is the canonical breach-name attribute the credential-reuse
        // correlator (AU-105) groups on; without it AU-105 falls back to the
        // Evidence `source` FIELD (the module name "dehashed") and collapses
        // every DeHashed record into one pseudo-breach, so cross-breach reuse
        // among a subject's DeHashed hits could never fire. `source` is retained
        // (existing consumers read it) but is an attribute, not the field
        // AU-105's fallback inspects — hence both are stamped.
        .with_attr("dbname", db.as_str())
        .with_attr("source", db)
        .with_attr("provider", "dehashed.com")
        .with_attr("api_key_origin", key_fp);
    let Some(obj) = item.as_object() else {
        return ev;
    };
    obj.iter().fold(ev, |ev, (k, v)| {
        let val = match v {
            Value::Null => return ev,
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if val.is_empty() {
            return ev;
        }
        // Don't clobber the canonical `source` attribute set above.
        let key = if k == "source" {
            "source_db"
        } else {
            k.as_str()
        };
        ev.with_attr(key, val)
    })
}

/// Apply the breach tags (`breach`, `dehashed`, plus any `extra_tags`) and a
/// cloned evidence record to `e`, then push it onto `result`.
fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag("dehashed");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Turn every DeHashed record into first-class, pivotable entities — identity
/// (email / username / phone / Person / ip), the credential secret (plaintext
/// `password` and the `hashed_password` digest, as `Password` entities), and the
/// full long tail (name parts, address, device, social handles, every remaining
/// scalar) via the shared [`crate::modules::breach_rich::extract_rich_detail`].
///
/// A broad search — above all a `name` query — returns same-name STRANGERS; the
/// entities a non-target record yields are demoted to quarantined `candidate`
/// leads (the same demotion `oathnet_pro` / `see_know` apply), so they survive
/// for transparency but never masquerade as the subject. The subject's own rows
/// stay first-class — including the hash that links their accounts across
/// sources. Nothing is deleted; nothing is omitted.
pub(super) fn extract_records(
    entries: &[Value],
    target_value: &str,
    key_fp: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let matcher = TargetMatch::new(target_value);
    for item in entries {
        // Scalar-flattened view for the evidence fold, the target match, and the
        // shared rich-detail pass; the original `item` (arrays intact) feeds the
        // per-value identity loops so a record with several emails/passwords
        // surfaces every one of them.
        let flat = flatten_record(item);
        let ev = record_evidence(&flat, key_fp);
        let is_target = matcher.matches(&flat);
        let quarantine_start = result.entities.len();

        for email in field_strings(item, "email") {
            let lower = email.to_lowercase();
            if crate::util::extract::looks_like_email(&lower) && seen.insert(lower) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Email, &email, confidence::HIGH_PLUS, scan_id),
                    &ev,
                    &[],
                );
            }
        }
        for uname in field_strings(item, "username") {
            let lower = uname.to_lowercase();
            if lower.len() >= 3 && seen.insert(lower) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Username, &uname, confidence::HIGH, scan_id),
                    &ev,
                    &[],
                );
            }
        }
        for phone in field_strings(item, "phone")
            .into_iter()
            .chain(field_strings(item, "phone_number"))
        {
            if phone.len() >= 7 && seen.insert(phone.to_lowercase()) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Phone, &phone, confidence::MEDIUM_PLUS, scan_id),
                    &ev,
                    &[],
                );
            }
        }
        for name in field_strings(item, "name")
            .into_iter()
            .chain(field_strings(item, "full_name"))
        {
            if name.trim().contains(' ')
                && !crate::util::json::is_null_sentinel(&name)
                && seen.insert(name.to_lowercase())
            {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Person, name.trim(), confidence::HIGH, scan_id),
                    &ev,
                    &[],
                );
            }
        }
        for ip_field in ["ip_address", "ip", "last_ip"] {
            for ip in field_strings(item, ip_field) {
                if crate::util::preflight::is_public_ip(&ip) && seen.insert(ip.clone()) {
                    push_breach_entity(
                        result,
                        Entity::new(EntityKind::IpAddress, &ip, confidence::MEDIUM_PLUS, scan_id),
                        &ev,
                        &["geolocation-lead"],
                    );
                }
            }
        }

        // Credential secrets — the data DeHashed exists to provide. A `Password`
        // entity for each hash digest makes it a reverse-searchable node and an
        // AU-105 hash-reuse link key; the plaintext `password` is the stronger
        // reuse signal. Both also ride on the per-record evidence above (so even
        // the email/username entities carry the hash attribute the linker reads).
        for hash_field in ["hashed_password", "password_hash", "hash"] {
            for h in field_strings(item, hash_field) {
                let h = h.trim();
                if h.len() >= 8 && seen.insert(format!("@pwhash:{}", h.to_lowercase())) {
                    // Offline hash intelligence ("hashcat-lite"): algorithm,
                    // crackability, appended salt, and an offline reverse-lookup of
                    // common-password digests — all pure, no network, no GPU.
                    let mut tags: Vec<String> = vec!["password-hash".to_string()];
                    if let Some((algo, fast)) = crate::util::hashcat::identify_hash(h) {
                        tags.push(format!("hash:{algo}"));
                        tags.push(
                            if fast {
                                "crackable:fast"
                            } else {
                                "crackable:slow"
                            }
                            .to_string(),
                        );
                    }
                    if crate::util::hashcat::is_salted(h) {
                        tags.push("salted".to_string());
                    }
                    let cracked = crate::util::hashcat::crack_common(h);
                    if cracked.is_some() {
                        tags.push("cracked".to_string());
                    }
                    let tag_refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                    push_breach_entity(
                        result,
                        Entity::new(EntityKind::Password, h, confidence::MEDIUM_HIGH, scan_id),
                        &ev,
                        &tag_refs,
                    );
                    // Synergy: a recovered plaintext is the subject's weak password
                    // laid bare — surface it as a first-class node for the dossier.
                    if let Some(pt) = cracked
                        && seen.insert(format!("@pw:{}", pt.to_lowercase()))
                    {
                        push_breach_entity(
                            result,
                            Entity::new(EntityKind::Password, pt, confidence::MEDIUM_PLUS, scan_id),
                            &ev,
                            &["cracked", "weak-password", "from-hash"],
                        );
                    }
                }
            }
        }
        for pw in field_strings(item, "password") {
            let p = pw.trim();
            match crate::util::extract::classify_credential_field(p) {
                // A capture sentinel ([fail], UPGRADE_TO_SEE…) is not a secret — drop it.
                crate::util::extract::CredentialField::Sentinel => {}
                // An email mis-stored in the password slot is a lead, not a secret:
                // minting it as a Password would forge a reused-secret link across every
                // row with the same quirk. Recover it into the email pipeline at modest
                // confidence — the same recovery oathnet_pro / see_know already do, so
                // the three breach parsers don't drift on this quirk.
                crate::util::extract::CredentialField::Email => {
                    let lower = p.to_lowercase();
                    if seen.insert(format!("@pw-email:{lower}")) {
                        push_breach_entity(
                            result,
                            Entity::new(EntityKind::Email, p, confidence::LOW_MEDIUM, scan_id),
                            &ev,
                            &["recovered-from-password"],
                        );
                    }
                }
                crate::util::extract::CredentialField::Secret => {
                    if p.chars().count() >= 4 && seen.insert(format!("@pw:{}", p.to_lowercase())) {
                        push_breach_entity(
                            result,
                            Entity::new(EntityKind::Password, p, confidence::MEDIUM_PLUS, scan_id),
                            &ev,
                            &["plaintext-password"],
                        );
                    }
                }
            }
        }

        // Long tail: names, full address, organisation, device fingerprints,
        // extra social handles, and EVERY remaining scalar field — the shared
        // "maximum raw data" pass the other paid pools use, so DeHashed surfaces
        // the identical field set with the identical semantics.
        crate::modules::breach_rich::extract_rich_detail(&flat, scan_id, SRC, &ev, seen, result);

        // A non-matching stranger's entities are demoted to quarantined
        // candidate leads — retained for transparency, never the subject.
        if !is_target {
            for e in &mut result.entities[quarantine_start..] {
                e.demote_to_candidate();
            }
        }
    }
}
