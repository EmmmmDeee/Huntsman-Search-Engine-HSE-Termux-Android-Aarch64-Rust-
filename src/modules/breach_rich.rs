//! Shared "maximum raw data" extractor for breach/stealer records.
//!
//! Both paid breach pools — `see_know` and `oathnet_pro` — receive verbose
//! per-record detail objects (infostealer device fingerprints, social handles,
//! address parts, employer, and a long tail of provider-specific scalar fields).
//! This module turns that long tail into first-class, pivotable entities so
//! nothing valuable stays locked inside the evidence blob (operator directive:
//! "I want everything. Maximum raw data.").
//!
//! It lives here, shared and source-parameterised, so the two providers extract
//! the **same** field set with the **same** semantics — the field knowledge
//! can't drift between them, and a new provider gets the full pass for free. The
//! caller supplies its own `source` tag (`"see-know"` / `"oathnet-pro"`) and the
//! evidence record; entities are pushed at full confidence and the caller
//! applies its own non-target demotion (see_know range-demotes after the call,
//! oathnet per row) — this pass stays demotion-agnostic.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
};
use crate::util::extract::is_placeholder_secret;
use crate::util::json::{is_null_sentinel, val_str};

/// A value that is an *absence/redaction marker*, not real data: a SQL NULL
/// sentinel (`\N`, written for an empty column in dumped exports) or a provider
/// redaction placeholder (`UPGRADE_TO_SEE_FULL`, `REDACTED`, bracketed
/// `[NULL]`/`[FAIL]`…). Such a value must NEVER mint a graph node — two records
/// that each carry `\N`/`REDACTED` in, say, `company` would otherwise both yield
/// an `Organisation("\N")` node and falsely co-occur, poisoning correlation.
fn is_absent_marker(s: &str) -> bool {
    is_null_sentinel(s) || is_placeholder_secret(s)
}

/// A hardware-fingerprint value that is a well-known BIOS/SMBIOS/dmidecode
/// PLACEHOLDER (or a trivial all-zero / broadcast filler), not a real per-machine
/// id. Infostealer logs capture these verbatim from boards whose OEM never burned
/// a real serial, so the SAME string recurs across thousands of UNRELATED
/// machines — typing it as a `DeviceId`/`MacAddress` would defeat AU-106's
/// uniqueness assumption and let a shared placeholder falsely link two strangers
/// as "one physical machine". Compared case-insensitively and whitespace-trimmed.
fn is_placeholder_fingerprint(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    // Trivial all-zero / all-`F` fillers, ignoring separators (`00:00:..`,
    // `00000000`, the null GUID, `FF-FF-..`/broadcast MAC).
    let core: String = t.chars().filter(char::is_ascii_alphanumeric).collect();
    if !core.is_empty()
        && (core.bytes().all(|b| b == b'0') || core.bytes().all(|b| b == b'f' || b == b'F'))
    {
        return true;
    }
    // Documented SMBIOS / dmidecode placeholder strings.
    let u = t.to_ascii_uppercase();
    matches!(
        u.as_str(),
        "TO BE FILLED BY O.E.M."
            | "TO BE FILLED BY OEM."
            | "TO BE FILLED BY OEM"
            | "SYSTEM SERIAL NUMBER"
            | "CHASSIS SERIAL NUMBER"
            | "BASE BOARD SERIAL NUMBER"
            | "DEFAULT STRING"
            | "NOT SPECIFIED"
            | "NOT APPLICABLE"
            | "NOT AVAILABLE"
            | "SERIAL NUMBER"
            | "SYSTEM MANUFACTURER"
            | "SYSTEM PRODUCT NAME"
            | "DEFAULT"
            | "NONE"
            | "UNKNOWN"
            | "O.E.M."
            | "OEM"
            | "STANDARD"
            | "INVALID"
            | "N/A"
            | "NA"
            | "NULL"
    )
}

/// Field names already turned into typed entities by the providers' primary
/// extractors (or deliberately suppressed as structural/metadata noise). The
/// catch-all pass skips these so it only emits the *long tail* — every other
/// value-bearing field — without duplicating a node already created or surfacing
/// envelope bookkeeping. Lower-cased compare so schema casing variants can't
/// leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    // Already typed by the primary identity/credential extractors.
    "email",
    "username",
    "phone",
    "phone_number",
    "full_name",
    "name",
    "ip",
    "country",
    "discord_id",
    "discordid",
    "steam_id",
    "steamid",
    "steam_id64",
    "password",
    "passwordhash",
    "password_hash",
    "hashed_password",
    "hash",
    "url",
    "url_str",
    "domain",
    // Composed/typed in the rich pass itself.
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "company",
    "employer",
    "organization",
    "organisation",
    "org",
    "mac",
    "mac_address",
    "bssid",
    "hwid",
    "machine_id",
    "device_id",
    "uuid",
    "guid",
    "computer_name",
    "machine",
    "hostname",
    "imei",
    "serial",
    "serial_number",
    "device_serial",
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    "city",
    "state",
    "region",
    "province",
    "zip",
    "zipcode",
    "postal",
    "postal_code",
    "postcode",
    "street",
    "address",
    "address_line",
    // Structural / metadata / provenance bookkeeping (kept verbatim on evidence,
    // but not worth a standalone graph node).
    "source",
    "source_db",
    "dbname",
    "_origin",
    "id",
    "_id",
    // Provider-internal record IDs — the pools stamp a `uid` and a
    // `migration_id` on every row (their own database keys, not the subject's).
    // Left un-skipped they leaked as `Other("uid")` / `Other("migration_id")`
    // junk nodes — one per record — diluting the graph with plumbing.
    "uid",
    "migration_id",
    "log_id",
    "log",
    "salt",
    "response_time_ms",
    "type",
    "success",
    "total",
    "breach_count",
    "stealer_count",
    "external_count",
    "index",
    "score",
    "_score",
    // Domain WHOIS/RDAP metadata — surfaced as Domain *attributes* by the
    // dedicated DNS/RDAP modules, not worth duplicating as standalone graph
    // nodes (and `dns` is a record map, never an entity value).
    "registrar",
    "dns",
    "nameservers",
    "name_servers",
    "created",
    "created_date",
    "creation_date",
    "updated",
    "updated_date",
    "last_changed",
    "expires",
    "expiry",
    "expiration_date",
    "status",
    "whois",
];

/// `O(1)` membership view over [`RICH_DETAIL_SKIP`], built once on first use.
/// The catch-all pass runs this lookup per field per record, so a `HashSet`
/// replaces a linear scan of the ~100 `&str` entries.
static RICH_DETAIL_SKIP_SET: std::sync::LazyLock<HashSet<&'static str>> =
    std::sync::LazyLock::new(|| RICH_DETAIL_SKIP.iter().copied().collect());

/// Push a breach-PII entity: tags `breach`, the provider `source`, plus any
/// `extra_tags`, then a cloned evidence record. (Source-sector tagging is
/// applied universally at engine admission, so it is not done per-module.)
fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    source: &str,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag(source);
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Push a stealer/infrastructure-CONTEXT entity: tags the provider `source` plus
/// any `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC,
/// HWID, hostname, …) are infrastructure/context, not leaked PII.
fn push_context_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    source: &str,
    extra_tags: &[&str],
) {
    e.tag(source);
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Maximum-raw-data extractor: turn the long tail of a breach/stealer record
/// into first-class, pivotable entities. Typed where a kind fits (Person,
/// Organisation, Address, MacAddress, DeviceId, platform Usernames), and
/// `Other(field)` for everything else — so EVERY value-bearing field of the raw
/// response becomes a node, not just an evidence attribute. Confidences are
/// modest (secondary, record-derived) so this breadth never outranks the primary
/// identity entities. Pushes at full confidence; the caller demotes non-target
/// rows in its own idiom.
pub fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    source: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(obj) = item.as_object() else {
        return;
    };

    // ── Names: first + last → a composed Person (the bare `name`/`full_name`
    // path only fires when the value already contains a space). ──
    let first = val_str(item, "first_name").or_else(|| val_str(item, "firstname"));
    let last = val_str(item, "last_name").or_else(|| val_str(item, "lastname"));
    if let (Some(f), Some(l)) = (&first, &last) {
        let full = format!("{} {}", f.trim(), l.trim());
        // A SQL NULL (`\N`) or redaction marker in either name component is
        // absence, not a name — never compose a `"\N \N"` (nor a half-real
        // `"\N Smith"` / `"REDACTED Smith"`) Person from it.
        if full.len() >= 3
            && !is_absent_marker(f)
            && !is_absent_marker(l)
            && seen.insert(format!("@person:{}", full.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Person, &full, confidence::MEDIUM_PLUS, scan_id),
                ev,
                source,
                &[],
            );
        }
    }

    // ── Organisation / employer. ──
    for k in ["company", "employer", "organization", "organisation", "org"] {
        if let Some(o) = val_str(item, k)
            && o.len() >= 2
            && !is_absent_marker(&o)
            && seen.insert(format!("@org:{}", o.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Organisation, &o, confidence::MEDIUM, scan_id),
                ev,
                source,
                &[],
            );
        }
    }

    // ── Device fingerprints — strong stealer-log pivots. ──
    for k in ["mac", "mac_address", "bssid"] {
        if let Some(m) = val_str(item, k)
            && m.len() >= 12
            && !is_absent_marker(&m)
            && !is_placeholder_fingerprint(&m)
            && seen.insert(format!("@mac:{}", m.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::MacAddress, &m, confidence::MEDIUM_PLUS, scan_id),
                ev,
                source,
                &["device"],
            );
        }
    }
    for k in [
        "hwid",
        "machine_id",
        "device_id",
        "uuid",
        "guid",
        "computer_name",
        "machine",
        "hostname",
        // Hardware serials / mobile equipment ids — globally-unique device
        // anchors. A shared IMEI/serial across ≥2 accounts is strong single-device
        // co-location proof; typed as DeviceId so AU-106 (shared-device identity)
        // consumes them. (Also in RICH_DETAIL_SKIP so the catch-all does not also
        // mint a duplicate `Other("imei")` from the distinct `@other:` namespace.)
        "imei",
        "serial",
        "serial_number",
        "device_serial",
    ] {
        if let Some(d) = val_str(item, k)
            && d.len() >= 3
            && !is_absent_marker(&d)
            && !is_placeholder_fingerprint(&d)
            && seen.insert(format!("@device:{k}:{}", d.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::DeviceId, &d, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &["device", "stealer"],
            );
        }
    }

    // ── Extra social handles → platform-prefixed Username pivots. ──
    for (k, plat) in [
        ("telegram", "telegram"),
        ("skype", "skype"),
        ("facebook", "facebook"),
        ("instagram", "instagram"),
        ("twitter", "twitter"),
        ("linkedin", "linkedin"),
        ("vk", "vk"),
        ("snapchat", "snapchat"),
    ] {
        if let Some(h) = val_str(item, k)
            && h.len() >= 2
            && !is_absent_marker(&h)
            && seen.insert(format!("@{plat}:{}", h.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, format!("{plat}:{h}"), confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &[plat],
            );
        }
    }

    // ── Physical location: each part as its own geo-hint Address, plus a
    // composed multi-part address (street/city/state/postal/country). ──
    let mut addr_parts: Vec<String> = Vec::new();
    for k in [
        "street",
        "address",
        "address_line",
        "city",
        "state",
        "region",
        "province",
        "zip",
        "zipcode",
        "postal",
        "postal_code",
        "postcode",
    ] {
        if let Some(p) = val_str(item, k)
            && p.len() >= 2
            && !is_absent_marker(&p)
        {
            if seen.insert(format!("@addr-part:{k}:{}", p.to_lowercase())) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Address, &p, confidence::LOW_MEDIUM, scan_id),
                    ev,
                    source,
                    &["geo-hint"],
                );
            }
            addr_parts.push(p);
        }
    }
    if addr_parts.len() >= 2 {
        if let Some(c) = val_str(item, "country")
            && !is_absent_marker(&c)
        {
            addr_parts.push(c);
        }
        let composed = addr_parts.join(", ");
        if seen.insert(format!("@addr:{}", composed.to_lowercase())) {
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&composed) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, confidence::LOW_MEDIUM, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag(tags::BREACH);
                c.tag(source);
                c.add_evidence(ev.clone());
                result.push(c);
            }
            push_breach_entity(
                result,
                Entity::new(EntityKind::Address, &composed, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &["geo-hint", "composed-address"],
            );
        }
    }

    // ── Catch-all: every remaining value-bearing SCALAR field becomes an
    // `Other(field)` node, so no atomic data point in the raw record is left
    // un-surfaced. Nested objects/arrays are NOT turned into entities — a
    // stringified JSON blob (e.g. a `dns` record map) is not a meaningful graph
    // node and only pollutes the entity set; its atomic contents are surfaced by
    // the typed paths above and by the dedicated DNS/RDAP modules. ──
    for (k, v) in obj {
        // O(1) set lookup; the skip list is all-lowercase, so only pay for a
        // lowercased copy when `k` actually contains uppercase ASCII (the common
        // case is already lowercase → no allocation).
        let skip = if k.bytes().any(|b| b.is_ascii_uppercase()) {
            RICH_DETAIL_SKIP_SET.contains(k.to_lowercase().as_str())
        } else {
            RICH_DETAIL_SKIP_SET.contains(k.as_str())
        };
        if skip {
            continue;
        }
        let val = match v {
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
        };
        if val.is_empty() || val.len() > 2000 || is_absent_marker(&val) {
            continue;
        }
        if seen.insert(format!("@other:{k}:{}", val.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Other(k.clone()), &val, confidence::LOW, scan_id),
                ev,
                source,
                &["raw-field"],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    include!("breach_rich_tests.rs");
}
