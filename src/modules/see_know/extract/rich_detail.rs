//! Rich-detail (context) extraction from SeekNow records.
//!
//! Walks the verbose per-record detail object, skipping the noisy fields in
//! `RICH_DETAIL_SKIP`, and emits context (non-PII) entities. Reaches parent
//! helpers/imports via `use super::*`.

use super::*;

/// Field names already turned into typed entities by `extract_entities` (or
/// deliberately suppressed as structural/metadata noise). The catch-all pass
/// skips these so it only emits the *long tail* — every other value-bearing
/// field — without duplicating a node already created or surfacing envelope
/// bookkeeping. Lower-cased compare so schema casing variants can't leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    // Already typed above.
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
    // Provider-internal record IDs — snusbase/see_know stamp a `uid` and a
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
    // Domain WHOIS/RDAP metadata — surfaced as Domain *attributes* by
    // `rdap_domain` / `whoisxml`, not worth duplicating as standalone graph
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
/// replaces the prior linear scan of ~90 `&str` entries without changing which
/// fields are skipped.
static RICH_DETAIL_SKIP_SET: std::sync::LazyLock<HashSet<&'static str>> =
    std::sync::LazyLock::new(|| RICH_DETAIL_SKIP.iter().copied().collect());

/// Push a stealer/infrastructure-CONTEXT entity: tags `see-know` plus any
/// `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC, HWID,
/// hostname, …) are infrastructure/context, not leaked PII — the same policy the
/// URL/Domain/Credential spidering follows — so they must not carry the `breach`
/// tag that [`super::push_breach_entity`] forces.
fn push_context_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag("see-know");
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
/// modest (secondary, record-derived) so this breadth never outranks the
/// primary identity entities.
pub(super) fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(obj) = item.as_object() else {
        return;
    };

    // ── Names: first + last → a composed Person (the bare `name`/`full_name`
    // path above only fires when the value already contains a space). ──
    let first = val_str(item, "first_name").or_else(|| val_str(item, "firstname"));
    let last = val_str(item, "last_name").or_else(|| val_str(item, "lastname"));
    if let (Some(f), Some(l)) = (&first, &last) {
        let full = format!("{} {}", f.trim(), l.trim());
        if full.len() >= 3 && seen.insert(format!("@person:{}", full.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Person, &full, 0.60, scan_id),
                ev,
                &[],
            );
        }
    }

    // ── Organisation / employer. ──
    for k in ["company", "employer", "organization", "organisation", "org"] {
        if let Some(o) = val_str(item, k)
            && o.len() >= 2
            && seen.insert(format!("@org:{}", o.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Organisation, &o, 0.50, scan_id),
                ev,
                &[],
            );
        }
    }

    // ── Device fingerprints — strong stealer-log pivots. ──
    for k in ["mac", "mac_address", "bssid"] {
        if let Some(m) = val_str(item, k)
            && m.len() >= 12
            && seen.insert(format!("@mac:{}", m.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::MacAddress, &m, 0.60, scan_id),
                ev,
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
    ] {
        if let Some(d) = val_str(item, k)
            && d.len() >= 3
            && seen.insert(format!("@device:{k}:{}", d.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::DeviceId, &d, 0.55, scan_id),
                ev,
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
            && seen.insert(format!("@{plat}:{}", h.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, format!("{plat}:{h}"), 0.55, scan_id),
                ev,
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
        {
            if seen.insert(format!("@addr-part:{k}:{}", p.to_lowercase())) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Address, &p, 0.45, scan_id),
                    ev,
                    &["geo-hint"],
                );
            }
            addr_parts.push(p);
        }
    }
    if addr_parts.len() >= 2 {
        if let Some(c) = val_str(item, "country") {
            addr_parts.push(c);
        }
        let composed = addr_parts.join(", ");
        if seen.insert(format!("@addr:{}", composed.to_lowercase())) {
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&composed) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.45, scan_id);
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("breach");
                c.tag("see-know");
                c.add_evidence(ev.clone());
                result.push(c);
            }
            push_breach_entity(
                result,
                Entity::new(EntityKind::Address, &composed, 0.55, scan_id),
                ev,
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
        // O(1) set lookup instead of a linear scan of ~90 entries per field.
        // The skip list is all-lowercase; only pay for a lowercased copy when
        // `k` actually contains uppercase ASCII (the common case is already
        // lowercase, so no allocation), preserving the case-insensitive match.
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
        if val.is_empty() || val.len() > 2000 {
            continue;
        }
        if seen.insert(format!("@other:{k}:{}", val.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Other(k.clone()), &val, 0.40, scan_id),
                ev,
                &["raw-field"],
            );
        }
    }
}
