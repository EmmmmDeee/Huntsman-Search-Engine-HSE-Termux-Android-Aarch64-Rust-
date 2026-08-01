//! STIX 2.1 bundle export — a scan's entities, typed relations, and correlation
//! findings serialised as a STIX 2.1 JSON bundle for threat-intelligence
//! interchange.
//!
//! STIX (Structured Threat Information eXpression) 2.1 is the OASIS standard the
//! defensive-TI ecosystem speaks: MISP, OpenCTI, ATT&CK Workbench, TheHive, and
//! every TAXII 2.1 server ingest it directly. Emitting it makes an HSE scan a
//! first-class citizen of that ecosystem — an operator can push a person /
//! domain / infrastructure dossier straight into their SIEM or CTI platform
//! instead of hand-transcribing a CSV. It is the interoperability counterpart of
//! [`crate::core::gexf`] (which targets Gephi/Cytoscape link-analysis); both are
//! pure, offline serialisers of the same entity + relation graph.
//!
//! # Mapping
//! Each HSE [`Entity`] becomes the closest native STIX object:
//!
//! | HSE kind | STIX object |
//! |----------|-------------|
//! | `IpAddress` | `ipv4-addr` / `ipv6-addr` (SCO) |
//! | `Domain` | `domain-name` (SCO) |
//! | `Url` | `url` (SCO) |
//! | `Email` | `email-addr` (SCO) |
//! | `MacAddress` | `mac-addr` (SCO) |
//! | `Username` | `user-account` (SCO) |
//! | `Asn` | `autonomous-system` (SCO) |
//! | `Person` | `identity` (`identity_class = individual`) |
//! | `Organisation` | `identity` (`identity_class = organization`) |
//! | `Coordinates` | `location` (latitude/longitude) |
//! | everything else | `x-huntsman-artifact` (custom SCO) |
//!
//! Typed [`Relation`]s become `relationship` SROs; correlator findings
//! ([`Correlation`]) become `note` SDOs referencing their child objects; and a
//! top-level `report` SDO ties the whole scan together. Every object also
//! carries HSE's own confidence / classification / provenance as STIX custom
//! (`x_huntsman_*`) properties, so no signal is lost in translation.
//!
//! # Determinism
//! The export reads **no wall clock** and generates **no random UUIDs**: every
//! object id is a content-derived UUID (a SHA-256 of the entity's own
//! deterministic uid, shaped into a valid UUIDv5), and every timestamp comes
//! from the scan's own immutable `started_at` / the entity's `observed_at`. So
//! re-exporting an unchanged scan yields a **byte-identical** bundle — it
//! `diff`s cleanly across runs and tools, the same reproducibility contract the
//! debug bundle holds. Content-derived ids also mean the SAME entity always maps
//! to the SAME STIX id, exactly as STIX 2.1's deterministic-id guidance for
//! Cyber Observables intends.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::core::correlator::Correlation;
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::Relation;
use crate::core::scan::Scan;

/// The STIX specification version every SDO/SRO declares.
const SPEC_VERSION: &str = "2.1";

/// Serialise a scan's entities (STIX objects), typed relations (SROs), and
/// correlation findings (notes) as a STIX 2.1 bundle, framed by a `report` SDO
/// and attributed to a stable HSE producer `identity`.
///
/// Pure and deterministic (see the module docs): identical input ⇒ byte-identical
/// output. `entities` should already be the caller's chosen view (the exporters
/// pass the confirmed, candidate-quarantined set, optionally redacted). A
/// relationship is emitted only when BOTH endpoints are present among
/// `entities` — the same dangling-edge invariant [`crate::core::gexf`] enforces
/// — so a filtered entity subset can never produce an SRO referencing an
/// undeclared object.
#[must_use]
pub fn entities_to_stix(
    entities: &[Entity],
    relations: &[Relation],
    correlations: &[Correlation],
    scan: &Scan,
) -> String {
    // Stable ordering so an unchanged scan serialises byte-identically
    // regardless of the store's row order: by kind, then value, then uid.
    let mut ents: Vec<&Entity> = entities.iter().collect();
    ents.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.uid.cmp(&b.uid))
    });

    let scan_ts = scan.started_at;
    let producer = producer_id();

    let mut objects: Vec<Value> =
        Vec::with_capacity(ents.len() + relations.len() + correlations.len() + 2);
    // Every object id, in emission order — becomes the report's `object_refs`.
    let mut object_refs: Vec<String> = Vec::new();

    // 1. The producer identity — `created_by_ref` for every SDO/SRO below.
    objects.push(producer_identity(&producer, scan_ts));
    object_refs.push(producer.clone());

    // 2. One STIX object per entity; remember uid → STIX id for edge wiring.
    let mut id_of: HashMap<&str, String> = HashMap::with_capacity(ents.len());
    for e in &ents {
        let (stix_id, obj) = entity_object(e, scan_ts, &producer);
        id_of.insert(e.uid.as_str(), stix_id.clone());
        object_refs.push(stix_id);
        objects.push(obj);
    }

    // 3. Typed relations → `relationship` SROs (both endpoints must be present).
    let mut rels: Vec<&Relation> = relations.iter().collect();
    rels.sort_by(|a, b| {
        a.from_uid
            .cmp(&b.from_uid)
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
            .then_with(|| a.to_uid.cmp(&b.to_uid))
    });
    for r in &rels {
        if let (Some(src), Some(tgt)) =
            (id_of.get(r.from_uid.as_str()), id_of.get(r.to_uid.as_str()))
        {
            let (rid, obj) = relationship_object(r, src, tgt, scan_ts, &producer);
            object_refs.push(rid);
            objects.push(obj);
        }
    }

    // 4. Correlator findings → `note` SDOs (skipped when none of the finding's
    //    child entities survived into the exported set — a note MUST reference
    //    at least one object).
    let mut corrs: Vec<&Correlation> = correlations.iter().collect();
    corrs.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then_with(|| a.description.cmp(&b.description))
    });
    for c in &corrs {
        let refs: Vec<String> = c
            .entity_uids
            .iter()
            .filter_map(|u| id_of.get(u.as_str()).cloned())
            .collect();
        if refs.is_empty() {
            continue;
        }
        let (nid, obj) = note_object(c, &refs, scan_ts, &producer);
        object_refs.push(nid);
        objects.push(obj);
    }

    // 5. The framing `report` — references every object above.
    objects.push(report_object(scan, &producer, &object_refs, scan_ts));

    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", det_uuid(&format!("bundle:{}", scan.id))),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string())
}

// ─── Object builders ─────────────────────────────────────────────────────────

/// The stable HSE producer id — a fixed content-derived UUID so every scan's
/// bundle attributes to the same `identity`.
fn producer_id() -> String {
    format!("identity--{}", det_uuid("huntsman-search-engine-producer"))
}

/// The HSE producer `identity` SDO (`identity_class = system`).
fn producer_identity(id: &str, scan_ts: u64) -> Value {
    let ts = rfc3339(scan_ts);
    json!({
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": id,
        "created": ts,
        "modified": ts,
        "name": "Huntsman Search Engine",
        "identity_class": "system",
        "description": "On-device OSINT/GEOINT reconnaissance engine (Termux aarch64).",
    })
}

/// Map one entity to its `(stix_id, object)` pair.
fn entity_object(e: &Entity, scan_ts: u64, producer: &str) -> (String, Value) {
    match &e.kind {
        EntityKind::IpAddress => {
            // Colon ⇒ IPv6; otherwise IPv4. HSE only ever stores syntactically
            // valid addresses, so the shape test is sufficient.
            let typ = if e.value.contains(':') {
                "ipv6-addr"
            } else {
                "ipv4-addr"
            };
            sco(typ, e, "value", json!(e.value))
        }
        EntityKind::Domain => sco("domain-name", e, "value", json!(e.value)),
        EntityKind::Url => sco("url", e, "value", json!(e.value)),
        EntityKind::Email => sco("email-addr", e, "value", json!(e.value)),
        // STIX mac-addr values are lowercase colon-separated by spec.
        EntityKind::MacAddress => sco("mac-addr", e, "value", json!(e.value.to_lowercase())),
        EntityKind::Username => sco("user-account", e, "account_login", json!(e.value)),
        EntityKind::Asn => match parse_asn(&e.value) {
            Some(n) => sco("autonomous-system", e, "number", json!(n)),
            None => artifact(e),
        },
        EntityKind::Person => identity(e, "individual", scan_ts, producer),
        EntityKind::Organisation => identity(e, "organization", scan_ts, producer),
        EntityKind::Coordinates => match parse_coords(&e.value) {
            Some((lat, lon)) => location(e, lat, lon, scan_ts, producer),
            None => artifact(e),
        },
        // Phone, Credential, ApiKey, Password, Cidr, Address, AbnAcn, DeviceId,
        // Ssid, TrackingId, CryptoAddress, Other — no native SCO; the custom
        // `x-huntsman-artifact` carries them (always valid STIX 2.1).
        _ => artifact(e),
    }
}

/// A native STIX Cyber Observable (`ipv4-addr`, `domain-name`, …). `key`/`value`
/// is the observable's defining property; HSE metadata rides as `x_huntsman_*`.
fn sco(stix_type: &str, e: &Entity, key: &str, value: Value) -> (String, Value) {
    let id = format!("{stix_type}--{}", det_uuid(&e.uid));
    let mut m = Map::new();
    m.insert("type".to_string(), json!(stix_type));
    m.insert("id".to_string(), json!(id));
    m.insert(key.to_string(), value);
    add_huntsman_props(&mut m, e);
    (id, Value::Object(m))
}

/// A custom STIX Cyber Observable (`x-`-prefixed type, valid per STIX 2.1 §11.3)
/// for HSE entity kinds with no native SCO — the value is preserved on the
/// standard `x_huntsman_value` property so a generic consumer still sees it.
fn artifact(e: &Entity) -> (String, Value) {
    let id = format!("x-huntsman-artifact--{}", det_uuid(&e.uid));
    let mut m = Map::new();
    m.insert("type".to_string(), json!("x-huntsman-artifact"));
    m.insert("id".to_string(), json!(id));
    add_huntsman_props(&mut m, e);
    (id, Value::Object(m))
}

/// An `identity` SDO for a Person / Organisation entity.
fn identity(e: &Entity, class: &str, scan_ts: u64, producer: &str) -> (String, Value) {
    let id = format!("identity--{}", det_uuid(&e.uid));
    let ts = rfc3339(ts_or(e.observed_at, scan_ts));
    let mut m = sdo_common("identity", &id, &ts, producer);
    m.insert("name".to_string(), json!(e.value));
    m.insert("identity_class".to_string(), json!(class));
    add_confidence(&mut m, e.c_effective());
    add_huntsman_props(&mut m, e);
    (id, Value::Object(m))
}

/// A `location` SDO for a Coordinates entity (latitude/longitude, WGS 84).
fn location(e: &Entity, lat: f64, lon: f64, scan_ts: u64, producer: &str) -> (String, Value) {
    let id = format!("location--{}", det_uuid(&e.uid));
    let ts = rfc3339(ts_or(e.observed_at, scan_ts));
    let mut m = sdo_common("location", &id, &ts, producer);
    m.insert("latitude".to_string(), json!(lat));
    m.insert("longitude".to_string(), json!(lon));
    add_confidence(&mut m, e.c_effective());
    add_huntsman_props(&mut m, e);
    (id, Value::Object(m))
}

/// A `relationship` SRO between two already-emitted objects.
fn relationship_object(
    r: &Relation,
    source_ref: &str,
    target_ref: &str,
    scan_ts: u64,
    producer: &str,
) -> (String, Value) {
    let seed = format!("rel:{}:{}:{}", r.from_uid, r.kind.as_str(), r.to_uid);
    let id = format!("relationship--{}", det_uuid(&seed));
    let ts = rfc3339(scan_ts);
    let mut m = sdo_common("relationship", &id, &ts, producer);
    // STIX relationship_type is `[a-z0-9-]+`; the HSE snake_case kind hyphenated
    // (`resolves_to` → `resolves-to`) is a valid, self-descriptive value. The
    // exact HSE kind is also kept verbatim as a custom property.
    m.insert(
        "relationship_type".to_string(),
        json!(r.kind.as_str().replace('_', "-")),
    );
    m.insert("source_ref".to_string(), json!(source_ref));
    m.insert("target_ref".to_string(), json!(target_ref));
    m.insert(
        "x_huntsman_relation_kind".to_string(),
        json!(r.kind.as_str()),
    );
    add_confidence(&mut m, r.confidence);
    (id, Value::Object(m))
}

/// A `note` SDO carrying one correlator finding, referencing its child objects.
fn note_object(c: &Correlation, refs: &[String], scan_ts: u64, producer: &str) -> (String, Value) {
    // Seed the id on the rule + the finding's (sorted) child uids so distinct
    // findings of the same rule get distinct, stable ids.
    let mut uids = c.entity_uids.clone();
    uids.sort();
    let seed = format!("note:{}:{}", c.rule_id, uids.join(","));
    let id = format!("note--{}", det_uuid(&seed));
    let ts = rfc3339(scan_ts);
    let mut m = sdo_common("note", &id, &ts, producer);
    m.insert(
        "abstract".to_string(),
        json!(format!("[{}] {} ({})", c.rule_id, c.rule_name, c.severity)),
    );
    m.insert("content".to_string(), json!(c.description));
    m.insert("object_refs".to_string(), json!(refs));
    m.insert("x_huntsman_rule_id".to_string(), json!(c.rule_id));
    m.insert(
        "x_huntsman_severity".to_string(),
        json!(c.severity.to_string()),
    );
    m.insert(
        "x_huntsman_rank".to_string(),
        json!((c.rank * 1000.0).round() / 1000.0),
    );
    (id, Value::Object(m))
}

/// The framing `report` SDO — one per scan, referencing every other object.
fn report_object(scan: &Scan, producer: &str, object_refs: &[String], scan_ts: u64) -> Value {
    let id = format!("report--{}", det_uuid(&format!("report:{}", scan.id)));
    let ts = rfc3339(scan_ts);
    let mut m = sdo_common("report", &id, &ts, producer);
    m.insert(
        "name".to_string(),
        json!(format!(
            "Huntsman scan {}: {} = {}",
            scan.id,
            scan.target.kind.canonical_str(),
            scan.target.value
        )),
    );
    // OSINT collection ⇒ observed-data (from report-type-ov).
    m.insert("report_types".to_string(), json!(["observed-data"]));
    m.insert("published".to_string(), json!(ts));
    m.insert("object_refs".to_string(), json!(object_refs));
    m.insert("x_huntsman_scan_id".to_string(), json!(scan.id));
    m.insert(
        "x_huntsman_target_kind".to_string(),
        json!(scan.target.kind.canonical_str()),
    );
    m.insert(
        "x_huntsman_target_value".to_string(),
        json!(scan.target.value),
    );
    Value::Object(m)
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

/// The common required properties every HSE-produced SDO/SRO carries.
fn sdo_common(stix_type: &str, id: &str, ts: &str, producer: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".to_string(), json!(stix_type));
    m.insert("spec_version".to_string(), json!(SPEC_VERSION));
    m.insert("id".to_string(), json!(id));
    m.insert("created".to_string(), json!(ts));
    m.insert("modified".to_string(), json!(ts));
    m.insert("created_by_ref".to_string(), json!(producer));
    m
}

/// Attach HSE's own confidence/classification/provenance to any object as STIX
/// custom (`x_huntsman_*`) properties — carried on both SCOs and SDOs so no HSE
/// signal is lost regardless of which STIX shape the entity took.
fn add_huntsman_props(m: &mut Map<String, Value>, e: &Entity) {
    m.insert("x_huntsman_kind".to_string(), json!(e.kind.to_string()));
    m.insert("x_huntsman_value".to_string(), json!(e.value));
    m.insert(
        "x_huntsman_confidence".to_string(),
        json!(pct(e.c_effective())),
    );
    m.insert(
        "x_huntsman_base_confidence".to_string(),
        json!(round3(e.confidence)),
    );
    m.insert(
        "x_huntsman_classification".to_string(),
        json!(e.classify().as_str()),
    );
    m.insert("x_huntsman_generation".to_string(), json!(e.generation));
    m.insert(
        "x_huntsman_source_count".to_string(),
        json!(e.source_count()),
    );
    if !e.tags.is_empty() {
        m.insert("x_huntsman_tags".to_string(), json!(e.tags));
    }
    let attack = attack_techniques(e);
    if !attack.is_empty() {
        m.insert("x_huntsman_attack".to_string(), json!(attack));
    }
}

/// Set the native STIX `confidence` (0–100) when a positive value is known.
/// Omitted at zero so the bundle never asserts a spurious "0 % confidence".
fn add_confidence(m: &mut Map<String, Value>, c: f64) {
    let v = pct(c);
    if v > 0 {
        m.insert("confidence".to_string(), json!(v));
    }
}

/// The sorted, de-duplicated MITRE ATT&CK technique ids stamped on this entity's
/// `attack:<ID>` provenance tags (the technique(s) that collected it).
fn attack_techniques(e: &Entity) -> Vec<String> {
    let mut v: Vec<String> = e
        .tags
        .iter()
        .filter_map(|t| t.strip_prefix("attack:"))
        .map(str::to_string)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// A confidence fraction (0.0–1.0) as a STIX confidence integer (0–100).
fn pct(x: f64) -> i64 {
    (x * 100.0).round().clamp(0.0, 100.0) as i64
}

/// Round to three decimals for a compact, stable float in custom properties.
fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The entity's own `observed_at`, falling back to the scan start for the rare
/// entity created without one — a STIX timestamp must be a real instant.
fn ts_or(observed_at: u64, fallback: u64) -> u64 {
    if observed_at > 0 {
        observed_at
    } else {
        fallback
    }
}

/// Deterministic UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SS.000Z`) for a Unix second
/// count, composed from the project's single-sourced pure date helpers. No wall
/// clock is read, so an unchanged scan re-exports byte-identically.
fn rfc3339(unix_secs: u64) -> String {
    let date =
        crate::util::timefmt::ymd_utc(unix_secs as i64).unwrap_or_else(|| "1970-01-01".to_string());
    let time = crate::util::timefmt::hms_utc(unix_secs);
    format!("{date}T{time}.000Z")
}

/// A deterministic, content-derived UUID (shaped as a valid UUIDv5) for a stable
/// seed. SHA-256 the seed, take the first 16 bytes as hex, then overlay the UUID
/// version (5) and RFC 4122 variant (10xx) nibbles so the result is a
/// syntactically valid UUID that is nonetheless a pure function of the seed:
/// the same entity always yields the same STIX id, and re-exporting an unchanged
/// scan is byte-identical.
fn det_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    // hex::encode of 16 bytes is exactly 32 lowercase ASCII hex chars, so every
    // index below is in bounds and every slice lands on a char boundary.
    let mut ch: Vec<char> = hex::encode(&digest[..16]).chars().collect();
    ch[12] = '5'; // UUID version 5
    ch[16] = '8'; // RFC 4122 variant (10xx)
    let s: String = ch.into_iter().collect();
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

/// Parse an ASN entity value (`AS13335`, `as13335`, `13335`) to its number.
fn parse_asn(value: &str) -> Option<u32> {
    let digits = value.trim().trim_start_matches(['A', 'S', 'a', 's']);
    digits.parse::<u32>().ok()
}

/// Parse a `lat,lon` coordinate value to a validated WGS-84 pair. Rejects
/// out-of-range values so a `location` SDO never carries an invalid coordinate.
fn parse_coords(value: &str) -> Option<(f64, f64)> {
    let (lat_s, lon_s) = value.split_once(',')?;
    let lat = lat_s.trim().parse::<f64>().ok()?;
    let lon = lon_s.trim().parse::<f64>().ok()?;
    if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) {
        Some((lat, lon))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
