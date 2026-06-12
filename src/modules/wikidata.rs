//! Wikidata knowledge-graph lookup (keyless, free).
//!
//! Endpoints (MediaWiki Action API, public, keyless):
//!   * search: `…/w/api.php?action=wbsearchentities&search={q}&type=item`
//!   * claims: `…/w/api.php?action=wbgetentities&ids={Qid}&props=claims|labels|descriptions`
//!
//! For a `FullName` or `Organisation` seed we resolve the entity in Wikidata and,
//! for the best name-matching item, emit the directly-usable cross-correlation
//! pivots its structured claims carry:
//!
//!   * `Person` / `Organisation` — classified from P31 (`Q5` = human),
//!   * `Domain` — the official website (P856 → DNS/web modules),
//!   * `Username` — social-media handles (GitHub/X/Instagram/… → username_search).
//!
//! Precision over recall: Wikidata only holds *notable* entities and a name-only
//! seed has namesakes, so a false match is costly. We therefore require the
//! item's label to contain every seed token as a whole word (the same gate as
//! `acnc_charities`/`gleif_lei`); the top such match is fanned out, further
//! same-name items are surfaced as low-confidence candidates (with their Wikidata
//! id + description in evidence — nothing dropped) that stay below the expansion
//! floor so a namesake can't pivot. Single-source findings keep base confidence
//! until another module independently corroborates them.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};
use crate::util::url_util::host_from_url;

const SRC: &str = "wikidata";
const API: &str = "https://www.wikidata.org/w/api.php";

/// Max same-name items surfaced (1 primary + the rest as candidates).
const MAX_CANDIDATES: usize = 6;
/// Max social handles fanned out from the primary item.
const MAX_HANDLES: usize = 12;

// Confidence tiers vs the 0.50 noisy-OR expansion floor. The primary pivots;
// candidates stay sub-floor. People are kept a touch lower than orgs because a
// name-only seed is more ambiguous than an organisation name.
const PERSON_PRIMARY: f64 = 0.72;
const ORG_PRIMARY: f64 = 0.80;
const CANDIDATE: f64 = 0.40;
const DOMAIN_CONF: f64 = 0.58;
const HANDLE_CONF: f64 = 0.55;
/// Confidence for the Wikidata P18 image URL. Moderate: the image authentically
/// depicts the matched subject, but the URL is a derived pointer, not a direct
/// finding about the subject's accounts.
const IMAGE_CONF: f64 = 0.60;

/// Wikidata properties whose value is *itself* a social handle/username (a plain
/// string, no entity-id resolution needed) → emitted as `Username` for
/// `username_search` to enumerate. Curated to platforms whose id is a genuine
/// *handle* — opaque channel ids (e.g. YouTube P2397, `UC…`) are excluded since
/// they aren't searchable usernames and would only add noise.
const HANDLE_PROPS: &[(&str, &str)] = &[
    ("P2002", "twitter"),
    ("P2003", "instagram"),
    ("P2037", "github"),
    ("P6634", "linkedin"),
    ("P3789", "telegram"),
    ("P4033", "mastodon"),
    ("P2013", "facebook"),
    ("P11245", "tiktok"),
];

pub struct Wikidata;

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    search: Vec<SearchHit>,
}

#[derive(Deserialize)]
struct SearchHit {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct EntitiesResp {
    /// Entity bodies kept as raw JSON: claim `datavalue.value` is a string for
    /// handle/website properties but an object (`{"id":"Q5"}`) for P31, so a
    /// flexible `Value` is more robust than a rigid typed model.
    #[serde(default)]
    entities: serde_json::Map<String, Value>,
}

/// Coordinate location from P625 as `(lat, lon)`, or `None` if absent/malformed.
fn claim_p625(entity: &Value) -> Option<(f64, f64)> {
    let val = entity.pointer("/claims/P625/0/mainsnak/datavalue/value")?;
    let lat = val.get("latitude").and_then(Value::as_f64)?;
    let lon = val.get("longitude").and_then(Value::as_f64)?;
    if crate::util::geo::is_valid_coords(lat, lon) {
        Some((lat, lon))
    } else {
        None
    }
}

/// String-valued claims for a property (e.g. P856 website, P2037 github handle).
fn claim_strings(entity: &Value, pid: &str) -> Vec<String> {
    entity
        .get("claims")
        .and_then(|c| c.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.pointer("/mainsnak/datavalue/value")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Entity-id-valued claims for a property (e.g. P31 instance-of → `["Q5", …]`).
fn claim_entity_ids(entity: &Value, pid: &str) -> Vec<String> {
    entity
        .get("claims")
        .and_then(|c| c.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.pointer("/mainsnak/datavalue/value/id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `labels`/`descriptions` English value for an entity body.
fn en_text(entity: &Value, section: &str) -> Option<String> {
    entity
        .get(section)
        .and_then(|s| s.get("en"))
        .and_then(|e| e.get("value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// True if `name` contains every token of the seed `query` as a whole word
/// (case-insensitive) — the same precision gate as `acnc_charities`/`gleif_lei`.
fn name_matches_query(name: &str, query: &str) -> bool {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let mut any = false;
    for tok in query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        any = true;
        if !words.iter().any(|w| w.eq_ignore_ascii_case(tok)) {
            return false;
        }
    }
    any
}

fn search_url(q: &str) -> String {
    format!(
        "{API}?action=wbsearchentities&search={}&language=en&format=json&type=item&limit=10",
        urlencode(q)
    )
}

fn entities_url(qid: &str) -> String {
    format!("{API}?action=wbgetentities&ids={qid}&format=json&props=claims%7Clabels%7Cdescriptions")
}

/// Entity kind for the primary item: P31 `Q5` ⇒ Person; an explicit non-human
/// P31 ⇒ Organisation; absent P31 ⇒ fall back to the seed's kind.
fn classify(entity: &Value, seed: TargetKind) -> EntityKind {
    let p31 = claim_entity_ids(entity, "P31");
    if p31.iter().any(|id| id == "Q5") {
        EntityKind::Person
    } else if p31.is_empty() {
        seed_kind(seed)
    } else {
        EntityKind::Organisation
    }
}

fn seed_kind(seed: TargetKind) -> EntityKind {
    match seed {
        TargetKind::Organisation => EntityKind::Organisation,
        _ => EntityKind::Person,
    }
}

/// Build the fan-out for the primary item from its claims body.
fn primary_entities(
    qid: &str,
    label: &str,
    entity: &Value,
    seed: TargetKind,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let kind = classify(entity, seed);
    let conf = if kind == EntityKind::Person {
        PERSON_PRIMARY
    } else {
        ORG_PRIMARY
    };
    let desc = en_text(entity, "descriptions");

    let mut head = Entity::new(kind.clone(), label, conf, scan_id);
    head.tag(SRC);
    head.tag("wikidata");
    head.tag(qid);
    head.tag("exact-name-match");
    let mut ev = Evidence::new(SRC, format!("Wikidata {qid}: {label}"))
        .with_attr("wikidata_id", qid)
        .with_attr("register", "Wikidata");
    if let Some(d) = desc.as_deref() {
        ev = ev.with_attr("description", d);
    }
    head.add_evidence(ev);
    out.push(head);

    // Official website (P856) → Domain.
    for url in claim_strings(entity, "P856") {
        if let Some(host) = host_from_url(&url) {
            let mut d = Entity::new(EntityKind::Domain, &host, DOMAIN_CONF, scan_id);
            d.tag(SRC);
            d.tag("wikidata");
            d.tag("official-website");
            d.add_evidence(
                Evidence::new(SRC, format!("Official website of {label}")).with_attr("url", &url),
            );
            out.push(d);
        }
    }

    // Image (P18) → the canonical Wikimedia Commons image URL — an approved,
    // keyless "image search": the official record's photo of the matched subject.
    // Emitted as a `Url` tagged `image`/`avatar` so the metadata pipeline picks
    // it up: `Special:FilePath/<file>.jpg` ends in an image extension, so
    // `exif_geo` accepts it during expansion and mines EXIF — GPS, camera,
    // capture time — normalising any geotag into `Coordinates` the geo
    // correlators consume. Commons normalises spaces↔underscores, so the
    // space→underscore form is a valid, stable URL needing no extra API call.
    for filename in claim_strings(entity, "P18") {
        let f = filename.trim();
        if f.is_empty() {
            continue;
        }
        let img_url = format!(
            "https://commons.wikimedia.org/wiki/Special:FilePath/{}",
            f.replace(' ', "_")
        );
        let mut img = Entity::new(EntityKind::Url, &img_url, IMAGE_CONF, scan_id);
        img.tag(SRC);
        img.tag("wikidata");
        img.tag("image");
        img.tag("avatar");
        img.add_evidence(
            Evidence::new(SRC, format!("Wikimedia Commons image of {label}"))
                .with_attr("commons_file", f)
                .with_attr("wikidata_id", qid)
                .with_attr("image_source", "wikidata_p18"),
        );
        out.push(img);
        break; // one canonical image is sufficient
    }

    // Coordinate location (P625) → Coordinates entity for geo correlators.
    if let Some((lat, lon)) = claim_p625(entity) {
        let coord_val = format!("{lat:.6},{lon:.6}");
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.65, scan_id);
        c.tag(SRC);
        c.tag("wikidata");
        c.tag("geoint");
        let mut ev = Evidence::new(SRC, format!("Wikidata P625 coordinate for {label}"))
            .with_attr("wikidata_id", qid)
            .with_attr("latitude", format!("{lat:.6}"))
            .with_attr("longitude", format!("{lon:.6}"));
        if let Some(d) = desc.as_deref() {
            ev = ev.with_attr("description", d);
        }
        if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
            c.tag(format!("au-state:{state}"));
            c.tag("country:AU");
        }
        c.add_evidence(ev);
        out.push(c);
    }

    // Social handles → Username (capped).
    let mut emitted = 0usize;
    for (pid, platform) in HANDLE_PROPS {
        if emitted >= MAX_HANDLES {
            break;
        }
        for handle in claim_strings(entity, pid) {
            if emitted >= MAX_HANDLES {
                break;
            }
            let h = handle.trim();
            if h.is_empty() {
                continue;
            }
            let mut u = Entity::new(EntityKind::Username, h, HANDLE_CONF, scan_id);
            u.tag(SRC);
            u.tag("wikidata");
            u.tag(*platform);
            u.add_evidence(
                Evidence::new(SRC, format!("{platform} handle for {label}"))
                    .with_attr("platform", *platform)
                    .with_attr("of", label),
            );
            out.push(u);
            emitted += 1;
        }
    }
    out
}

/// A non-primary same-name item: surfaced as a low-confidence candidate so a
/// namesake is visible (with its id + description) but never pivots.
fn candidate_entity(hit: &SearchHit, seed: TargetKind, scan_id: &str) -> Entity {
    let label = hit.label.clone().unwrap_or_else(|| hit.id.clone());
    let mut e = Entity::new(seed_kind(seed), &label, CANDIDATE, scan_id);
    e.tag(SRC);
    e.tag("wikidata");
    e.tag(&hit.id);
    e.tag("name-candidate");
    let mut ev = Evidence::new(SRC, format!("Wikidata candidate {}: {label}", hit.id))
        .with_attr("wikidata_id", &hit.id);
    if let Some(d) = hit.description.as_deref() {
        ev = ev.with_attr("description", d);
    }
    e.add_evidence(ev);
    e
}

#[async_trait]
impl Module for Wikidata {
    fn name(&self) -> &'static str {
        "wikidata"
    }

    fn description(&self) -> &'static str {
        "Wikidata knowledge-graph entity resolution (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // People-enrichment band: an authoritative resolver of notable people /
        // orgs to their official site + social handles, just below name_intel.
        96
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Domain,
            EntityKind::Username,
            EntityKind::Url,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential MediaWiki calls (search + claims); beat the 3s default.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let search: SearchResp = fetch_json(&ctx.http, SRC, &search_url(query)).await?;

        // Eligible = items whose label matches every seed token (precision gate).
        let eligible: Vec<&SearchHit> = search
            .search
            .iter()
            .filter(|h| {
                h.label
                    .as_deref()
                    .is_some_and(|l| name_matches_query(l, query))
            })
            .take(MAX_CANDIDATES)
            .collect();

        let Some((primary, rest)) = eligible.split_first() else {
            return Ok(ModuleResult::new());
        };

        let mut out = ModuleResult::new();
        let primary_label = primary.label.clone().unwrap_or_else(|| primary.id.clone());

        // Fetch the primary item's claims (non-fatal: candidates still surface).
        if let Ok(ents) =
            fetch_json::<EntitiesResp>(&ctx.http, SRC, &entities_url(&primary.id)).await
            && let Some(body) = ents.entities.get(&primary.id)
        {
            out.extend(primary_entities(
                &primary.id,
                &primary_label,
                body,
                target.kind,
                &ctx.scan_id,
            ));
        } else {
            // Claims unavailable — still surface the primary as a plain entity.
            let mut e = Entity::new(
                seed_kind(target.kind),
                &primary_label,
                CANDIDATE,
                &ctx.scan_id,
            );
            e.tag(SRC);
            e.tag("wikidata");
            e.tag(&primary.id);
            e.add_evidence(
                Evidence::new(SRC, format!("Wikidata {}: {primary_label}", primary.id))
                    .with_attr("wikidata_id", &primary.id),
            );
            out.push(e);
        }

        for hit in rest {
            out.push(candidate_entity(hit, target.kind, &ctx.scan_id));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn torvalds_entity() -> Value {
        serde_json::json!({
            "labels": {"en": {"value": "Linus Torvalds"}},
            "descriptions": {"en": {"value": "Finnish software engineer (born 1969)"}},
            "claims": {
                "P31":   [{"mainsnak": {"datavalue": {"value": {"entity-type": "item", "id": "Q5"}}}}],
                "P856":  [{"mainsnak": {"datavalue": {"value": "https://torvalds-family.blogspot.com"}}}],
                "P2037": [{"mainsnak": {"datavalue": {"value": "torvalds"}}}],
                "P6634": [{"mainsnak": {"datavalue": {"value": "linustorvalds"}}}]
            }
        })
    }

    #[test]
    fn accepts_fullname_and_org_only() {
        let m = Wikidata;
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Linus Torvalds")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Mozilla Foundation")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn module_metadata() {
        let m = Wikidata;
        assert_eq!(m.name(), "wikidata");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), ModuleCost::Free);
        assert_eq!(m.category(), ModuleCategory::People);
        assert!(m.max_timeout_ms() > 3_000);
    }

    #[test]
    fn classify_uses_p31_human() {
        let person = torvalds_entity();
        assert_eq!(classify(&person, TargetKind::FullName), EntityKind::Person);
        // Non-human P31 → Organisation even for a FullName seed.
        let org = serde_json::json!({"claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q43229"}}}}]}});
        assert_eq!(
            classify(&org, TargetKind::FullName),
            EntityKind::Organisation
        );
        // No P31 → fall back to the seed kind.
        let bare = serde_json::json!({"claims": {}});
        assert_eq!(
            classify(&bare, TargetKind::Organisation),
            EntityKind::Organisation
        );
        assert_eq!(classify(&bare, TargetKind::FullName), EntityKind::Person);
    }

    #[test]
    fn primary_fans_out_person_website_and_handles() {
        let body = torvalds_entity();
        let ents = primary_entities("Q34253", "Linus Torvalds", &body, TargetKind::FullName, "s");

        let person = ents
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("a Person head entity");
        assert_eq!(person.value, "Linus Torvalds");
        assert!(person.tags.iter().any(|t| t == "Q34253"));
        assert!((person.confidence - PERSON_PRIMARY).abs() < f64::EPSILON);

        // Official website → Domain (host extracted).
        let dom = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("a Domain from P856");
        assert_eq!(dom.value, "torvalds-family.blogspot.com");

        // Social handles → Usernames, tagged by platform.
        let unames: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .map(|e| e.value.as_str())
            .collect();
        assert!(unames.contains(&"torvalds")); // github
        assert!(unames.contains(&"linustorvalds")); // linkedin
        let gh = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "torvalds")
            .unwrap();
        assert!(gh.tags.iter().any(|t| t == "github"));
    }

    #[test]
    fn primary_emits_commons_image_url_for_p18() {
        // P18 image claim → a normalized Url tagged image/avatar pointing at the
        // official Commons Special:FilePath endpoint, ending in an image
        // extension so exif_geo will mine its metadata during expansion.
        let body = serde_json::json!({
            "labels": {"en": {"value": "Jane Doe"}},
            "claims": {
                "P18": [{"mainsnak": {"datavalue": {"value": "Jane Doe portrait.jpg"}}}]
            }
        });
        let ents = primary_entities("Q1", "Jane Doe", &body, TargetKind::FullName, "s");
        let img = ents
            .iter()
            .find(|e| e.kind == EntityKind::Url)
            .expect("a Url image entity from P18");
        assert_eq!(
            img.value,
            "https://commons.wikimedia.org/wiki/Special:FilePath/Jane_Doe_portrait.jpg"
        );
        assert!(img.tags.iter().any(|t| t == "image"));
        assert!(img.tags.iter().any(|t| t == "avatar"));
        assert!(
            img.value.to_lowercase().ends_with(".jpg"),
            "must end in an image extension so exif_geo accepts it"
        );
        // No P18 → no image url.
        let none = serde_json::json!({"labels": {"en": {"value": "No Pic"}}, "claims": {}});
        let ents2 = primary_entities("Q2", "No Pic", &none, TargetKind::FullName, "s");
        assert!(ents2.iter().all(|e| e.kind != EntityKind::Url));
    }

    #[test]
    fn name_match_gate_is_whole_word() {
        assert!(name_matches_query("Linus Torvalds", "linus torvalds"));
        assert!(name_matches_query(
            "Australian Red Cross",
            "red cross australian"
        ));
        assert!(!name_matches_query("Mildred Smith", "red")); // not substring of Mildred
        assert!(!name_matches_query("Linus Torvalds", "linus pauling")); // missing token
    }

    #[test]
    fn candidate_is_sub_floor_with_description_evidence() {
        let hit = SearchHit {
            id: "Q123".into(),
            label: Some("John Smith".into()),
            description: Some("English cricketer".into()),
        };
        let e = candidate_entity(&hit, TargetKind::FullName, "s");
        assert_eq!(e.kind, EntityKind::Person);
        assert!(e.confidence < 0.50);
        assert!(e.tags.iter().any(|t| t == "name-candidate"));
        assert!(e.tags.iter().any(|t| t == "Q123"));
        assert!(
            e.evidence[0]
                .attributes
                .iter()
                .any(|(k, v)| k == "description" && v == "English cricketer")
        );
    }

    #[test]
    fn search_url_and_entities_url_shapes() {
        let s = search_url("Linus Torvalds");
        assert!(s.contains("action=wbsearchentities"));
        assert!(s.contains("search=Linus+Torvalds"));
        assert!(s.contains("type=item"));
        let e = entities_url("Q34253");
        assert!(e.contains("action=wbgetentities"));
        assert!(e.contains("ids=Q34253"));
        assert!(e.contains("props=claims%7Clabels%7Cdescriptions"));
    }

    #[test]
    fn handle_cap_is_respected() {
        // Build an entity with more handles than MAX_HANDLES across properties.
        let mut claims = serde_json::Map::new();
        for (pid, _) in HANDLE_PROPS {
            claims.insert(
                (*pid).to_string(),
                serde_json::json!([
                    {"mainsnak": {"datavalue": {"value": "h1"}}},
                    {"mainsnak": {"datavalue": {"value": "h2"}}}
                ]),
            );
        }
        let body = serde_json::json!({"claims": Value::Object(claims)});
        let ents = primary_entities("Q1", "X", &body, TargetKind::Organisation, "s");
        let n = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .count();
        assert!(n <= MAX_HANDLES, "emitted {n} usernames, cap {MAX_HANDLES}");
    }
}
