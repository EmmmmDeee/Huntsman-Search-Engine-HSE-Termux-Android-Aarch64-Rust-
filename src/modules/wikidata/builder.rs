use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::TargetKind,
};
use crate::util::url_util::host_from_url;

use super::{
    CANDIDATE, DOMAIN_CONF, HANDLE_CONF, HANDLE_PROPS, IMAGE_CONF, MAX_HANDLES, ORG_PRIMARY,
    PERSON_PRIMARY, SRC,
    claims::{claim_p625, claim_strings, en_text},
    classify::{classify, seed_kind},
};

/// Build the fan-out for the primary item from its claims body.
pub(super) fn primary_entities(
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
    out.extend(claim_strings(entity, "P856").into_iter().filter_map(|url| {
        let host = host_from_url(&url)?;
        let mut d = Entity::new(EntityKind::Domain, &host, DOMAIN_CONF, scan_id);
        d.tag(SRC);
        d.tag("wikidata");
        d.tag("official-website");
        d.add_evidence(
            Evidence::new(SRC, format!("Official website of {label}")).with_attr("url", &url),
        );
        Some(d)
    }));

    // Image (P18) → the canonical Wikimedia Commons image URL — an approved,
    // keyless "image search": the official record's photo of the matched subject.
    // Emitted as a `Url` tagged `image`/`avatar` so the metadata pipeline picks
    // it up: `Special:FilePath/<file>.jpg` ends in an image extension, so
    // `exif_geo` accepts it during expansion and mines EXIF — GPS, camera,
    // capture time — normalising any geotag into `Coordinates` the geo
    // correlators consume. Commons normalises spaces↔underscores, so the
    // space→underscore form is a valid, stable URL needing no extra API call.
    // The first non-empty P18 filename yields one canonical Commons image URL.
    if let Some(img) = claim_strings(entity, "P18")
        .into_iter()
        .find_map(|filename| {
            let f = filename.trim();
            if f.is_empty() {
                return None;
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
            Some(img)
        })
    {
        out.push(img);
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
pub(super) fn candidate_entity(
    hit: &super::types::SearchHit,
    seed: TargetKind,
    scan_id: &str,
) -> Entity {
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
