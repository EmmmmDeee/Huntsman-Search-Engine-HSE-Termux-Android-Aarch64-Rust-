//! Pure transform: GLEIF API response → entities.

use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, Evidence};

use crate::util::namesake::{AMBIGUOUS_NAME, NameCollisions};

use super::{
    ABN_CONF, ADDR_CONF, MAX_RECORDS, ORG_AMBIGUOUS, ORG_CANDIDATE, ORG_EXACT, SRC,
    helpers::{au_abn_acn, locality, name_matches_query, record_evidence},
    types::GleifResp,
};

/// Every legal name this response holds more than once — the names GLEIF's own
/// answer proves do not identify a single company.
///
/// Folded exactly as the engine folds an entity value, because the question is
/// "will these rows fuse into one `Organisation`?" — see [`NameCollisions`].
fn collisions(resp: &GleifResp) -> NameCollisions {
    NameCollisions::of(
        &EntityKind::Organisation,
        resp.data.iter().take(MAX_RECORDS).filter_map(|rec| {
            rec.attributes
                .as_ref()?
                .entity
                .as_ref()?
                .legal_name
                .as_ref()?
                .name
                .as_deref()
        }),
    )
}

/// The `(LEI, legal name)` of every searched row whose legal name matches the
/// seed exactly **and identifies exactly one company** — the only rows a
/// Level-2 corporate-family walk is spent on.
///
/// Loose name candidates are excluded deliberately. A walk costs three HTTP
/// requests and, worse, attributes a whole corporate family to the operator's
/// subject; doing that off a fuzzy match would manufacture a confident graph
/// around the wrong company. Rows without an LEI are skipped because there is
/// nothing to walk from.
///
/// An **ambiguous exact** match is excluded for the same reason, and it was not
/// (REQ-GLEIF-001). When two companies in different jurisdictions hold one
/// legal name, both rows matched exactly, both were walked, and both corporate
/// families — parents, ultimate parents and children — were attributed to the
/// one subject, arriving tagged `exact-name-match`. That is the harm this
/// function's own rule already forbade, reached through the gate rather than
/// around it: the name is not the wrong company's, it is *both* companies'.
///
/// Pure, so the seed-selection rule is testable without a network round trip.
pub(super) fn exact_seeds(resp: &GleifResp, query: &str) -> Vec<(String, String)> {
    let shared = collisions(resp);
    resp.data
        .iter()
        .take(MAX_RECORDS)
        .filter_map(|rec| {
            let attrs = rec.attributes.as_ref()?;
            let entity = attrs.entity.as_ref()?;
            let name =
                super::helpers::non_empty(entity.legal_name.as_ref().and_then(|n| n.name.clone()))?;
            let lei = super::helpers::non_empty(attrs.lei.clone())?;
            (name_matches_query(&name, query)
                && !shared.is_shared(&EntityKind::Organisation, &name))
            .then_some((lei, name))
        })
        .collect()
}

/// Cap and flag everything one proven-collision row produced.
///
/// The Organisation and its whole fan-out — the AbnAcn, the registered Address,
/// the inline Coordinates — all rest on the single claim "the subject is this
/// company", so they inherit the ambiguity of that claim. Leaving the AbnAcn at
/// `ABN_CONF` (`confidence::EXPERT`) while demoting only the Organisation would
/// move the defect rather than remove it: the ACN would still pivot, still
/// attributed to a subject who may be the *other* company.
///
/// Idempotent — the tag de-dupes and the cap is a `min`.
fn mark_ambiguous(e: &mut Entity) {
    e.tag(AMBIGUOUS_NAME);
    e.confidence = e.confidence.min(ORG_AMBIGUOUS);
}

/// Pure transform: GLEIF records → entities. Every row yields an `Organisation`
/// carrying the full record in evidence; exact name matches additionally fan out
/// into the AbnAcn (AU) and Address pivots. Loose candidates stay a single
/// sub-floor Organisation so a noisy match can't pivot.
///
/// A legal name this same response holds more than once is a **proven
/// collision**: two different real companies hold it, and because the entity
/// value IS the name, `Entity::new` derives one uid for both and the engine
/// fuses them. `Entity::absorb` keeps both sides' evidence (joining conflicting
/// attributes as `"AU; DE"`), so nothing observed is lost — but the fused
/// entity used to *assert* a single company at `ORG_EXACT`, above the expansion
/// floor, so a composite of two companies pivoted immediately. Those rows are
/// now capped below the floor and say why, the rule `ahpra` established for
/// practitioners (REQ-AHPRA-001) and this module lacked (REQ-GLEIF-001).
pub(super) fn records_to_entities(resp: &GleifResp, query: &str, scan_id: &str) -> Vec<Entity> {
    let shared = collisions(resp);
    let total = resp
        .meta
        .as_ref()
        .and_then(|m| m.pagination.as_ref())
        .and_then(|p| p.total)
        .unwrap_or(resp.data.len() as u64);

    let mut out = Vec::new();
    for rec in resp.data.iter().take(MAX_RECORDS) {
        let Some(attrs) = rec.attributes.as_ref() else {
            continue;
        };
        let Some(entity) = attrs.entity.as_ref() else {
            continue;
        };
        let Some(name) = entity
            .legal_name
            .as_ref()
            .and_then(|n| super::helpers::non_empty(n.name.clone()))
        else {
            continue;
        };
        let lei = attrs.lei.clone().unwrap_or_default();
        let exact = name_matches_query(&name, query);
        // Only an EXACT match can be an ambiguous one: a loose candidate is
        // already sub-floor and already says it did not match.
        let ambiguous = exact && shared.is_shared(&EntityKind::Organisation, &name);
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };
        let row_start = out.len();

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag(SRC);
        org.tag("gleif");
        org.tag("lei");
        if let Some(j) = entity.jurisdiction.as_deref() {
            org.tag(format!("country:{j}"));
        }
        org.tag(if exact {
            "exact-name-match"
        } else {
            "name-candidate"
        });
        // GLEIF entity status is authoritative (ISO 17442): "ACTIVE", "INACTIVE",
        // or "ANNULLED". Tag it directly so rule engines can filter without
        // parsing evidence attributes.
        match entity
            .status
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("ACTIVE") => {
                org.tag("active");
            }
            Some("INACTIVE" | "ANNULLED") => {
                org.tag("inactive");
                org.confidence = confidence::derived_from(org.confidence);
            }
            _ => {}
        }
        let mut ev = record_evidence(&lei, entity, &name, total);
        if ambiguous {
            // The caution rides in evidence, not only in a tag, because the
            // fused entity's attributes are what an operator reads: it will
            // show `jurisdiction: "AU; DE"` and this says why.
            ev = ev.with_attr(
                "caution",
                "this legal name is held by more than one company in GLEIF's own \
                 answer; the merged record describes every holder, not one company",
            );
        }
        org.add_evidence(ev);
        out.push(org);

        if !exact {
            continue;
        }

        // AU local registry id (ACN/ABN) → the business-registry modules.
        if let Some(abn) = au_abn_acn(entity) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, ABN_CONF, scan_id);
            e.tag(SRC);
            e.tag("gleif");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(SRC, format!("ACN/ABN for {name} (LEI {lei})"))
                    .with_attr("lei", &lei),
            );
            out.push(e);
        }

        // Registered address → geocode chains it into Coordinates. Prefer the HQ
        // address (it carries street lines); fall back to the legal address.
        let addr = entity
            .hq_address
            .as_ref()
            .and_then(|a| locality(a).map(|l| (l, a)))
            .or_else(|| {
                entity
                    .legal_address
                    .as_ref()
                    .and_then(|a| locality(a).map(|l| (l, a)))
            });
        if let Some((loc, a)) = addr {
            let mut e = Entity::new(EntityKind::Address, &loc, ADDR_CONF, scan_id);
            e.tag(SRC);
            e.tag("gleif");
            if let Some(j) = entity.jurisdiction.as_deref() {
                e.tag(format!("country:{j}"));
            }
            e.tag("geoint");
            e.tag("registered-address");
            // GLEIF region codes use ISO 3166-2 format "AU-VIC", "AU-NSW", etc.
            // Extract the sub-national part for au-state tagging.
            if let Some(region) = a.region.as_deref() {
                if let Some(sub) = region.strip_prefix("AU-") {
                    e.tag(format!("au-state:{sub}"));
                    e.tag("country:AU");
                }
            } else if let Some(sc) = crate::util::address_au::state_code(&loc) {
                e.tag(format!("au-state:{sc}"));
                e.tag("country:AU");
            }
            let mut aev = Evidence::new(SRC, format!("Registered address for {name}"))
                .with_attr("org", &name)
                .with_attr("lei", &lei);
            if !a.address_lines.is_empty() {
                aev = aev.with_attr("street", a.address_lines.join(", "));
            }
            e.add_evidence(aev);
            out.push(e);

            // Inline Coordinates via city lookup.
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&loc) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    confidence::NOTABLE,
                    scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("gleif");
                if let Some(region) = a.region.as_deref() {
                    if let Some(sub) = region.strip_prefix("AU-") {
                        c.tag(format!("au-state:{sub}"));
                        c.tag("country:AU");
                    }
                } else if let Some(sc) = crate::util::address_au::state_code(&loc) {
                    c.tag(format!("au-state:{sc}"));
                    c.tag("country:AU");
                }
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Inline geocode of GLEIF address '{loc}' → {coord_val}"),
                ));
                out.push(c);
            }
        }

        if ambiguous {
            for e in &mut out[row_start..] {
                mark_ambiguous(e);
            }
        }
    }
    out
}
