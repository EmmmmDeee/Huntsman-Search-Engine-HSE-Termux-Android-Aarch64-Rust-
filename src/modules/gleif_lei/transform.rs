//! Pure transform: GLEIF API response → entities.

use crate::core::entity::{Entity, EntityKind, Evidence};

use super::{
    ABN_CONF, ADDR_CONF, MAX_RECORDS, ORG_CANDIDATE, ORG_EXACT, SRC,
    helpers::{au_abn_acn, locality, name_matches_query, record_evidence},
    types::GleifResp,
};

/// Pure transform: GLEIF records → entities. Every row yields an `Organisation`
/// carrying the full record in evidence; exact name matches additionally fan out
/// into the AbnAcn (AU) and Address pivots. Loose candidates stay a single
/// sub-floor Organisation so a noisy match can't pivot.
pub(super) fn records_to_entities(resp: &GleifResp, query: &str, scan_id: &str) -> Vec<Entity> {
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
        let conf = if exact { ORG_EXACT } else { ORG_CANDIDATE };

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
        org.add_evidence(record_evidence(&lei, entity, &name, total));
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
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
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
    }
    out
}
