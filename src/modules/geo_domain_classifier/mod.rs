//! Geo-indicative domain classifier — zero-API geolocation from domain names.
//!
//! Stealer logs and breach data produce hundreds of domain entities. Many of
//! these encode geographic signals: country-code TLDs (`.com.au`, `.co.uk`),
//! country-specific services (commbank.com.au → Australia), and regional
//! platforms (seek.com.au → Australian employment). This module classifies
//! domains against a static table and emits Address entities at coarse
//! (country/city) granularity.
//!
//! No network calls. Runs in < 1ms. Priority 94 so it fires before
//! geocoding modules that would forward-geocode the addresses it emits.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "geo_domain_classifier";

pub struct GeoDomainClassifier;

#[async_trait]
impl Module for GeoDomainClassifier {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Geo-domain classifier — infers country/region from geo-indicative domain names and TLDs"
    }

    fn priority(&self) -> u8 {
        94
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // Email too: a `@uni.edu.au` / `@*.gov.au` address geolocates the person
        // who uses it (see the institutional gate in `process`). Domain/Url
        // classify fully; an email classifies ONLY when its domain is an
        // education / government institution.
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Url | TargetKind::Email
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let domain = match target.kind {
            TargetKind::Url => crate::util::url_util::host_from_url(&target.value)
                .map(|h| h.to_lowercase())
                .unwrap_or_default(),
            // The domain part of the address (after the last `@`).
            TargetKind::Email => target
                .value
                .rsplit('@')
                .next()
                .map(|d| d.trim().to_lowercase())
                .unwrap_or_default(),
            _ => target.value.trim().to_lowercase(),
        };

        if domain.is_empty() {
            return Ok(result);
        }

        // Domain / Url classify fully (jurisdiction → service → ccTLD). An EMAIL
        // geolocates the person ONLY when its domain is an education / government
        // INSTITUTION — `@uni.edu.au` places a student/staff/alumnus in that
        // city, `@*.gov.au` a public servant in that jurisdiction — via the
        // precise jurisdiction + known-service paths. The ccTLD country-grain is
        // deliberately skipped for emails (an `@x.com` is not "in the United
        // States") and the country-grain known-service rows ("Australia") add no
        // location an AU scan doesn't already assume, so a freemail or generic
        // corporate email yields nothing rather than a misleading fix.
        let classification = if target.kind == TargetKind::Email {
            if is_institutional_domain(&domain) {
                classify_au_jurisdiction_domain(&domain)
                    .or_else(|| classify_by_known_service(&domain))
                    .filter(|g| g.location != "Australia")
            } else {
                None
            }
        } else {
            classify_domain(&domain)
        };

        if let Some(geo) = classification {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.location,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag(crate::core::tags::COARSE);
            e.tag("domain-inferred");
            // Distinguish a location inferred from an email's institutional
            // domain (a `@uni.edu.au` / `@*.gov.au` affiliation) from one read off
            // a bare domain/url, so downstream consumers can weight it as the
            // affiliation signal it is.
            if target.kind == TargetKind::Email {
                e.tag("email-affiliation");
            }
            // A `*.{state}.gov.au` domain pins the jurisdiction: tag the state so
            // the jurisdiction cross-checks (AU-056 / AU-085) read it, and mark it
            // a government affiliation for filtering.
            if let Some(state) = geo.au_state {
                e.tag(format!("au-state:{state}"));
                e.tag("gov-domain");
                e.tag("au-relevant");
            }
            // The `.au` second-level domain encodes the registrant's entity type
            // under the licensing rules — `id.au` a natural person, `com.au`/
            // `net.au` a commercial ABN/trademark holder, `org.au` a non-profit,
            // `asn.au` an association, `gov.au`/`edu.au` government/education. Tag
            // it so the people-vs-organisation and AU-jurisdiction signals are
            // captured alongside the location (purely additive to the Address).
            if let Some((category, label)) = crate::util::address_au::au_domain_registrant(&domain)
            {
                e.tag(format!("au-registrant:{category}"));
                e.tag("au-relevant");
                e.add_evidence(
                    Evidence::new(SRC, format!("`.au` domain '{domain}' → {label}"))
                        .with_attr("au_registrant", category)
                        .with_attr("domain", &domain),
                );
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Domain '{}' indicates {}", domain, geo.location),
                )
                .with_attr("domain", &domain)
                .with_attr("country_code", geo.country_code)
                .with_attr("method", geo.method),
            );
            // A whole-state government classification must NOT pin a single
            // coordinate (and a state-name string can spuriously substring-match a
            // city); only point/country-grain classifications geocode.
            if geo.au_state.is_none()
                && let Some((lat, lon)) = crate::util::city_coords::city_coords(geo.location)
            {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    geo.confidence - 0.10,
                    &ctx.scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("domain-inferred");
                c.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Geocode of domain-inferred location '{}'", geo.location),
                    )
                    .with_attr("domain", &domain),
                );
                result.push(c);
            }
            result.push(e);
        }

        Ok(result)
    }
}

struct GeoClassification {
    location: &'static str,
    country_code: &'static str,
    confidence: f64,
    method: &'static str,
    /// The AU state/territory code when the classification is jurisdiction-precise
    /// (a `*.{state}.gov.au` government domain) rather than country/city grain.
    /// Drives an `au-state:` tag and suppresses the point-geocode (a whole state
    /// must not pin a single coordinate).
    au_state: Option<&'static str>,
}

fn classify_domain(domain: &str) -> Option<GeoClassification> {
    // An AU state-government / state-education domain (`health.nsw.gov.au` → NSW,
    // `schools.vic.edu.au` → VIC) is a precise, official jurisdiction signal that
    // must win over the generic `.au` country-grain classification below. Then a
    // known service (incl. universities → city), then the ccTLD.
    classify_au_jurisdiction_domain(domain)
        .or_else(|| classify_by_known_service(domain))
        .or_else(|| classify_by_cctld(domain))
}

/// A `*.{state}.gov.au` government domain or `*.{state}.edu.au` state-education
/// domain → a state-grain `<State>, Australia` location with its canonical state
/// code, so it feeds the jurisdiction cross-checks (AU-056 / AU-085) at state
/// precision. Federal `*.gov.au`, university `*.edu.au` (institution-named →
/// a city via the service table) and non-AU-jurisdiction domains return `None`.
fn classify_au_jurisdiction_domain(domain: &str) -> Option<GeoClassification> {
    let state = crate::util::address_au::au_gov_domain_state(domain)
        .or_else(|| crate::util::address_au::au_edu_domain_state(domain))?;
    let location = match state {
        "NSW" => "New South Wales, Australia",
        "VIC" => "Victoria, Australia",
        "QLD" => "Queensland, Australia",
        "WA" => "Western Australia, Australia",
        "SA" => "South Australia, Australia",
        "TAS" => "Tasmania, Australia",
        "ACT" => "Australian Capital Territory, Australia",
        "NT" => "Northern Territory, Australia",
        _ => return None,
    };
    Some(GeoClassification {
        location,
        country_code: "AU",
        confidence: 0.62,
        method: "au_gov_domain",
        au_state: Some(state),
    })
}

/// True for an education or government domain — the email domains that reliably
/// place the person who uses them: a `@uni.edu.au` student / staff / alumnus, a
/// `@*.gov.au` public servant, an academic `@*.ac.*`. Generic corporate and
/// freemail domains are excluded, so an email only geolocates when its domain is
/// a real institution (the `process` email gate). Matches on the registrable
/// shape, not a fixed list, so a new university / agency domain is covered
/// without a table edit.
fn is_institutional_domain(domain: &str) -> bool {
    let d = domain.strip_prefix("www.").unwrap_or(domain);
    d.ends_with(".edu.au")
        || d.ends_with(".gov.au")
        || d.ends_with(".edu")
        || d.ends_with(".gov")
        || d.contains(".edu.")
        || d.contains(".gov.")
        || d.contains(".ac.")
}

fn classify_by_known_service(domain: &str) -> Option<GeoClassification> {
    let d = domain.strip_prefix("www.").unwrap_or(domain);
    GEO_SERVICES
        .iter()
        .find(|&&(pattern, _, _)| crate::util::domains::is_or_subdomain_of(d, pattern))
        .map(|&(_, location, cc)| GeoClassification {
            location,
            country_code: cc,
            confidence: confidence::MEDIUM_PLUS,
            method: "known_service",
            au_state: None,
        })
}

fn classify_by_cctld(domain: &str) -> Option<GeoClassification> {
    CCTLD_MAP
        .iter()
        .find(|&&(tld, _, _)| domain.ends_with(tld))
        .map(|&(_, location, cc)| GeoClassification {
            location,
            country_code: cc,
            confidence: confidence::LOW_MEDIUM,
            method: "cctld",
            au_state: None,
        })
}

const GEO_SERVICES: &[(&str, &str, &str)] = &[
    // Australia
    ("commbank.com.au", "Australia", "AU"),
    ("westpac.com.au", "Australia", "AU"),
    ("anz.com.au", "Australia", "AU"),
    ("nab.com.au", "Australia", "AU"),
    ("realestate.com.au", "Australia", "AU"),
    ("domain.com.au", "Australia", "AU"),
    ("seek.com.au", "Australia", "AU"),
    ("gumtree.com.au", "Australia", "AU"),
    ("afterpay.com", "Australia", "AU"),
    ("zip.co", "Australia", "AU"),
    ("bunnings.com.au", "Australia", "AU"),
    ("woolworths.com.au", "Australia", "AU"),
    ("coles.com.au", "Australia", "AU"),
    ("telstra.com.au", "Australia", "AU"),
    ("optus.com.au", "Australia", "AU"),
    ("centrelink.gov.au", "Australia", "AU"),
    ("myob.com", "Australia", "AU"),
    // Australian universities → their home city (a `@uni.edu.au` address places a
    // student / staff / alumnus in a specific city, finer than the `.edu.au`
    // country fallback). Single-campus-city institutions only; the city must be
    // in `util::city_coords` so it geocodes (→ coordinate → AU state). Matched as
    // a subdomain too (`student.uq.edu.au` → uq.edu.au).
    ("sydney.edu.au", "Sydney, Australia", "AU"),
    ("unsw.edu.au", "Sydney, Australia", "AU"),
    ("uts.edu.au", "Sydney, Australia", "AU"),
    ("mq.edu.au", "Sydney, Australia", "AU"),
    ("westernsydney.edu.au", "Sydney, Australia", "AU"),
    ("unimelb.edu.au", "Melbourne, Australia", "AU"),
    ("monash.edu", "Melbourne, Australia", "AU"),
    ("rmit.edu.au", "Melbourne, Australia", "AU"),
    ("latrobe.edu.au", "Melbourne, Australia", "AU"),
    ("swinburne.edu.au", "Melbourne, Australia", "AU"),
    ("deakin.edu.au", "Melbourne, Australia", "AU"),
    ("vu.edu.au", "Melbourne, Australia", "AU"),
    ("uq.edu.au", "Brisbane, Australia", "AU"),
    ("qut.edu.au", "Brisbane, Australia", "AU"),
    ("griffith.edu.au", "Brisbane, Australia", "AU"),
    ("uwa.edu.au", "Perth, Australia", "AU"),
    ("curtin.edu.au", "Perth, Australia", "AU"),
    ("murdoch.edu.au", "Perth, Australia", "AU"),
    ("ecu.edu.au", "Perth, Australia", "AU"),
    ("adelaide.edu.au", "Adelaide, Australia", "AU"),
    ("unisa.edu.au", "Adelaide, Australia", "AU"),
    ("flinders.edu.au", "Adelaide, Australia", "AU"),
    ("anu.edu.au", "Canberra, Australia", "AU"),
    ("canberra.edu.au", "Canberra, Australia", "AU"),
    ("utas.edu.au", "Hobart, Australia", "AU"),
    ("cdu.edu.au", "Darwin, Australia", "AU"),
    ("newcastle.edu.au", "Newcastle, Australia", "AU"),
    ("uow.edu.au", "Wollongong, Australia", "AU"),
    ("usc.edu.au", "Sunshine Coast, Australia", "AU"),
    ("federation.edu.au", "Ballarat, Australia", "AU"),
    ("csu.edu.au", "Bathurst, Australia", "AU"),
    ("jcu.edu.au", "Townsville, Australia", "AU"),
    ("bond.edu.au", "Gold Coast, Australia", "AU"),
    ("xero.com", "New Zealand", "NZ"),
    // United Kingdom
    ("hsbc.co.uk", "United Kingdom", "GB"),
    ("barclays.co.uk", "United Kingdom", "GB"),
    ("lloydsbank.co.uk", "United Kingdom", "GB"),
    ("natwest.com", "United Kingdom", "GB"),
    ("rightmove.co.uk", "United Kingdom", "GB"),
    ("autotrader.co.uk", "United Kingdom", "GB"),
    ("nhs.uk", "United Kingdom", "GB"),
    ("gov.uk", "United Kingdom", "GB"),
    // United States
    ("chase.com", "United States", "US"),
    ("bankofamerica.com", "United States", "US"),
    ("wellsfargo.com", "United States", "US"),
    ("capitalone.com", "United States", "US"),
    ("zillow.com", "United States", "US"),
    ("realtor.com", "United States", "US"),
    ("craigslist.org", "United States", "US"),
    ("usps.com", "United States", "US"),
    ("irs.gov", "United States", "US"),
    ("dmv.org", "United States", "US"),
    // Germany
    ("sparkasse.de", "Germany", "DE"),
    ("commerzbank.de", "Germany", "DE"),
    ("postbank.de", "Germany", "DE"),
    ("immobilienscout24.de", "Germany", "DE"),
    ("mobile.de", "Germany", "DE"),
    // France
    ("labanquepostale.fr", "France", "FR"),
    ("leboncoin.fr", "France", "FR"),
    ("impots.gouv.fr", "France", "FR"),
    // Canada
    ("td.com", "Canada", "CA"),
    ("rbc.com", "Canada", "CA"),
    ("scotiabank.com", "Canada", "CA"),
    ("kijiji.ca", "Canada", "CA"),
    // Japan
    ("rakuten.co.jp", "Japan", "JP"),
    ("yahoo.co.jp", "Japan", "JP"),
    ("mercari.com", "Japan", "JP"),
    // Brazil
    ("mercadolivre.com.br", "Brazil", "BR"),
    ("itau.com.br", "Brazil", "BR"),
    ("bradesco.com.br", "Brazil", "BR"),
    // India
    ("flipkart.com", "India", "IN"),
    ("paytm.com", "India", "IN"),
    ("hdfc.com", "India", "IN"),
    ("icicibank.com", "India", "IN"),
];

const CCTLD_MAP: &[(&str, &str, &str)] = &[
    (".com.au", "Australia", "AU"),
    (".net.au", "Australia", "AU"),
    (".org.au", "Australia", "AU"),
    (".gov.au", "Australia", "AU"),
    (".edu.au", "Australia", "AU"),
    // `.id.au` (a natural-person Australian registrant) and `.asn.au` (an
    // incorporated association) are real AU 2LDs that previously fell through to
    // no classification — so an individual's `.id.au` domain produced no AU
    // jurisdiction signal at all. Country-grain here; the registrant category is
    // tagged in `process` via `au_domain_registrant`.
    (".id.au", "Australia", "AU"),
    (".asn.au", "Australia", "AU"),
    (".co.uk", "United Kingdom", "GB"),
    (".org.uk", "United Kingdom", "GB"),
    (".ac.uk", "United Kingdom", "GB"),
    (".gov.uk", "United Kingdom", "GB"),
    (".co.nz", "New Zealand", "NZ"),
    (".co.za", "South Africa", "ZA"),
    (".com.br", "Brazil", "BR"),
    (".co.jp", "Japan", "JP"),
    (".co.kr", "South Korea", "KR"),
    (".co.in", "India", "IN"),
    (".com.sg", "Singapore", "SG"),
    (".com.my", "Malaysia", "MY"),
    (".co.id", "Indonesia", "ID"),
    (".com.ph", "Philippines", "PH"),
    (".com.tw", "Taiwan", "TW"),
    (".com.hk", "Hong Kong", "HK"),
    (".com.mx", "Mexico", "MX"),
    (".com.ar", "Argentina", "AR"),
    (".com.co", "Colombia", "CO"),
    (".com.pe", "Peru", "PE"),
    (".com.ng", "Nigeria", "NG"),
    (".com.eg", "Egypt", "EG"),
    (".com.pk", "Pakistan", "PK"),
    (".com.bd", "Bangladesh", "BD"),
    (".com.vn", "Vietnam", "VN"),
    (".com.tr", "Turkey", "TR"),
    (".com.ua", "Ukraine", "UA"),
    // Simple ccTLDs (lower confidence — many are used internationally)
    (".de", "Germany", "DE"),
    (".fr", "France", "FR"),
    (".it", "Italy", "IT"),
    (".es", "Spain", "ES"),
    (".pt", "Portugal", "PT"),
    (".nl", "Netherlands", "NL"),
    (".be", "Belgium", "BE"),
    (".at", "Austria", "AT"),
    (".ch", "Switzerland", "CH"),
    (".se", "Sweden", "SE"),
    (".no", "Norway", "NO"),
    (".dk", "Denmark", "DK"),
    (".fi", "Finland", "FI"),
    (".pl", "Poland", "PL"),
    (".cz", "Czech Republic", "CZ"),
    (".hu", "Hungary", "HU"),
    (".ro", "Romania", "RO"),
    (".bg", "Bulgaria", "BG"),
    (".hr", "Croatia", "HR"),
    (".sk", "Slovakia", "SK"),
    (".ie", "Ireland", "IE"),
    (".ru", "Russia", "RU"),
    (".jp", "Japan", "JP"),
    (".kr", "South Korea", "KR"),
    (".cn", "China", "CN"),
    (".in", "India", "IN"),
    (".za", "South Africa", "ZA"),
    (".ca", "Canada", "CA"),
    (".mx", "Mexico", "MX"),
    (".br", "Brazil", "BR"),
    (".ar", "Argentina", "AR"),
    (".cl", "Chile", "CL"),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
