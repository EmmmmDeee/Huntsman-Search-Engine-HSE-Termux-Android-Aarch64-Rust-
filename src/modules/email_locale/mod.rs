//! Email locale inference — detect geographic signals from the naming
//! conventions in the local part of an email address.
//!
//! German emails use `vorname.nachname@`, Italian use `nome.cognome@`,
//! Cyrillic transliterations follow `imya.familiya@` patterns. Combined
//! with the domain ccTLD, these signals narrow geography.
//!
//! No network calls. Pure string analysis. Priority 91.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "email_locale";

pub struct EmailLocale;

#[async_trait]
impl Module for EmailLocale {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Email locale inference — triangulates locale/country from email local-part naming conventions"
    }
    fn priority(&self) -> u8 {
        91
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
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
        let email = target.value.clone();
        let Some((local, domain)) = email.split_once('@') else {
            return Ok(result);
        };

        if local.len() < 3 {
            return Ok(result);
        }

        // ccTLD signal: a geographic country-code TLD on the domain is an
        // independent geographic signal (e.g. `@company.de` → Germany). Emit
        // a separate Address entity so the geospatial layer picks it up even
        // when the local-part pattern has no match. Common non-geographic TLDs
        // used as generic branding (.io, .ai, .co, .tv, .app, .ly, .me) are
        // excluded — they carry no reliable country signal.
        // Lowercase the label before the lookup: DNS is case-insensitive and a
        // seed can carry an upper/mixed-case TLD (`user@example.DE`), but
        // `cctld_country`'s table is keyed on lowercase, so an unnormalised
        // `"DE"` would silently miss the country signal.
        let cctld_geo = domain
            .rsplit('.')
            .next()
            .map(str::to_ascii_lowercase)
            .and_then(|tld| cctld_country(&tld));
        if let Some((country, locale_code)) = cctld_geo {
            let ev = Evidence::new(
                SRC,
                format!(
                    "Email domain ccTLD .{} indicates {country}",
                    domain.rsplit('.').next().unwrap_or("")
                ),
            )
            .with_attr("cctld", domain.rsplit('.').next().unwrap_or(""))
            .with_attr("locale", locale_code);
            let mut ae = Entity::new(EntityKind::Address, country, 0.40, &ctx.scan_id);
            ae.tag("geoint");
            ae.tag(crate::core::tags::COARSE);
            ae.tag("cctld-inferred");
            ae.add_evidence(ev.clone());
            result.push(ae);
            if let Some((lat, lon)) = locale_centroid(locale_code) {
                let coords = format!("{lat},{lon}");
                let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.30, &ctx.scan_id);
                ce.tag("geoint");
                ce.tag(crate::core::tags::COARSE);
                ce.tag("cctld-inferred");
                ce.add_evidence(ev);
                result.push(ce);
            }
        }

        if let Some(geo) = detect_locale_from_local_part(local) {
            let ev = Evidence::new(
                SRC,
                format!("Email local part matches {} naming pattern", geo.locale),
            )
            .with_attr("locale", geo.locale)
            .with_attr("pattern", geo.pattern);

            let mut e = Entity::new(
                EntityKind::Address,
                geo.region,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag(crate::core::tags::COARSE);
            e.tag("locale-inferred");
            e.add_evidence(ev.clone());
            result.push(e);

            // Emit a coarse Coordinates entity (country/region centroid) so the
            // geospatial layer can plot the inferred locale. Confidence is kept
            // well below the Address confidence — the centroid is an approximation
            // of a country-level inference, not a confirmed location.
            if let Some((lat, lon)) = locale_centroid(geo.locale) {
                let coords = format!("{lat},{lon}");
                let mut ce = Entity::new(
                    EntityKind::Coordinates,
                    &coords,
                    geo.confidence - 0.10,
                    &ctx.scan_id,
                );
                ce.tag("geoint");
                ce.tag(crate::core::tags::COARSE);
                ce.tag("locale-inferred");
                ce.add_evidence(ev);
                result.push(ce);
            }
        }

        Ok(result)
    }
}

struct LocaleGeo {
    region: &'static str,
    locale: &'static str,
    pattern: &'static str,
    confidence: f64,
}

fn detect_locale_from_local_part(local: &str) -> Option<LocaleGeo> {
    let parts: Vec<&str> = local.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Email local-part case is not significant in practice (RFC 5321 §2.4 leaves
    // it to the receiver, and the major providers treat it case-insensitively),
    // and the pattern tables below are all lowercase. Fold the candidate name
    // parts so an ordinary `Guillaume.Martin@…` or `ERIK.JOHANSSON@…` still
    // matches instead of silently missing. `to_lowercase` (not ASCII-only) so the
    // non-ASCII suffixes (`ström`, `oğlu`) fold correctly too.
    let first = parts[0].to_lowercase();
    let last = parts[parts.len() - 1].to_lowercase();

    // Surname-suffix match (higher confidence) first, then a given-name match.
    let by_surname = SURNAME_SUFFIX_PATTERNS
        .iter()
        .find(|&&(suffixes, _, _)| {
            suffixes
                .iter()
                .any(|suffix| last.ends_with(suffix) && last.len() >= suffix.len() + 2)
        })
        .map(|&(_, region, locale)| LocaleGeo {
            region,
            locale,
            pattern: "surname_suffix",
            confidence: 0.35,
        });

    by_surname.or_else(|| {
        GIVEN_NAME_PATTERNS
            .iter()
            .find(|&&(prefixes, _, _)| prefixes.contains(&first.as_str()))
            .map(|&(_, region, locale)| LocaleGeo {
                region,
                locale,
                pattern: "given_name",
                confidence: 0.30,
            })
    })
}

/// Map a 2-letter ccTLD to `(country_name, locale_code)` for geographic ccTLDs
/// that reliably indicate a country. Non-geographic TLDs used as generic
/// branding (.io, .ai, .co, .tv, .app, .ly, .me, .to, .is) are absent —
/// they carry no durable country signal. Returns `None` for unknown or
/// non-geographic TLDs.
fn cctld_country(tld: &str) -> Option<(&'static str, &'static str)> {
    Some(match tld {
        "de" => ("Germany", "de"),
        "fr" => ("France", "fr"),
        "it" => ("Italy", "it"),
        "es" => ("Spain", "es"),
        "nl" => ("Netherlands", "nl"),
        "pl" => ("Poland", "pl"),
        "ru" => ("Russia", "ru"),
        "ua" => ("Ukraine", "ua"),
        "se" => ("Sweden", "se"),
        "no" => ("Norway", "no"),
        "dk" => ("Denmark", "dk"),
        "fi" => ("Finland", "fi"),
        "pt" => ("Portugal", "pt"),
        "ro" => ("Romania", "ro"),
        "cz" => ("Czech Republic", "cz"),
        "sk" => ("Slovakia", "sk"),
        "hu" => ("Hungary", "hu"),
        "at" => ("Austria", "at"),
        "be" => ("Belgium", "be"),
        "ch" => ("Switzerland", "ch"),
        "gr" => ("Greece", "el"),
        "tr" => ("Turkey", "tr"),
        "jp" => ("Japan", "ja"),
        "cn" => ("China", "zh"),
        "kr" => ("South Korea", "ko"),
        "in" => ("India", "hi"),
        "au" => ("Australia", "en-au"),
        "nz" => ("New Zealand", "en-nz"),
        "za" => ("South Africa", "af"),
        "br" => ("Brazil", "pt-br"),
        "mx" => ("Mexico", "es-mx"),
        "ar" => ("Argentina", "es-ar"),
        "uk" => ("United Kingdom", "en-gb"),
        _ => return None,
    })
}

/// Map a locale code (as emitted by the pattern tables) to an approximate
/// country/region centroid `(lat, lon)`.
///
/// `es-mx`, `es-ar`, and `pt-br` are only ever produced by [`cctld_country`]
/// from an UNAMBIGUOUS ccTLD (`.mx`/`.ar`/`.br`), so each gets its own correct
/// national capital rather than being folded into the "parent language"
/// country's centroid — Mexico City is not Madrid, and Brasília is not Lisbon.
///
/// Bare `pt` is genuinely overloaded: [`cctld_country`] emits it for the
/// unambiguous `.pt` ccTLD (definitely Portugal), but [`GIVEN_NAME_PATTERNS`]
/// also emits it for the coarser "Iberia/Latin America" given-name heuristic
/// (`jose`/`carlos`/`pedro`/…), which could equally be a Latin-American
/// country. Both paths resolve to the same locale string here, so `pt` always
/// yields the Lisbon centroid; the given-name path's already-low 0.30
/// confidence (see [`detect_locale_from_local_part`]) reflects that
/// imprecision rather than this function silently dropping the coordinate.
/// Returns `None` only for a locale with no country signal at all.
fn locale_centroid(locale: &str) -> Option<(f64, f64)> {
    // Centroids are national capitals or geographic midpoints — clearly coarse.
    Some(match locale {
        "sv" | "se" => (59.334_6, 18.063_2), // Stockholm, Sweden
        "ru" => (55.751_2, 37.618_4),        // Moscow, Russia
        "ua" => (50.450_0, 30.523_4),        // Kyiv, Ukraine
        "pl" => (52.229_7, 21.011_2),        // Warsaw, Poland
        "fi" => (60.169_9, 24.938_4),        // Helsinki, Finland
        "ro" => (44.436_9, 26.102_8),        // Bucharest, Romania
        "tr" => (39.925_5, 32.866_3),        // Ankara, Turkey
        "el" => (37.983_9, 23.729_4),        // Athens, Greece
        "it" => (41.902_8, 12.496_4),        // Rome, Italy
        "fr" => (48.856_6, 2.352_2),         // Paris, France
        "de" => (52.520_0, 13.404_9),        // Berlin, Germany
        "ja" => (35.689_5, 139.691_7),       // Tokyo, Japan
        "zh" => (39.904_2, 116.407_4),       // Beijing, China
        "es" => (40.416_7, -3.703_5),        // Madrid, Spain
        "es-mx" => (19.432_6, -99.133_2),    // Mexico City, Mexico
        "es-ar" => (-34.603_7, -58.381_6),   // Buenos Aires, Argentina
        "nl" => (52.370_2, 4.895_2),         // Amsterdam, Netherlands
        "cz" => (50.075_5, 14.437_8),        // Prague, Czech Republic
        "sk" => (48.148_6, 17.107_5),        // Bratislava, Slovakia
        "hu" => (47.497_9, 19.039_8),        // Budapest, Hungary
        "at" => (48.208_2, 16.373_8),        // Vienna, Austria
        "be" => (50.850_3, 4.351_7),         // Brussels, Belgium
        "ch" => (46.948_0, 7.447_4),         // Bern, Switzerland
        "no" => (59.913_9, 10.752_2),        // Oslo, Norway
        "dk" => (55.676_1, 12.568_4),        // Copenhagen, Denmark
        "pt" => (38.716_8, -9.142_1),        // Lisbon, Portugal
        "pt-br" => (-15.793_9, -47.882_7),   // Brasília, Brazil
        "ko" => (37.566_5, 126.978_0),       // Seoul, South Korea
        "hi" => (28.613_9, 77.209_0),        // New Delhi, India
        "en-au" => (-33.868_8, 151.209_3),   // Sydney, Australia
        "en-nz" => (-36.848_5, 174.763_3),   // Auckland, New Zealand
        "af" => (-25.746_0, 28.188_1),       // Pretoria, South Africa
        "en-gb" => (51.507_4, -0.127_8),     // London, United Kingdom
        _ => return None,
    })
}

const SURNAME_SUFFIX_PATTERNS: &[(&[&str], &str, &str)] = &[
    (
        &["sson", "dottir", "ström", "qvist"],
        "Scandinavia (Sweden/Iceland)",
        "sv",
    ),
    (
        &["ovic", "enko", "chuk", "skiy"],
        "Eastern Europe (Ukraine/Russia/Serbia)",
        "ru",
    ),
    (&["owski", "ewicz", "czyk"], "Poland", "pl"),
    (&["inen", "anen", "ainen"], "Finland", "fi"),
    (&["escu", "eanu"], "Romania", "ro"),
    (&["oğlu", "oglu"], "Turkey", "tr"),
    (&["ides", "akis", "oulos"], "Greece", "el"),
    (&["etti", "elli", "otti", "ucci"], "Italy", "it"),
];

const GIVEN_NAME_PATTERNS: &[(&[&str], &str, &str)] = &[
    (
        &[
            "guillaume",
            "thierry",
            "sebastien",
            "christophe",
            "stephane",
        ],
        "France",
        "fr",
    ),
    (
        &["juergen", "andreas", "matthias", "thorsten", "steffen"],
        "Germany",
        "de",
    ),
    (
        &["giuseppe", "giovanni", "francesco", "alessandro", "lorenzo"],
        "Italy",
        "it",
    ),
    (
        &["jose", "carlos", "pedro", "joao", "rafael"],
        "Iberia/Latin America",
        "pt",
    ),
    (
        &["dmitry", "sergei", "aleksei", "nikolai", "evgeny"],
        "Russia",
        "ru",
    ),
    (
        &["takeshi", "hiroshi", "kenji", "masahiro", "yusuke"],
        "Japan",
        "ja",
    ),
    (&["wei", "jian", "ming", "xiao", "yong"], "China", "zh"),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
