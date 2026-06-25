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
        "Infer locale/country from email local-part naming conventions"
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
        let Some((local, _domain)) = email.split_once('@') else {
            return Ok(result);
        };

        if local.len() < 3 {
            return Ok(result);
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
            e.tag("coarse");
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
                ce.tag("coarse");
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

/// Map a locale code (as emitted by the pattern tables) to an approximate
/// country/region centroid `(lat, lon)`. Returns `None` for ambiguous regions
/// that span multiple countries with no single representative point (e.g. `pt`
/// covers both Portugal and Latin America — a centroid would be misleading).
fn locale_centroid(locale: &str) -> Option<(f64, f64)> {
    // Centroids are national capitals or geographic midpoints — clearly coarse.
    Some(match locale {
        "sv" => (59.334_6, 18.063_2),  // Stockholm, Sweden
        "ru" => (55.751_2, 37.618_4),  // Moscow, Russia
        "pl" => (52.229_7, 21.011_2),  // Warsaw, Poland
        "fi" => (60.169_9, 24.938_4),  // Helsinki, Finland
        "ro" => (44.436_9, 26.102_8),  // Bucharest, Romania
        "tr" => (39.925_5, 32.866_3),  // Ankara, Turkey
        "el" => (37.983_9, 23.729_4),  // Athens, Greece
        "it" => (41.902_8, 12.496_4),  // Rome, Italy
        "fr" => (48.856_6, 2.352_2),   // Paris, France
        "de" => (52.520_0, 13.404_9),  // Berlin, Germany
        "ja" => (35.689_5, 139.691_7), // Tokyo, Japan
        "zh" => (39.904_2, 116.407_4), // Beijing, China
        // "pt" spans Portugal + Latin America — no representative centroid.
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
