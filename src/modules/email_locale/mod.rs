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
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let email = &target.value;
        let Some((local, _domain)) = email.split_once('@') else {
            return Ok(result);
        };

        if local.len() < 3 {
            return Ok(result);
        }

        if let Some(geo) = detect_locale_from_local_part(local) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.region,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("locale-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email local part matches {} naming pattern", geo.locale),
                )
                .with_attr("locale", geo.locale)
                .with_attr("pattern", geo.pattern),
            );
            result.push(e);
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
