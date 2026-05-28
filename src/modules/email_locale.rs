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
    module::{Module, ModuleContext, ModuleResult},
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

    let first = parts[0];
    let last = parts[parts.len() - 1];

    for &(suffixes, region, locale) in SURNAME_SUFFIX_PATTERNS {
        for suffix in suffixes {
            if last.ends_with(suffix) && last.len() >= suffix.len() + 2 {
                return Some(LocaleGeo {
                    region,
                    locale,
                    pattern: "surname_suffix",
                    confidence: 0.35,
                });
            }
        }
    }

    for &(prefixes, region, locale) in GIVEN_NAME_PATTERNS {
        for prefix in prefixes {
            if first == *prefix {
                return Some(LocaleGeo {
                    region,
                    locale,
                    pattern: "given_name",
                    confidence: 0.30,
                });
            }
        }
    }

    None
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
    use super::*;

    #[test]
    fn swedish_surname() {
        let geo = detect_locale_from_local_part("erik.johansson").unwrap();
        assert!(geo.region.contains("Scandinavia"));
    }

    #[test]
    fn polish_surname() {
        let geo = detect_locale_from_local_part("jan.kowalczyk").unwrap();
        assert!(geo.region.contains("Poland"));
    }

    #[test]
    fn french_given_name() {
        let geo = detect_locale_from_local_part("guillaume.martin").unwrap();
        assert!(geo.region.contains("France"));
    }

    #[test]
    fn generic_name_returns_none() {
        assert!(detect_locale_from_local_part("john.smith").is_none());
    }

    #[test]
    fn no_dot_returns_none() {
        assert!(detect_locale_from_local_part("johndoe").is_none());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = EmailLocale;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }
}
