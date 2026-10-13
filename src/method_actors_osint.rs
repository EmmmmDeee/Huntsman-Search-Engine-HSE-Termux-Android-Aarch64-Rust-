//! OSINT method actors.
//!
//! Classification is [`crate::classifier::classify`], the engine's runtime authority, and
//! placeholder and syntax decisions are [`crate::validation`] and [`crate::value_syntax`].
//! These actors only compose them.

use std::sync::Arc;

use crate::classifier::{self, Classified};
use crate::entity::EntityKind;
use crate::method_actor::{ActorMetadata, FunctionActor, MethodActor};
use crate::validation::{self, ValueKind};
use crate::value_syntax;

/// True when the shared rules mark the classified value as a placeholder or a
/// non-routable address rather than a real-world indicator.
#[must_use]
pub fn is_false_positive(classified: &Classified) -> bool {
    let value = classified.value.as_str();
    let kind = match classified.kind {
        EntityKind::IpAddress => return validation::is_non_routable_ip(value),
        EntityKind::Email => ValueKind::Email,
        EntityKind::Url => ValueKind::Url,
        EntityKind::Domain => ValueKind::Domain,
        EntityKind::Username => ValueKind::Username,
        EntityKind::Person => ValueKind::Person,
        _ => return false,
    };
    validation::is_placeholder_entity(&kind, value)
}

fn email_domain(classified: &Classified) -> Option<String> {
    (classified.kind == EntityKind::Email)
        .then(|| classified.value.rsplit_once('@'))
        .flatten()
        .and_then(|(_, host)| value_syntax::canonical_domain(host))
}

fn actor(
    id: &str,
    name: &str,
    cost: u32,
    f: impl Fn(Vec<String>) -> Vec<String> + Send + Sync + 'static,
) -> Arc<dyn MethodActor> {
    Arc::new(FunctionActor::new(
        ActorMetadata::new(id, name).with_cost_estimate(cost),
        Arc::new(move |items| Ok(f(items))),
    ))
}

/// Prefix each value with its engine kind and canonical form: `email:ada@analytical.org`.
#[must_use]
pub fn entity_classifier_actor() -> Arc<dyn MethodActor> {
    actor("entity_classifier", "Classify Entity Types", 12, |items| {
        items
            .iter()
            .map(|item| {
                let classified = classifier::classify(item);
                format!("{}:{}", classified.kind, classified.value)
            })
            .collect()
    })
}

/// Emit the organisation domain behind each email, URL or domain; drop everything else.
#[must_use]
pub fn organization_extractor_actor() -> Arc<dyn MethodActor> {
    actor(
        "org_extractor",
        "Extract Organisation Domains",
        15,
        |items| {
            items
                .iter()
                .filter_map(|item| {
                    let classified = classifier::classify(item);
                    match classified.kind {
                        EntityKind::Email => email_domain(&classified),
                        EntityKind::Url => value_syntax::host_from_url(&classified.value)
                            .and_then(|host| value_syntax::canonical_domain_host(&host)),
                        EntityKind::Domain => {
                            value_syntax::canonical_domain_host(&classified.value)
                        }
                        _ => None,
                    }
                })
                .collect()
        },
    )
}

/// Keep only values the engine classifies as an email, phone number or domain.
#[must_use]
pub fn contact_validator_actor() -> Arc<dyn MethodActor> {
    actor("contact_validator", "Validate Contact Info", 10, |items| {
        items
            .into_iter()
            .filter(|item| {
                matches!(
                    classifier::classify(item).kind,
                    EntityKind::Email | EntityKind::Phone | EntityKind::Domain
                )
            })
            .collect()
    })
}

/// Give scheme-less values `https://` and lowercase the scheme and host. Paths, queries
/// and userinfo keep their case because they are case-sensitive.
#[must_use]
pub fn url_normalizer_actor() -> Arc<dyn MethodActor> {
    actor("url_normalizer", "Normalize URLs", 12, |items| {
        items
            .into_iter()
            .map(|item| normalize_url(item.trim()))
            .collect()
    })
}

fn normalize_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => format!("{userinfo}@{}", host.to_ascii_lowercase()),
        None => authority.to_ascii_lowercase(),
    };
    format!("{}://{authority}{tail}", scheme.to_ascii_lowercase())
}

/// Emit the lowercase host of each URL; drop values that are not URLs.
#[must_use]
pub fn hostname_extractor_actor() -> Arc<dyn MethodActor> {
    actor("hostname_extractor", "Extract Hostnames", 10, |items| {
        items
            .iter()
            .filter(|item| item.contains("://"))
            .filter_map(|item| value_syntax::host_from_url(item))
            .collect()
    })
}

/// Drop placeholder and non-routable indicators. See [`is_false_positive`].
#[must_use]
pub fn false_positive_filter_actor() -> Arc<dyn MethodActor> {
    actor("fp_filter", "Filter False Positives", 8, |items| {
        items
            .into_iter()
            .filter(|item| !is_false_positive(&classifier::classify(item)))
            .collect()
    })
}

/// Keep only values the engine classifies as domain names.
#[must_use]
pub fn domain_registry_validator_actor() -> Arc<dyn MethodActor> {
    actor("domain_registry", "Validate Domain Names", 10, |items| {
        items
            .into_iter()
            .filter(|item| classifier::classify(item).kind == EntityKind::Domain)
            .collect()
    })
}

/// Truncate each value to `max_chars` characters, marking cut values with `...`.
#[must_use]
pub fn evidence_snippet_actor(max_chars: usize) -> Arc<dyn MethodActor> {
    actor(
        "evidence_snippet",
        "Extract Evidence Snippets",
        6,
        move |items| {
            items
                .into_iter()
                .map(|item| match item.char_indices().nth(max_chars) {
                    Some((cut, _)) => format!("{}...", &item[..cut]),
                    None => item,
                })
                .collect()
        },
    )
}

/// Emit each canonical value followed by the relations its syntax alone proves: an
/// email's domain (`email_of:`) and a host's parent domain (`subdomain_of:`).
#[must_use]
pub fn relationship_resolver_actor() -> Arc<dyn MethodActor> {
    actor(
        "relationship_resolver",
        "Resolve Relationships",
        20,
        |items| {
            items
                .iter()
                .flat_map(|item| {
                    let classified = classifier::classify(item);
                    let relation = match classified.kind {
                        EntityKind::Email => {
                            email_domain(&classified).map(|d| format!("email_of:{d}"))
                        }
                        EntityKind::Domain => classified
                            .value
                            .split_once('.')
                            .map(|(_, parent)| parent)
                            .filter(|parent| {
                                classifier::classify(parent).kind == EntityKind::Domain
                            })
                            .map(|parent| format!("subdomain_of:{parent}")),
                        _ => None,
                    };
                    std::iter::once(classified.value).chain(relation)
                })
                .collect()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_actor::PipelineBuilder;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    fn false_positive(value: &str) -> bool {
        is_false_positive(&classifier::classify(value))
    }

    #[test]
    fn false_positives_follow_the_shared_placeholder_rules() {
        for value in [
            "user@example.com",
            "firstname.lastname@company.com",
            "127.0.0.1",
            "192.0.2.10",
            "intranet.local",
            "John Doe",
        ] {
            assert!(false_positive(value), "{value} should be a false positive");
        }
        for value in [
            "contest@company.com",
            "sysadmin@company.com",
            "demographics.gov.au",
            "democrats.org",
            "sampleton@company.com",
            "8.8.8.8",
            "Ada Lovelace",
        ] {
            assert!(!false_positive(value), "{value} is real evidence");
        }
    }

    #[test]
    fn entity_classifier_reports_the_engine_classification() {
        let out = entity_classifier_actor()
            .process(strings(&[
                "Ada@Analytical.org",
                "198.51.100.7",
                " analytical.org ",
                "0412 345 678",
            ]))
            .unwrap();
        let expected: Vec<String> = [
            "Ada@Analytical.org",
            "198.51.100.7",
            " analytical.org ",
            "0412 345 678",
        ]
        .iter()
        .map(|raw| {
            let c = classifier::classify(raw);
            format!("{}:{}", c.kind, c.value)
        })
        .collect();
        assert_eq!(out, expected);
        assert!(out[0].starts_with("email:"));
        assert!(out[1].starts_with("ip_address:"));
        assert_eq!(out[2], "domain:analytical.org");
        assert!(out[3].starts_with("phone:"));
    }

    #[test]
    fn url_normalizer_preserves_case_sensitive_parts() {
        let out = url_normalizer_actor()
            .process(strings(&[
                "HTTP://User@EXAMPLE.org/Path?Q=A",
                "Analytical.org/Notes",
            ]))
            .unwrap();
        assert_eq!(
            out,
            strings(&[
                "http://User@example.org/Path?Q=A",
                "https://analytical.org/Notes"
            ])
        );
    }

    #[test]
    fn evidence_snippets_cut_on_character_boundaries() {
        let out = evidence_snippet_actor(3)
            .process(strings(&["Zoë Ångström", "abc"]))
            .unwrap();
        assert_eq!(out, strings(&["Zoë...", "abc"]));
    }

    #[test]
    fn relationships_are_only_those_the_syntax_proves() {
        let out = relationship_resolver_actor()
            .process(strings(&[
                "ada@mail.analytical.org",
                "mail.analytical.org",
                "analytical.org",
            ]))
            .unwrap();
        assert_eq!(
            out,
            strings(&[
                "ada@mail.analytical.org",
                "email_of:mail.analytical.org",
                "mail.analytical.org",
                "subdomain_of:analytical.org",
                "analytical.org",
            ])
        );
    }

    #[test]
    fn organisation_domains_come_from_emails_urls_and_domains() {
        let out = organization_extractor_actor()
            .process(strings(&[
                "ada@Analytical.org",
                "https://www.babbage.net/engine",
                "www.lovelace.com",
                "198.51.100.7",
            ]))
            .unwrap();
        assert_eq!(
            out,
            strings(&["analytical.org", "babbage.net", "lovelace.com"])
        );
    }

    #[test]
    fn investigation_pipeline_triages_raw_indicators() {
        let pipeline = PipelineBuilder::new()
            .add_actor(false_positive_filter_actor())
            .add_actor(contact_validator_actor())
            .add_actor(entity_classifier_actor())
            .build()
            .unwrap();

        let run = pipeline
            .execute(strings(&[
                "ada@analytical.org",
                "test@example.com",
                "+61412345678",
                "127.0.0.1",
                "not an indicator",
                "babbage.net",
            ]))
            .unwrap();

        assert_eq!(run.output.len(), 3, "{:?}", run.output);
        assert_eq!(run.output[0], "email:ada@analytical.org");
        assert!(run.output[1].starts_with("phone:"));
        assert_eq!(run.output[2], "domain:babbage.net");
        assert_eq!(run.stages[0].items_processed, 6);
        assert_eq!(run.stages[0].items_successful, 4);
    }

    #[test]
    fn hostnames_come_only_from_urls() {
        let out = hostname_extractor_actor()
            .process(strings(&[
                "HTTPS://Analytical.org:8443/x",
                "analytical.org",
            ]))
            .unwrap();
        assert_eq!(out, strings(&["analytical.org"]));
    }
}
