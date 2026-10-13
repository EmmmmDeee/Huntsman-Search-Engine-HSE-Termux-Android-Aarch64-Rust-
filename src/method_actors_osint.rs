//! OSINT method actors.
//!
//! Every syntax and placeholder decision here delegates to the crate's shared rules in
//! [`crate::value_syntax`] and [`crate::validation`]; these actors only compose them.

use std::net::IpAddr;
use std::sync::Arc;

use crate::method_actor::{ActorMetadata, FunctionActor, MethodActor};
use crate::validation::{self, ValueKind};
use crate::value_syntax;

/// The kind of value an indicator string holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorKind {
    Ip,
    Email,
    Url,
    Domain,
    Phone,
    Other,
}

impl IndicatorKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Email => "email",
            Self::Url => "url",
            Self::Domain => "domain",
            Self::Phone => "phone",
            Self::Other => "other",
        }
    }
}

/// A domain under the shared syntax rules whose top-level label is not all digits.
fn domain_name(value: &str) -> Option<String> {
    value_syntax::canonical_domain(value)
        .filter(|domain| domain.rsplit('.').next().is_some_and(has_ascii_letter))
}

fn has_ascii_letter(label: &str) -> bool {
    label.bytes().any(|b| b.is_ascii_alphabetic())
}

fn email_domain(value: &str) -> Option<String> {
    if !validation::validate_email_syntax(value).valid {
        return None;
    }
    value
        .rsplit_once('@')
        .and_then(|(_, host)| domain_name(host))
}

/// Classify one indicator. IP literals are checked before domains so dotted quads are
/// never read as host names.
#[must_use]
pub fn classify_indicator(value: &str) -> IndicatorKind {
    let value = value.trim();
    if value.parse::<IpAddr>().is_ok() {
        IndicatorKind::Ip
    } else if value.contains('@') && email_domain(value).is_some() {
        IndicatorKind::Email
    } else if value.contains("://") && value_syntax::host_from_url(value).is_some() {
        IndicatorKind::Url
    } else if domain_name(value).is_some() {
        IndicatorKind::Domain
    } else if value_syntax::canonical_phone(value).is_some()
        || value_syntax::phone_e164_error(value).is_none()
    {
        IndicatorKind::Phone
    } else {
        IndicatorKind::Other
    }
}

/// True when the shared rules mark the value as a placeholder or non-routable address
/// rather than a real-world indicator.
#[must_use]
pub fn is_false_positive(value: &str) -> bool {
    let value = value.trim();
    match classify_indicator(value) {
        IndicatorKind::Ip => validation::is_non_routable_ip(value),
        IndicatorKind::Email => validation::is_placeholder_entity(&ValueKind::Email, value),
        IndicatorKind::Url => validation::is_placeholder_entity(&ValueKind::Url, value),
        IndicatorKind::Domain => validation::is_placeholder_entity(&ValueKind::Domain, value),
        IndicatorKind::Phone | IndicatorKind::Other => false,
    }
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

/// Prefix each value with its kind: `email:a@b.com`.
#[must_use]
pub fn entity_classifier_actor() -> Arc<dyn MethodActor> {
    actor("entity_classifier", "Classify Entity Types", 12, |items| {
        items
            .into_iter()
            .map(|item| {
                let value = item.trim();
                format!("{}:{value}", classify_indicator(value).label())
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
                .into_iter()
                .filter_map(|item| {
                    let value = item.trim();
                    match classify_indicator(value) {
                        IndicatorKind::Email => email_domain(value),
                        IndicatorKind::Url => value_syntax::host_from_url(value)
                            .and_then(|host| value_syntax::canonical_domain_host(&host)),
                        IndicatorKind::Domain => value_syntax::canonical_domain_host(value),
                        _ => None,
                    }
                })
                .collect()
        },
    )
}

/// Keep only emails, phone numbers and domains.
#[must_use]
pub fn contact_validator_actor() -> Arc<dyn MethodActor> {
    actor("contact_validator", "Validate Contact Info", 10, |items| {
        items
            .into_iter()
            .filter(|item| {
                matches!(
                    classify_indicator(item),
                    IndicatorKind::Email | IndicatorKind::Phone | IndicatorKind::Domain
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
            .into_iter()
            .filter(|item| item.contains("://"))
            .filter_map(|item| value_syntax::host_from_url(&item))
            .collect()
    })
}

/// Drop placeholder and non-routable indicators. See [`is_false_positive`].
#[must_use]
pub fn false_positive_filter_actor() -> Arc<dyn MethodActor> {
    actor("fp_filter", "Filter False Positives", 8, |items| {
        items
            .into_iter()
            .filter(|item| !is_false_positive(item))
            .collect()
    })
}

/// Keep only syntactically valid domain names.
#[must_use]
pub fn domain_registry_validator_actor() -> Arc<dyn MethodActor> {
    actor("domain_registry", "Validate Domain Names", 10, |items| {
        items
            .into_iter()
            .filter(|item| domain_name(item).is_some())
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

/// Emit each value followed by the relations its syntax alone proves: an email's domain
/// (`email_of:`), and a host's parent domain (`subdomain_of:`).
#[must_use]
pub fn relationship_resolver_actor() -> Arc<dyn MethodActor> {
    actor(
        "relationship_resolver",
        "Resolve Relationships",
        20,
        |items| {
            items
                .into_iter()
                .flat_map(|item| {
                    let value = item.trim().to_string();
                    let mut relations = Vec::new();
                    match classify_indicator(&value) {
                        IndicatorKind::Email => {
                            if let Some(domain) = email_domain(&value) {
                                relations.push(format!("email_of:{domain}"));
                            }
                        }
                        IndicatorKind::Domain => {
                            if let Some(parent) = domain_name(&value)
                                .and_then(|d| d.split_once('.').map(|(_, p)| p.to_string()))
                                .filter(|parent| domain_name(parent).is_some())
                            {
                                relations.push(format!("subdomain_of:{parent}"));
                            }
                        }
                        _ => {}
                    }
                    std::iter::once(value).chain(relations)
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

    #[test]
    fn classification_separates_ips_phones_and_domains() {
        let cases = [
            ("198.51.100.7", IndicatorKind::Ip),
            ("2001:db8::1", IndicatorKind::Ip),
            ("ada@analytical.org", IndicatorKind::Email),
            ("https://Analytical.org/Engine", IndicatorKind::Url),
            ("mail.analytical.org", IndicatorKind::Domain),
            ("+61412345678", IndicatorKind::Phone),
            ("0412 345 678", IndicatorKind::Phone),
            ("1.2.3", IndicatorKind::Other),
            ("ada lovelace", IndicatorKind::Other),
            ("a@b@c.com", IndicatorKind::Other),
        ];
        for (value, kind) in cases {
            assert_eq!(classify_indicator(value), kind, "{value}");
        }
    }

    #[test]
    fn false_positives_follow_the_shared_placeholder_rules() {
        for value in [
            "user@example.com",
            "firstname.lastname@company.com",
            "127.0.0.1",
            "192.0.2.10",
            "intranet.local",
        ] {
            assert!(
                is_false_positive(value),
                "{value} should be a false positive"
            );
        }
        for value in [
            "contest@company.com",
            "sysadmin@company.com",
            "demographics.gov.au",
            "democrats.org",
            "sampleton@company.com",
            "8.8.8.8",
        ] {
            assert!(!is_false_positive(value), "{value} is real evidence");
        }
    }

    #[test]
    fn entity_classifier_labels_every_value() {
        let out = entity_classifier_actor()
            .process(strings(&[
                "ada@analytical.org",
                "198.51.100.7",
                " analytical.org ",
            ]))
            .unwrap();
        assert_eq!(
            out,
            strings(&[
                "email:ada@analytical.org",
                "ip:198.51.100.7",
                "domain:analytical.org"
            ])
        );
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

        assert_eq!(
            run.output,
            strings(&[
                "email:ada@analytical.org",
                "phone:+61412345678",
                "domain:babbage.net"
            ])
        );
        assert_eq!(run.stages.len(), 3);
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
