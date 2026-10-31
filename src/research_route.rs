//! Pure, subject-neutral routing for a universal research request.
//!
//! The existing `scan` command deliberately treats arbitrary free text as a person, and refuses
//! single words. A universal research request must not quietly assign that meaning: recognised
//! exact identifiers use the existing scan route; otherwise the keyless adaptive search is used.
//! This layer neither fetches nor constructs a new source client, evidence store or scheduler.

use crate::network_selector::NetworkSelector;
use crate::scan_route::{ScanKind, canonical_selector, infer_kind};

/// The existing Huntsman capability chosen for one research term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchAction {
    /// An exact, recognised selector can use the established typed lookup.
    Targeted { kind: ScanKind, selector: String },
    /// Free text or an ambiguous phrase is a web-search lead, not a person identity.
    AdaptiveWeb { query: String },
}

const MAX_RESEARCH_BYTES: usize = 512;

/// Resolve one arbitrary research term without network access.
///
/// This is intentionally conservative: free text, including a plausible person's name, stays
/// general research rather than automatically consulting person-lookup providers. A coordinate
/// pair selects GEOINT instead of the older `scan` default of a radio-area lookup.
///
/// # Errors
/// Rejects empty text, overly long text and control characters before any operation is routed.
pub fn plan(input: &str) -> Result<ResearchAction, &'static str> {
    if input.len() > MAX_RESEARCH_BYTES || input.chars().any(char::is_control) {
        return Err("research text exceeds 512 bytes or contains control characters");
    }
    let query = input.trim();
    if query.is_empty() {
        return Err("research requires a non-empty term");
    }

    let inferred = infer_kind(query);
    // The shared scan inference recognises *public* addresses and blocks. Without this guard a
    // private literal may instead be classified as a domain, or an excluded CIDR as free text,
    // sending the address to unrelated search providers. Fail closed before any network work.
    let is_ip_literal = query.parse::<std::net::IpAddr>().is_ok();
    let is_ip_block = query
        .split_once('/')
        .is_some_and(|(address, _)| address.parse::<std::net::IpAddr>().is_ok());
    if (is_ip_literal && inferred != ScanKind::Ip)
        || (is_ip_block && inferred != ScanKind::Netblock)
    {
        return Err("invalid or non-public IP address or network block");
    }
    let kind = match inferred {
        // A free-text name is an interpretation, not an observed identity.
        ScanKind::People => {
            return Ok(ResearchAction::AdaptiveWeb {
                query: query.into(),
            });
        }
        // A point is geographic for general research; the existing scan command retains its
        // radio-area precedence for compatibility.
        ScanKind::Network
            if matches!(
                NetworkSelector::parse_identifier(query),
                Some(NetworkSelector::Area { .. })
            ) =>
        {
            ScanKind::Place
        }
        kind => kind,
    };
    let selector = canonical_selector(kind, query).ok_or("invalid research selector")?;
    Ok(ResearchAction::Targeted { kind, selector })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_is_not_forced_into_person_lookup() {
        for query in [
            "vape",
            "Ada Lovelace",
            "open source mapping tools",
            "historical records of Example Organisation",
            "https://example.org/path",
        ] {
            assert_eq!(
                plan(query),
                Ok(ResearchAction::AdaptiveWeb {
                    query: query.to_owned()
                }),
                "{query}"
            );
        }
    }

    #[test]
    fn typed_selectors_reuse_existing_routes() {
        for (query, kind) in [
            ("example.org", ScanKind::Domain),
            ("test@example.org", ScanKind::Email),
            ("@Some_Name", ScanKind::Username),
            ("1.1.1.1", ScanKind::Ip),
            ("AS13335", ScanKind::Asn),
            ("aa:bb:cc:dd:ee:ff", ScanKind::Network),
        ] {
            let ResearchAction::Targeted { kind: actual, .. } = plan(query).unwrap() else {
                panic!("{query} was not routed to a typed lookup");
            };
            assert_eq!(actual, kind, "{query}");
        }
    }

    #[test]
    fn coordinates_use_existing_geocode_and_bssids_keep_network_route() {
        assert_eq!(
            plan("-27.4705,153.0260"),
            Ok(ResearchAction::Targeted {
                kind: ScanKind::Place,
                selector: "-27.4705,153.0260".into(),
            })
        );
        assert!(matches!(
            plan("aa:bb:cc:dd:ee:ff"),
            Ok(ResearchAction::Targeted {
                kind: ScanKind::Network,
                ..
            })
        ));
    }

    #[test]
    fn original_case_is_kept_for_ambiguous_terms_and_case_sensitive_handles() {
        assert_eq!(
            plan("  PG_Smith  "),
            Ok(ResearchAction::AdaptiveWeb {
                query: "PG_Smith".into(),
            })
        );
        assert_eq!(
            plan("@PG_Smith"),
            Ok(ResearchAction::Targeted {
                kind: ScanKind::Username,
                selector: "PG_Smith".into(),
            })
        );
    }

    #[test]
    fn ip_syntax_never_falls_through_to_domain_or_adaptive_search() {
        for input in [
            "10.0.0.5",
            "192.168.1.20",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "fc00::/7",
            "1.1.1.1/33",
            "10.0.0.5/not-a-prefix",
        ] {
            assert!(plan(input).is_err(), "{input} must not reach a provider");
        }
        assert!(matches!(
            plan("1.1.1.1"),
            Ok(ResearchAction::Targeted {
                kind: ScanKind::Ip,
                ..
            })
        ));
        assert!(matches!(
            plan("1.1.1.0/24"),
            Ok(ResearchAction::Targeted {
                kind: ScanKind::Netblock,
                ..
            })
        ));
    }

    #[test]
    fn refuses_invalid_inputs_without_fallback_network_work() {
        for input in ["", "  ", "name\nother", "x\0y", &"x".repeat(513)] {
            assert!(plan(input).is_err(), "{input:?}");
        }
    }
}
