//! Native declarative source routing for lightweight OSINT pivots.
//!
//! This registry is intentionally Huntsman-authored. It does not embed or copy an
//! external catalogue. A route is a lead-generation action, not evidence; fetched
//! material must still pass Huntsman's normal provenance and source-outcome gates.

use crate::entity::EntityKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCategory {
    WebSearch,
    Archive,
    DomainIntel,
    Infrastructure,
    Identity,
    Geo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    SearchUrl,
    BrowserRequired,
}

impl ExecutionMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SearchUrl => "search_url",
            Self::BrowserRequired => "browser_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAccess {
    Public,
    Account,
}

impl SourceAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Account => "account",
        }
    }
}

/// How a route may be used in the evidence system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRole {
    /// The generated URL is discovery only. It never corroborates a claim itself.
    LeadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub category: SourceCategory,
    pub accepted_kinds: &'static [EntityKind],
    pub execution: ExecutionMode,
    pub access: SourceAccess,
    pub url_template: &'static str,
    /// Provider-owned or otherwise first-party landing page used to identify the source.
    pub reference_url: &'static str,
    pub evidence_role: EvidenceRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRoute {
    pub source_id: &'static str,
    pub source_name: &'static str,
    pub category: SourceCategory,
    pub execution: ExecutionMode,
    pub access: SourceAccess,
    pub url: String,
    pub reference_url: &'static str,
    pub evidence_role: EvidenceRole,
}

const IDENTITY_SEARCH: &[EntityKind] = &[
    EntityKind::Person,
    EntityKind::Organisation,
    EntityKind::Email,
    EntityKind::Username,
];
const DOMAIN_ONLY: &[EntityKind] = &[EntityKind::Domain];
const IP_ONLY: &[EntityKind] = &[EntityKind::IpAddress];
const USERNAME_ONLY: &[EntityKind] = &[EntityKind::Username];
const COORDINATES_ONLY: &[EntityKind] = &[EntityKind::Coordinates];

/// Small, independently curated bootstrap set. The architecture is designed to grow
/// by adding descriptors rather than one Rust module per external search surface.
static SOURCES: &[SourceDescriptor] = &[
    SourceDescriptor {
        id: "google_exact",
        name: "Google exact search",
        category: SourceCategory::WebSearch,
        accepted_kinds: IDENTITY_SEARCH,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://www.google.com/search?q=%22{value}%22",
        reference_url: "https://www.google.com/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "bing_exact",
        name: "Bing exact search",
        category: SourceCategory::WebSearch,
        accepted_kinds: IDENTITY_SEARCH,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://www.bing.com/search?q=%22{value}%22",
        reference_url: "https://www.bing.com/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "google_site",
        name: "Google site search",
        category: SourceCategory::WebSearch,
        accepted_kinds: DOMAIN_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://www.google.com/search?q=site%3A{value}",
        reference_url: "https://www.google.com/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "wayback",
        name: "Internet Archive Wayback Machine",
        category: SourceCategory::Archive,
        accepted_kinds: DOMAIN_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://web.archive.org/web/*/{value}/*",
        reference_url: "https://web.archive.org/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "whois",
        name: "Whois.com",
        category: SourceCategory::DomainIntel,
        accepted_kinds: DOMAIN_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://www.whois.com/whois/{value}",
        reference_url: "https://www.whois.com/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "crtsh",
        name: "crt.sh certificate search",
        category: SourceCategory::DomainIntel,
        accepted_kinds: DOMAIN_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://crt.sh/?q=%25.{value}",
        reference_url: "https://crt.sh/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "urlscan",
        name: "urlscan.io domain view",
        category: SourceCategory::DomainIntel,
        accepted_kinds: DOMAIN_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://urlscan.io/domain/{value}",
        reference_url: "https://urlscan.io/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "shodan_host",
        name: "Shodan host view",
        category: SourceCategory::Infrastructure,
        accepted_kinds: IP_ONLY,
        execution: ExecutionMode::BrowserRequired,
        access: SourceAccess::Public,
        url_template: "https://www.shodan.io/host/{value}",
        reference_url: "https://www.shodan.io/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "bgp_he",
        name: "Hurricane Electric BGP Toolkit",
        category: SourceCategory::Infrastructure,
        accepted_kinds: IP_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://bgp.he.net/ip/{value}",
        reference_url: "https://bgp.he.net/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "github_users",
        name: "GitHub user search",
        category: SourceCategory::Identity,
        accepted_kinds: USERNAME_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://github.com/search?q={value}&type=users",
        reference_url: "https://github.com/",
        evidence_role: EvidenceRole::LeadOnly,
    },
    SourceDescriptor {
        id: "google_maps",
        name: "Google Maps coordinates",
        category: SourceCategory::Geo,
        accepted_kinds: COORDINATES_ONLY,
        execution: ExecutionMode::SearchUrl,
        access: SourceAccess::Public,
        url_template: "https://www.google.com/maps?q={value}",
        reference_url: "https://www.google.com/maps",
        evidence_role: EvidenceRole::LeadOnly,
    },
];

#[must_use]
pub const fn registry() -> &'static [SourceDescriptor] {
    SOURCES
}

#[must_use]
pub fn routes_for(kind: &EntityKind, value: &str) -> Vec<SourceRoute> {
    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }
    let encoded = percent_encode_component(value);
    SOURCES
        .iter()
        .filter(|source| {
            source
                .accepted_kinds
                .iter()
                .any(|candidate| candidate == kind)
        })
        .map(|source| SourceRoute {
            source_id: source.id,
            source_name: source.name,
            category: source.category,
            execution: source.execution,
            access: source.access,
            url: source.url_template.replace("{value}", &encoded),
            reference_url: source.reference_url,
            evidence_role: source.evidence_role,
        })
        .collect()
}

fn percent_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn registry_is_unique_https_and_renderable() {
        let mut ids = BTreeSet::new();
        for source in registry() {
            assert!(ids.insert(source.id), "duplicate source id {}", source.id);
            assert!(source.url_template.starts_with("https://"));
            assert!(source.reference_url.starts_with("https://"));
            assert_eq!(source.url_template.matches("{value}").count(), 1);
            assert_ne!(source.accepted_kinds, []);
        }
    }

    #[test]
    fn domain_fans_out_without_turning_routes_into_evidence() {
        let routes = routes_for(&EntityKind::Domain, "example.com");
        assert!(routes.len() >= 5);
        assert!(
            routes
                .iter()
                .all(|route| route.evidence_role == EvidenceRole::LeadOnly)
        );
        assert!(routes.iter().any(|route| route.source_id == "wayback"));
        assert!(routes.iter().any(|route| route.source_id == "crtsh"));
    }

    #[test]
    fn human_query_is_rfc3986_encoded() {
        let routes = routes_for(&EntityKind::Person, "Ada Lovelace");
        assert_ne!(routes, [] as [SourceRoute; 0]);
        assert!(
            routes
                .iter()
                .all(|route| route.url.contains("Ada%20Lovelace"))
        );
        assert!(
            routes
                .iter()
                .all(|route| !route.url.contains("Ada Lovelace"))
        );
    }
}
