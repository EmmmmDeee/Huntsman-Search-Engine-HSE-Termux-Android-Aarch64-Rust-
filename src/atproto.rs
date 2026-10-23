//! AT Protocol handle and DID helpers.

use crate::canonical::canonical_domain;

#[must_use]
pub fn is_plc_did(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("did:plc:") else {
        return false;
    };
    suffix.len() == 24
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}

#[must_use]
pub fn web_did_host(value: &str) -> Option<&str> {
    let host = value.strip_prefix("did:web:")?;
    canonical_domain(host).is_some().then_some(host)
}

const PLATFORM_HANDLE_SUFFIXES: &[&str] =
    &[".bsky.social", ".bsky.team", ".brid.gy", ".translate.goog"];

#[must_use]
pub fn platform_handle_suffix(handle: &str) -> Option<&'static str> {
    let lower = handle.to_ascii_lowercase();
    PLATFORM_HANDLE_SUFFIXES
        .iter()
        .copied()
        .find(|suffix| lower.ends_with(suffix))
}

#[must_use]
pub fn bare_handle(handle: &str) -> &str {
    match platform_handle_suffix(handle) {
        Some(suffix) => &handle[..handle.len() - suffix.len()],
        None => handle,
    }
}

fn handle_labels(handle: &str) -> usize {
    handle.split('.').filter(|label| !label.is_empty()).count()
}

/// How far a current domain handle stands for its domain: a registrable name (two labels)
/// more than a subdomain an operator may have issued.
#[must_use]
pub fn handle_domain_confidence(handle: &str) -> f64 {
    if handle_labels(handle) <= 2 {
        0.93
    } else {
        0.81
    }
}

pub const DOMAIN_HANDLE_ATTRIBUTION: &str = "AT Protocol verifies a domain handle by DNS TXT at _atproto.<domain> or by HTTPS /.well-known/atproto-did while the handle is in force";
pub const DOMAIN_HANDLE_CAVEAT: &str = "A domain handle proves DNS or web-root control at the time, not ongoing domain registration ownership; operator-issued subdomain handles should be corroborated separately";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_dids() {
        assert!(is_plc_did("did:plc:oky5czdrnfjpqslsw2a5iclo"));
        assert!(!is_plc_did("did:plc:../../../../etc/passwd/xx"));
        assert_eq!(web_did_host("did:web:example.com"), Some("example.com"));
        assert_eq!(web_did_host("did:web:example.com%3A8443"), None);
    }

    #[test]
    fn handles_platform_suffixes_and_confidence() {
        assert_eq!(bare_handle("alice.bsky.social"), "alice");
        assert_eq!(bare_handle("pfrazee.com"), "pfrazee.com");
        assert_eq!(
            platform_handle_suffix("Alice.BSKY.Social"),
            Some(".bsky.social")
        );
        assert!(
            handle_domain_confidence("pfrazee.com")
                > handle_domain_confidence("alice.pds.example.org")
        );
    }
}
