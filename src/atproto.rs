//! AT Protocol handle and DID helpers.

#[must_use]
pub fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

#[must_use]
pub fn is_handle(value: &str) -> bool {
    crate::textnorm::is_domain_handle(value)
}

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
    is_handle(host).then_some(host)
}

pub const PLATFORM_HANDLE_SUFFIXES: &[&str] =
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

#[must_use]
pub fn handle_labels(handle: &str) -> usize {
    handle.split('.').filter(|label| !label.is_empty()).count()
}

#[must_use]
pub fn handle_domain_confidence(current: bool, handle: &str) -> f64 {
    match (current, handle_labels(handle) <= 2) {
        (true, true) => 0.93,
        (true, false) | (false, true) => 0.81,
        (false, false) => 0.42,
    }
}

pub const DOMAIN_HANDLE_ATTRIBUTION: &str = "AT Protocol verifies a domain handle by DNS TXT at _atproto.<domain> or by HTTPS /.well-known/atproto-did while the handle is in force";
pub const DOMAIN_HANDLE_CAVEAT: &str = "A domain handle proves DNS or web-root control at the time, not ongoing domain registration ownership; operator-issued subdomain handles should be corroborated separately";

#[must_use]
pub fn is_bluesky_operated_pds(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "bsky.social" || host == "bsky.network" || host.ends_with(".bsky.network")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_labels_handles_and_dids() {
        assert!(is_dns_label("alice"));
        assert!(!is_dns_label("_alice"));
        assert!(is_handle("alice.dev"));
        assert!(!is_handle("alice"));
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
            handle_domain_confidence(true, "pfrazee.com")
                > handle_domain_confidence(false, "alice.pds.example.org")
        );
        assert!(is_bluesky_operated_pds("morel.us-east.host.bsky.network"));
        assert!(!is_bluesky_operated_pds("pds.robocracy.org"));
    }
}
