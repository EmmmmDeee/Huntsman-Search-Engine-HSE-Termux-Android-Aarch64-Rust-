/// Reverse the octets of an IPv4 address for DNSBL queries.
/// Returns `None` for IPv6 (unsupported by most blocklists) and invalid input.
pub(super) fn reverse_ip(ip: &str) -> Option<String> {
    let parsed: std::net::IpAddr = ip.parse().ok()?;
    match parsed {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!(
                "{}.{}.{}.{}",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        std::net::IpAddr::V6(_) => None,
    }
}

/// Re-export the SOA RNAME decoder from the shared DNS utilities so this
/// module's `resolve` leg keeps calling it under the original path. The decoder
/// (and the `unescape_dns_label` primitive it builds on) is single-sourced in
/// `util::dns`; T2.125 folded this module's former private copy into it.
pub(super) use crate::util::dns::soa_rname_to_email;

/// Domain-ownership verification TXT prefixes → the vendor they prove a
/// relationship with. A published verification record discloses which SaaS the
/// organisation has onboarded — real OSINT for mapping its vendor/tech stack.
/// Curated from each provider's published setup docs and matched
/// case-insensitively; a prefix that is even slightly wrong simply never matches
/// (no false positives), so the table fails safe.
pub(super) const VERIFICATION_VENDORS: &[(&str, &str)] = &[
    ("google-site-verification=", "google"),
    ("facebook-domain-verification=", "facebook"),
    ("apple-domain-verification=", "apple"),
    ("atlassian-domain-verification=", "atlassian"),
    ("adobe-idp-site-verification=", "adobe"),
    ("adobe-sign-verification=", "adobe"),
    ("stripe-verification=", "stripe"),
    ("docusign=", "docusign"),
    ("dropbox-domain-verification=", "dropbox"),
    ("zoom-domain-verification=", "zoom"),
    ("globalsign-domain-verification=", "globalsign"),
    ("pinterest-site-verification=", "pinterest"),
    ("cisco-ci-domain-verification=", "cisco"),
    ("hubspot-developer-verification=", "hubspot"),
    ("salesforce-authorization-verification=", "salesforce"),
    ("loaderio=", "loaderio"),
    ("twilio-domain-verification=", "twilio"),
    ("yandex-verification:", "yandex"),
    ("shopify-domain-verification=", "shopify"),
    // Microsoft 365 tenant verification — short and generic, so it is matched
    // last (nothing else in the table shares this prefix).
    ("ms=", "microsoft"),
];

/// The vendor a TXT record verifies domain ownership for, if any. **Pure**:
/// a case-insensitive prefix match against [`VERIFICATION_VENDORS`].
pub(super) fn verification_vendor(txt: &str) -> Option<&'static str> {
    let b = txt.as_bytes();
    VERIFICATION_VENDORS.iter().find_map(|(prefix, vendor)| {
        let p = prefix.as_bytes();
        (b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p)).then_some(*vendor)
    })
}
