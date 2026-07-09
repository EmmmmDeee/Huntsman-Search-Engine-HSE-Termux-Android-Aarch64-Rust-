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

/// SOA RNAME field is encoded as `local-part.domain` (no `@` allowed in DNS
/// labels), with any literal `.` in the local part backslash-escaped (RFC 1035
/// §8). Decode by splitting on the first *unescaped* `.` into `@`, then
/// **unescaping** the local part so `hostmaster\.ops.example.com` becomes
/// `hostmaster.ops@example.com`. Returns an empty string when the input doesn't
/// look like an email.
pub(super) fn soa_rname_to_email(rname: &str) -> String {
    if rname.is_empty() || !rname.contains('.') {
        return String::new();
    }
    let bytes = rname.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'.' {
            let (local, rest) = rname.split_at(i);
            let domain = &rest[1..];
            if local.is_empty() || domain.is_empty() {
                return String::new();
            }
            return format!("{}@{domain}", unescape_dns_label(local));
        }
        i += 1;
    }
    String::new()
}

/// Decode DNS presentation-format escapes in a label: `\DDD` (a decimal byte) or
/// `\X` (the literal char `X`, covering the common `\.` and `\\`). A trailing
/// lone `\` is dropped. **Pure**.
pub(super) fn unescape_dns_label(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // `\DDD` decimal escape (exactly three digits, ≤ 255).
        if i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
            && let Ok(n) = std::str::from_utf8(&bytes[i + 1..i + 4])
                .unwrap_or("")
                .parse::<u16>()
            && n <= 255
        {
            out.push(n as u8);
            i += 4;
        } else if i + 1 < bytes.len() {
            out.push(bytes[i + 1]); // `\X` → literal X (e.g. `\.` → `.`)
            i += 2;
        } else {
            i += 1; // trailing lone backslash — drop it
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True if `mx_host` shares `domain`'s registrable domain — i.e. self-hosted
/// mail, as opposed to a third-party provider (Google Workspace, Microsoft
/// 365, Mimecast, …). Mail delivery is essentially never proxied through a
/// web CDN, so a same-registrable-domain MX host is a strong origin-adjacency
/// signal when the web presence itself sits behind one — but only when the MX
/// host is actually *part of* the target's own infrastructure. A live probe
/// (2026-07-09) against real Cloudflare/Fastly-fronted sites confirmed both
/// halves of this: `python.org` (Fastly-fronted) self-hosts `mail.python.org`,
/// which resolves off Fastly's ranges — a genuine origin-adjacency lead. But
/// `ycombinator.com`/`signal.org`/`mozilla.org` (also CDN-fronted) all route
/// mail through Google Workspace (`aspmx.l.google.com`), whose IPs belong to
/// Google and say nothing about the target's own hosting — flagging those
/// would be a false lead. Restricting to same-registrable-domain MX hosts
/// keeps the signal precise at the cost of recall (deliberate: this project's
/// bar is "false positives are worse than missing coverage"). **Pure**.
#[must_use]
pub(super) fn is_self_hosted_mx(mx_host: &str, domain: &str) -> bool {
    let mx_reg = crate::util::domains::registrable_domain(mx_host);
    let domain_reg = crate::util::domains::registrable_domain(domain);
    mx_reg.is_some() && mx_reg == domain_reg
}

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
