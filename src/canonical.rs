//! Canonical forms for entity values and provenance labels.

use crate::evidence_ancestry::canonical_family;

const TRACKING_PARAMS: &[&str] = &[
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    "fbclid",
    "igshid",
    "igsh",
    "mibextid",
    "msclkid",
    "twclid",
    "ref_src",
    "ref_url",
    "yclid",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "_hsenc",
    "_hsmi",
    "hsctatracking",
    "vero_id",
    "vero_conv",
    "oly_anon_id",
    "oly_enc_id",
    "wickedid",
    "spm",
    "scm",
    "s_kwcid",
    "_openstat",
    "icid",
];

#[must_use]
pub fn canonical_whitespace(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

#[must_use]
pub fn canonical_name(raw: &str) -> String {
    canonical_whitespace(raw)
}

#[must_use]
pub fn canonical_handle(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_start_matches('@');
    if raw.len() > 40 {
        return None;
    }
    let trimmed = raw
        .chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(trimmed)
}

#[must_use]
pub fn canonical_domain(raw: &str) -> Option<String> {
    crate::value_syntax::canonical_domain(raw)
}

#[must_use]
pub fn canonical_domain_host(raw: &str) -> Option<String> {
    crate::value_syntax::canonical_domain_host(raw)
}

#[must_use]
pub fn canonical_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let (local, domain) = trimmed.split_once('@')?;
    if crate::value_syntax::email_local_error(local).is_some()
        || !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    {
        return None;
    }
    Some(format!("{local}@{}", canonical_domain(domain)?))
}

#[must_use]
pub fn canonical_phone(raw: &str) -> Option<String> {
    crate::value_syntax::canonical_phone(raw)
}

/// `raw` as a public unicast IP address in its standard text form (IPv6 compressed and
/// lower-case), or `None`. A bracketed IPv6 address is accepted. A private, loopback, link-local,
/// shared (CGNAT), documentation, benchmarking, multicast, reserved or unspecified address is
/// `None`: nothing public is known about it, and asking a provider would only disclose it.
#[must_use]
pub fn canonical_ip(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(raw);
    let ip: std::net::IpAddr = raw.parse().ok()?;
    is_public_ip(ip).then(|| ip.to_string())
}

/// A public address block in canonical form, `192.0.2.7/24` written `192.0.2.0/24`, or `None`
/// for a bare address, a malformed block, or a block whose first address is not public (see
/// [`is_public_ip`]): a private or documentation block is refused before any request. **Pure.**
#[must_use]
pub fn canonical_netblock(raw: &str) -> Option<String> {
    let block = crate::netblock::Netblock::parse(raw)?;
    is_public_ip(block.network()).then(|| block.to_string())
}

/// A public AS number written `AS13335`, from `AS13335`, `as13335`, `ASN13335` or the bare
/// `13335` Spiderfoot takes as a `BGP_AS_OWNER` target; `None` for anything else, or for a
/// number IANA reserves (RFC 7607 `AS0`, `AS_TRANS` 23456, the documentation, private-use and
/// reserved ranges of RFC 5398, RFC 6996 and RFC 7300). **Pure.**
#[must_use]
pub fn canonical_asn(raw: &str) -> Option<String> {
    let upper = raw.trim().to_ascii_uppercase();
    let digits = upper
        .strip_prefix("ASN")
        .or_else(|| upper.strip_prefix("AS"))
        .unwrap_or(&upper)
        .trim_start();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number: u32 = digits.parse().ok()?;
    is_public_asn(number).then(|| format!("AS{number}"))
}

/// Whether IANA leaves `asn` for assignment to a network. **Pure.**
#[must_use]
pub fn is_public_asn(asn: u32) -> bool {
    !matches!(asn, 0 | 23_456 | 64_496..=131_071 | 4_200_000_000..=u32::MAX)
}

/// Whether `ip` is public unicast: see [`canonical_ip`]. IPv6 is public only inside global
/// unicast `2000::/3` and outside the documentation and transition prefixes; an IPv4-mapped
/// address is judged as its IPv4 address. **Pure.**
#[must_use]
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_public_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ipv4(v4);
            }
            let s = v6.segments();
            let global_unicast = s[0] & 0xe000 == 0x2000;
            let documentation = s[0] == 0x2001 && s[1] == 0x0db8;
            // 2001::/23 holds Teredo, benchmarking and other IETF special-purpose blocks;
            // 2002::/16 is 6to4.
            let special = (s[0] == 0x2001 && s[1] < 0x0200) || s[0] == 0x2002;
            global_unicast && !documentation && !special
        }
    }
}

fn is_public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113);
    !reserved
}

#[must_use]
pub fn canonical_coordinates(raw: &str) -> Option<String> {
    let (lat, lon) = raw.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    if !((-90.0)..=90.0).contains(&lat) || !((-180.0)..=180.0).contains(&lon) {
        return None;
    }
    Some(format!("{lat:.6},{lon:.6}"))
}

/// A MAC address (BSSID) in the one form the crate stores: six `:`-separated hex pairs, lower
/// case. `-` separators are accepted. `None` for anything else. **Pure.**
#[must_use]
pub fn canonical_mac(raw: &str) -> Option<String> {
    let mac = raw.trim().replace('-', ":").to_ascii_lowercase();
    is_colon_mac(&mac).then_some(mac)
}

/// Six `:`-separated pairs of hex digits, in either case. **Pure.**
#[must_use]
pub fn is_colon_mac(value: &str) -> bool {
    let mut count = 0usize;
    for part in value.split(':') {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        count += 1;
    }
    count == 6
}

#[must_use]
pub fn canonical_provenance_family(raw: &str) -> String {
    canonical_family(raw)
}

#[must_use]
pub fn is_tracking_param_key(key: &str) -> bool {
    if key
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("utm_"))
    {
        return true;
    }
    TRACKING_PARAMS
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
}

#[must_use]
pub fn canonical_query(raw: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            if is_tracking_param_key(key) {
                None
            } else {
                Some((key.to_ascii_lowercase(), value.to_owned()))
            }
        })
        .collect();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(key, value)| {
            if value.is_empty() {
                key
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// One http(s) authority, one canonical `(host, port)`. The single gate for every URL key in the
/// crate: userinfo and bracketed hosts are refused, the port must be a `u16`, and the scheme's
/// default port (or an empty port) collapses to `None`.
#[must_use]
pub fn canonical_authority(scheme: &str, authority: &str) -> Option<(String, Option<u16>)> {
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
        return None;
    }
    let (raw_host, raw_port) = match authority.rsplit_once(':') {
        Some((host, _)) if host.contains(':') => return None,
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if raw_host.is_empty() {
        return None;
    }
    let host = canonical_domain(raw_host.trim_end_matches('.'))?;
    let port = match raw_port {
        None | Some("") => None,
        Some(value) => {
            if !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let parsed = value.parse::<u16>().ok()?;
            let default = match scheme.to_ascii_lowercase().as_str() {
                "http" => 80,
                "https" => 443,
                _ => 0,
            };
            (parsed != default).then_some(parsed)
        }
    };
    Some((host, port))
}

#[must_use]
pub fn canonical_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let (before_fragment, _) = rest.split_once('#').unwrap_or((rest, ""));
    let split = before_fragment
        .find(['/', '?'])
        .unwrap_or(before_fragment.len());
    let authority = &before_fragment[..split];
    let tail = &before_fragment[split..];
    let (host, port) = canonical_authority(scheme, authority)?;
    let port = port.map_or_else(String::new, |p| format!(":{p}"));
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let path = if path.is_empty() { "/" } else { path };
    let query = canonical_query(query);
    let rendered_path = if path == "/" { "" } else { path };
    let mut out = format!(
        "{}://{}{port}{rendered_path}",
        scheme.to_ascii_lowercase(),
        host
    );
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    Some(out)
}

/// One selector, one stored form. Email, phone, URL, domain, handle and
/// coordinates win before a name. Empty after normalisation is `None`.
#[must_use]
pub fn canonicalise_selector(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    canonical_email(trimmed)
        .or_else(|| canonical_phone(trimmed))
        .or_else(|| canonical_url(trimmed))
        .or_else(|| canonical_domain(trimmed))
        .or_else(|| canonical_handle(trimmed))
        .or_else(|| canonical_coordinates(trimmed))
        .or_else(|| {
            let name = canonical_name(trimmed);
            (!name.is_empty()).then_some(name)
        })
}

/// Source identifiers are tokens, not selectors.
#[must_use]
pub fn canonicalise_token(raw: &str) -> Option<String> {
    let token = raw.trim().to_ascii_lowercase();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_blocks_are_canonical_netblocks() {
        assert_eq!(
            canonical_netblock(" 1.1.1.9/24 ").as_deref(),
            Some("1.1.1.0/24")
        );
        assert_eq!(
            canonical_netblock("2606:4700::/32").as_deref(),
            Some("2606:4700::/32")
        );
        for refused in [
            "10.0.0.0/8",
            "192.0.2.0/24",
            "0.0.0.0/0",
            "2001:db8::/32",
            "1.1.1.1",
        ] {
            assert_eq!(canonical_netblock(refused), None, "{refused}");
        }
    }

    #[test]
    fn only_public_as_numbers_are_canonical() {
        for (raw, canonical) in [
            ("AS13335", "AS13335"),
            (" as13335 ", "AS13335"),
            ("ASN 4608", "AS4608"),
            ("13335", "AS13335"),
            ("AS0013335", "AS13335"),
            ("AS4199999999", "AS4199999999"),
        ] {
            assert_eq!(canonical_asn(raw).as_deref(), Some(canonical), "{raw}");
        }
        for refused in [
            "AS0",
            "AS23456",
            "AS64496",
            "AS64512",
            "AS65535",
            "AS65551",
            "AS131071",
            "AS4200000000",
            "AS4294967295",
            "AS4294967296",
            "AS",
            "AS-13335",
            "ASX1",
            "13335/24",
            "",
        ] {
            assert_eq!(canonical_asn(refused), None, "{refused}");
        }
    }

    #[test]
    fn only_public_unicast_addresses_are_canonical_ips() {
        assert_eq!(canonical_ip(" 1.1.1.1 ").as_deref(), Some("1.1.1.1"));
        assert_eq!(
            canonical_ip("[2606:4700:4700:0:0:0:0:1111]").as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(
            canonical_ip("::ffff:8.8.8.8").as_deref(),
            Some("::ffff:8.8.8.8")
        );
        for refused in [
            "10.0.0.1",
            "172.16.4.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "1.1.1",
            "example.com",
            "",
        ] {
            assert_eq!(canonical_ip(refused), None, "{refused}");
        }
    }

    #[test]
    fn handle_collapses_separators() {
        assert_eq!(
            canonical_handle("@Ada.Lovelace"),
            Some("adalovelace".into())
        );
        assert_eq!(canonical_handle(""), None);
    }

    #[test]
    fn handle_length_limit_applies_to_raw_handle() {
        let forty = "a".repeat(40);
        assert_eq!(canonical_handle(&format!("@{forty}")), Some(forty));
        let long_raw = "ab.".repeat(20);
        assert_eq!(canonical_handle(&long_raw), None);
    }

    #[test]
    fn canonical_email_never_accepts_what_validate_email_syntax_rejects() {
        let long_local = format!("{}@example.com", "a".repeat(65));
        for bad in [
            ".ada@example.com",
            "ada.@example.com",
            "a..da@example.com",
            long_local.as_str(),
        ] {
            assert!(
                !crate::validation::validate_email_syntax(bad).valid,
                "{bad}"
            );
            assert_eq!(canonical_email(bad), None, "{bad}");
        }
        let max_local = format!("{}@example.com", "a".repeat(64));
        assert!(canonical_email(&max_local).is_some());
        assert_eq!(
            canonical_email("a.b+c@example.co.uk"),
            Some("a.b+c@example.co.uk".into())
        );
    }

    #[test]
    fn email_and_domain_are_validated() {
        assert_eq!(
            canonical_email(" Ada@Test.EXAMPLE.com "),
            Some("ada@test.example.com".into())
        );
        assert_eq!(canonical_email("x@."), None);
        assert_eq!(canonical_domain("ExAmPlE.COM."), Some("example.com".into()));
        assert_eq!(
            canonical_domain_host(" WWW.Example.COM. "),
            Some("example.com".into())
        );
    }

    #[test]
    fn url_drops_tracking_query() {
        assert_eq!(
            canonical_url("https://Example.com/?utm_source=x&b=2&a=1"),
            Some("https://example.com?a=1&b=2".into())
        );
    }

    #[test]
    fn coordinates_and_phone_normalise() {
        assert_eq!(
            canonical_coordinates(" -27.4698 , 153.0251 "),
            Some("-27.469800,153.025100".into())
        );
        assert_eq!(
            canonical_phone("+61 412 345 678"),
            Some("+61412345678".into())
        );
        assert_eq!(canonical_phone("abc"), None);
    }

    #[test]
    fn selector_prefers_email_over_name() {
        assert_eq!(
            canonicalise_selector("  Ada@Example.COM "),
            Some("ada@example.com".into())
        );
        assert_eq!(
            canonicalise_selector("  Example.COM "),
            Some("example.com".into())
        );
        assert_eq!(canonicalise_selector("   "), None);
        assert_eq!(canonicalise_token(" CrtSh "), Some("crtsh".into()));
        assert_eq!(canonicalise_token("has space"), None);
    }
}

#[cfg(test)]
mod authority_contract_tests {
    use super::canonical_url;
    use crate::archive::parse_archive_url;

    #[test]
    fn canonical_url_and_archive_key_agree_on_authority() {
        // Default port written with a leading zero is still the default port.
        assert_eq!(
            canonical_url("https://Example.com:0443/a").as_deref(),
            Some("https://example.com/a")
        );
        // A port that is not a u16 is not a URL.
        assert_eq!(canonical_url("https://example.com:abc/a"), None);
        assert_eq!(canonical_url("https://example.com:99999/a"), None);
        // Userinfo never survives into a canonical form.
        assert_eq!(canonical_url("https://user:pw@example.com/a"), None);
        // Non-default ports are kept, normalised.
        assert_eq!(
            canonical_url("http://example.com:08080/").as_deref(),
            Some("http://example.com:8080")
        );
        for raw in [
            "https://example.com:0443/a",
            "https://example.com:abc/a",
            "https://user:pw@example.com/a",
            "http://example.com:08080/",
            "https://example.com./a?b=1",
        ] {
            assert_eq!(
                canonical_url(raw).is_some(),
                parse_archive_url(raw).is_some(),
                "{raw}: canonical_url and parse_archive_url disagree on validity"
            );
        }
    }
}
