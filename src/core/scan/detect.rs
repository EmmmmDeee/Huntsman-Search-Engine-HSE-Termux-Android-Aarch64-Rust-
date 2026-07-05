//! Target-kind shape predicates: pure string classifiers used by
//! `TargetKind::detect` to recognise CIDR / MAC / phone / domain / company /
//! address inputs before the structured-kind fall-through. No scan state.

/// A CIDR network block: `IP/prefix` where `IP` parses and `prefix` is within
/// the address family's width (≤32 for v4, ≤128 for v6). Pure.
pub(super) fn is_cidr_shaped(v: &str) -> bool {
    let Some((ip, prefix)) = v.split_once('/') else {
        return false;
    };
    let Ok(addr) = ip.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
    matches!(prefix.trim().parse::<u8>(), Ok(p) if p <= max)
}

/// Six 2-hex-digit octets joined by ':' or '-' (`aa:bb:cc:dd:ee:ff`), or the
/// Cisco dotted form of three 4-hex-digit groups (`aabb.ccdd.eeff`) — the same
/// separator set `Target::validate` accepts for MacAddress. A 6-group colon
/// form is not a valid IPv6 address (which needs 8 groups or `::`), so the
/// IP check ahead of this in [`super::TargetKind::detect`] never steals a real MAC.
pub(super) fn is_mac_shaped(v: &str) -> bool {
    let sep = if v.contains(':') {
        ':'
    } else if v.contains('-') {
        '-'
    } else if v.contains('.') {
        // Cisco dotted form: three 4-hex-digit groups (`aabb.ccdd.eeff`).
        // `Target::validate` for MacAddress explicitly accepts '.'-separated
        // MACs, so detection must recognise the same form — without this arm a
        // dotted MAC fell through to the LATER shape checks and was
        // misclassified as a Domain (`aabb.ccdd.eeff` — 3 labels, alphabetic
        // hex "TLD") or a Username (when a group carries a digit), scanning a
        // device identifier as a junk host. Precedence over Domain is
        // deliberate: an all-hex 4.4.4 string in OSINT input is overwhelmingly
        // a Cisco-format MAC, not a registrable host.
        let groups: Vec<&str> = v.split('.').collect();
        return groups.len() == 3
            && groups
                .iter()
                .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()));
    } else {
        return false;
    };
    let octets: Vec<&str> = v.split(sep).collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A dialable phone number: 7–15 digits with only phone punctuation
/// (`+ - space ( ) .`), and any `+` only as the leading character.
pub(super) fn is_phone_shaped(v: &str) -> bool {
    let digits = v.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits) {
        return false;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'))
    {
        return false;
    }
    // A '+' is allowed only once, and only as the leading character (the
    // international-dialling form); `+123+4567` is not a phone number.
    let plus = v.chars().filter(|&c| c == '+').count();
    plus == 0 || (plus == 1 && v.trim_start().starts_with('+'))
}

/// Domain-name shape: no whitespace/'@', at least one dot, only label chars
/// (`alnum . - _`), non-empty labels, and a TLD of ≥2 ASCII letters.
pub(super) fn is_domain_shaped(v: &str) -> bool {
    if v.contains(char::is_whitespace) || v.contains('@') || !v.contains('.') {
        return false;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return false;
    }
    let labels: Vec<&str> = v.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    match labels.last() {
        Some(tld) => tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()),
        None => false,
    }
}

/// `value` (already lowercased) ends with a recognised company-form suffix.
pub(super) fn has_company_suffix(lower: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        " pty ltd",
        " pty. ltd.",
        " pty limited",
        " inc",
        " inc.",
        " llc",
        " l.l.c.",
        " ltd",
        " ltd.",
        " limited",
        " corp",
        " corp.",
        " corporation",
        " gmbh",
        " plc",
        " ag",
        " s.a.",
        " b.v.",
    ];
    SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Street-address shape: a leading house number, then a space and an alphabetic
/// word (`123 Main St`, `42 Wallaby Way, Sydney`). Requires the leading number
/// so it never swallows a bare name; coordinates/phones are matched earlier.
pub(super) fn is_address_shaped(v: &str) -> bool {
    let house = v.bytes().take_while(u8::is_ascii_digit).count();
    if house == 0 {
        return false;
    }
    let rest = v[house..].trim_start();
    rest.chars().next().is_some_and(char::is_alphabetic) && v.contains(' ')
}

/// Google tracking identifier shape.
///
/// Matches:
/// - Universal Analytics: `UA-XXXXXXX-X` (UA- + 4–10 digits + dash + 1–4 digits)
/// - GA4:                  `G-XXXXXXXXXX` (G- + 2–12 alphanumeric)
/// - Google Tag Manager:   `GTM-XXXXXXX`  (GTM- + 4–10 alphanumeric)
/// - Google Ads:           `AW-XXXXXXXXX` (AW- + 9–12 digits)
pub(super) fn is_tracking_id_shaped(v: &str) -> bool {
    let u = v.trim().to_ascii_uppercase();
    // UA-XXXXXXX-X
    if let Some(rest) = u.strip_prefix("UA-") {
        let parts: Vec<&str> = rest.splitn(2, '-').collect();
        if parts.len() == 2 {
            let (a, b) = (parts[0], parts[1]);
            return a.len() >= 4
                && a.len() <= 10
                && a.chars().all(|c| c.is_ascii_digit())
                && !b.is_empty()
                && b.len() <= 4
                && b.chars().all(|c| c.is_ascii_digit());
        }
    }
    // G-XXXXXXXXXX (GA4)
    if let Some(rest) = u.strip_prefix("G-") {
        return rest.len() >= 2
            && rest.len() <= 12
            && rest.chars().all(|c| c.is_ascii_alphanumeric());
    }
    // GTM-XXXXXXX
    if let Some(rest) = u.strip_prefix("GTM-") {
        return rest.len() >= 4
            && rest.len() <= 10
            && rest.chars().all(|c| c.is_ascii_alphanumeric());
    }
    // AW-XXXXXXXXX (Google Ads)
    if let Some(rest) = u.strip_prefix("AW-") {
        return rest.len() >= 9 && rest.len() <= 12 && rest.chars().all(|c| c.is_ascii_digit());
    }
    false
}
