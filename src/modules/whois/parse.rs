//! WHOIS response parsing helpers.
//!
//! All functions are pure (no I/O) and unit-testable against canned WHOIS
//! text. The [`WhoisFields`] struct is the typed product of [`parse_whois`].

/// True if `line`'s leading bytes match `key` ignoring ASCII case. Avoids the
/// per-line `to_lowercase()` allocation a `lower.starts_with(&lkey)` check
/// would force (WHOIS keys are pure ASCII).
pub(super) fn starts_with_ascii_ci(line: &str, key: &str) -> bool {
    line.len() >= key.len() && line.as_bytes()[..key.len()].eq_ignore_ascii_case(key.as_bytes())
}

pub(super) fn field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        for key in keys {
            if starts_with_ascii_ci(line, key)
                && let Some((_, rest)) = line.split_once(':')
            {
                let v = rest.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

pub(super) fn all_fields(text: &str, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        for key in keys {
            if starts_with_ascii_ci(line, key)
                && let Some((_, rest)) = line.split_once(':')
            {
                let v = rest.trim().to_string();
                if !v.is_empty() && !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The typed fields parsed out of a raw WHOIS response. Pure data — the
/// entity-building in `process` consumes these by name.
pub(super) struct WhoisFields {
    pub(super) registrar: Option<String>,
    pub(super) registrar_iana: Option<String>,
    pub(super) registrar_url: Option<String>,
    pub(super) updated: Option<String>,
    pub(super) created: Option<String>,
    pub(super) expires: Option<String>,
    pub(super) registrant_email: Option<String>,
    pub(super) registrant_org: Option<String>,
    pub(super) registrant_country: Option<String>,
    pub(super) registrant_state: Option<String>,
    pub(super) admin_email: Option<String>,
    pub(super) admin_name: Option<String>,
    pub(super) admin_org: Option<String>,
    pub(super) tech_email: Option<String>,
    pub(super) tech_name: Option<String>,
    pub(super) tech_org: Option<String>,
    pub(super) abuse_email: Option<String>,
    pub(super) nameservers: Vec<String>,
    pub(super) statuses: Vec<String>,
    pub(super) dnssec: Option<String>,
    /// Deduplicated phone numbers (E.164-style `+<digits>`) from registrant,
    /// admin, and tech contact sections. Redacted/privacy values are excluded.
    pub(super) phones: Vec<String>,
}

/// True if a WHOIS field value looks like a real phone number rather than a
/// redaction placeholder. Requires a leading `+` and at least 7 total digits.
fn is_real_phone(s: &str) -> bool {
    if !s.contains('+') {
        return false;
    }
    let lower = s.to_lowercase();
    if lower.contains("redacted")
        || lower.contains("privacy")
        || lower.contains("not disclosed")
        || lower.contains("data protected")
        || lower.contains("unavailable")
    {
        return false;
    }
    let digits: usize = s.bytes().filter(u8::is_ascii_digit).count();
    digits >= 7
}

/// Normalise a WHOIS phone value to `+<digits>` (stripping separators).
fn normalise_phone(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

/// Parse a raw WHOIS response body into the [`WhoisFields`] we surface. Pure
/// (no I/O), so it is unit-testable against canned WHOIS text. Email fields are
/// gated through `extract::looks_like_email` so registry placeholders
/// ("REDACTED", a bare `@`, a half value) never reach the entity layer.
pub(super) fn parse_whois(response: &str) -> WhoisFields {
    WhoisFields {
        registrar: field(response, &["Registrar:", "Sponsoring Registrar:"]),
        registrar_iana: field(response, &["Registrar IANA ID:", "Registrar IANA Number:"]),
        registrar_url: field(response, &["Registrar URL:", "Registrar Website:"]),
        updated: field(
            response,
            &[
                "Updated Date:",
                "Last Modified:",
                "Last updated:",
                "changed:",
            ],
        ),
        created: field(response, &["Creation Date:", "created:", "Created On:"]),
        expires: field(
            response,
            &[
                "Registry Expiry Date:",
                "Registrar Registration Expiration Date:",
                "expires:",
                "paid-till:",
            ],
        ),
        registrant_email: field(
            response,
            &["Registrant Email:", "Tech Email:", "Admin Email:"],
        )
        .filter(|e| crate::util::extract::looks_like_email(e)),
        registrant_org: field(
            response,
            &[
                "Registrant Organization:",
                "Registrant Organisation:",
                "org:",
            ],
        ),
        registrant_country: field(response, &["Registrant Country:", "country:"]),
        registrant_state: field(
            response,
            &["Registrant State/Province:", "Registrant State:"],
        ),
        admin_email: field(response, &["Admin Email:"])
            .filter(|e| crate::util::extract::looks_like_email(e)),
        admin_name: field(response, &["Admin Name:"]),
        admin_org: field(response, &["Admin Organization:", "Admin Organisation:"]),
        tech_email: field(response, &["Tech Email:"])
            .filter(|e| crate::util::extract::looks_like_email(e)),
        tech_name: field(response, &["Tech Name:"]),
        tech_org: field(response, &["Tech Organization:", "Tech Organisation:"]),
        abuse_email: field(
            response,
            &[
                "Registrar Abuse Contact Email:",
                "abuse-mailbox:",
                "OrgAbuseEmail:",
            ],
        )
        .filter(|e| crate::util::extract::looks_like_email(e)),
        nameservers: all_fields(response, &["Name Server:", "nserver:"]),
        statuses: all_fields(response, &["Domain Status:", "status:"]),
        dnssec: field(response, &["DNSSEC:", "dnssec:"]),
        phones: {
            let mut seen = std::collections::HashSet::new();
            all_fields(
                response,
                &[
                    "Registrant Phone:",
                    "Admin Phone:",
                    "Tech Phone:",
                    "Registrant Phone Ext:",
                ],
            )
            .into_iter()
            .filter(|p| is_real_phone(p))
            .map(|p| normalise_phone(&p))
            .filter(|p| seen.insert(p.clone()))
            .collect()
        },
    }
}
