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
    pub(super) tech_email: Option<String>,
    pub(super) abuse_email: Option<String>,
    pub(super) nameservers: Vec<String>,
    pub(super) statuses: Vec<String>,
    pub(super) dnssec: Option<String>,
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
        tech_email: field(response, &["Tech Email:"])
            .filter(|e| crate::util::extract::looks_like_email(e)),
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
    }
}
