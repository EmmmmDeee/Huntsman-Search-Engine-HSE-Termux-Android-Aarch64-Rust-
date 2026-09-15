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
    /// IP-registry (RIR) record fields. An RIR's answer for an address is an
    /// allocation record — `NetRange`/`NetName`/`Organization` at ARIN,
    /// `inetnum`/`netname`/`org`/`descr` in the RPSL dialect RIPE, APNIC and
    /// AFRINIC share, `inetnum`/`owner` at LACNIC — with none of the
    /// registrar/creation/nameserver/status fields a *domain* record carries.
    /// Parsed explicitly so an IP answer is judged on its own signals (see
    /// `super::build_result`) rather than on domain-only ones, which read every
    /// ARIN allocation — the whole of North America — as "no data".
    pub(super) net_name: Option<String>,
    /// `NetRange:` (ARIN) / `inetnum:` / `inet6num:` (RPSL, LACNIC).
    pub(super) net_range: Option<String>,
    /// `CIDR:` (ARIN only).
    pub(super) cidr: Option<String>,
    /// `NetType:` (ARIN: Direct Allocation / Reassigned / …).
    pub(super) net_type: Option<String>,
    /// First `descr:` line (RPSL) — free text, kept as an evidence attribute
    /// only; it is often an address line, so it is never an Organisation.
    pub(super) descr: Option<String>,
}

/// True if a WHOIS field value looks like a real phone number rather than a
/// redaction placeholder. Requires a leading `+` and at least 7 total digits.
fn is_real_phone(s: &str) -> bool {
    if !s.contains('+') {
        return false;
    }
    if crate::core::validation::is_whois_privacy_placeholder(s) {
        return false;
    }
    let digits: usize = s.bytes().filter(u8::is_ascii_digit).count();
    digits >= 7
}

/// Normalise a WHOIS phone value to `+<digits>` (stripping separators).
fn normalise_phone(s: &str) -> String {
    crate::util::str_util::ascii_digits_and_plus(s)
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
                // RPSL (RIPE/APNIC/AFRINIC) and ARIN allocation records.
                "last-modified:",
                "Updated:",
            ],
        ),
        // `RegDate:` is ARIN's allocation date — the same fact `created:` carries
        // in an RPSL `inetnum`. Both feed the timeline's `Registered` event.
        created: field(
            response,
            &["Creation Date:", "created:", "Created On:", "RegDate:"],
        ),
        expires: field(
            response,
            &[
                "Registry Expiry Date:",
                "Registrar Registration Expiration Date:",
                "expires:",
                "paid-till:",
            ],
        ),
        // Registrant-role only — "Tech Email:"/"Admin Email:" are a DIFFERENT
        // role, not a dialect synonym for the same field (unlike the other
        // multi-key lookups in this struct, e.g. registrar/created above,
        // which really are the same fact spelled differently by different
        // WHOIS servers). Those two are already captured under their own
        // correct role via `tech_email`/`admin_email` below; folding them in
        // here too let a response with no published Registrant Email (common
        // post-GDPR) silently substitute the admin's or tech contact's
        // address and evidence it as "WHOIS registrant contact".
        registrant_email: field(response, &["Registrant Email:"])
            .filter(|e| crate::util::extract::looks_like_email(e)),
        // The organisation's NAME. `OrgName:` (ARIN), `org-name:` (the RPSL
        // `organisation` object RIPE/APNIC/AFRINIC return alongside an inetnum)
        // and `owner:` (LACNIC) are names. A bare RPSL `org:` line on the
        // inetnum itself is a HANDLE (`ORG-RIEN1-RIPE`) referencing that
        // object, so it is only used when it does not look like one — `.ru`'s
        // registry, for instance, writes the registrant's real name on `org:`.
        // The handle used to win here (first matching line), so every RIPE-
        // region IP minted an Organisation entity named `ORG-XXX-RIPE`.
        registrant_org: field(
            response,
            &[
                "Registrant Organization:",
                "Registrant Organisation:",
                "OrgName:",
                "org-name:",
                "owner:",
            ],
        )
        .or_else(|| field(response, &["org:"]).filter(|v| !is_rpsl_org_handle(v))),
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
        nameservers: {
            // A nameserver line may carry glue after the host (`nserver:
            // A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e::2:30`, DENIC's
            // `Nserver: ns1.example.de 192.0.2.1`); only the host is the name.
            // Dedup case-insensitively AFTER cleaning: `NS1.X.COM` and
            // `ns1.x.com` are one server.
            let mut seen = std::collections::HashSet::new();
            all_fields(response, &["Name Server:", "nserver:"])
                .into_iter()
                .filter_map(|v| clean_nameserver(&v))
                .filter(|h| seen.insert(h.to_ascii_lowercase()))
                .collect()
        },
        statuses: all_fields(response, &["Domain Status:", "status:"]),
        dnssec: field(response, &["DNSSEC:", "dnssec:"]),
        net_name: field(response, &["NetName:"]),
        net_range: field(response, &["NetRange:", "inetnum:", "inet6num:"]),
        cidr: field(response, &["CIDR:"]),
        net_type: field(response, &["NetType:"]),
        descr: field(response, &["descr:"]),
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

/// True if an RPSL `org:` value is an organisation-object HANDLE
/// (`ORG-RIEN1-RIPE`, `ORG-XYZ1-AP`, `ORG-ABC1-AFRINIC`) rather than a name.
/// RIR handles are upper-case, `ORG-`-prefixed and contain no spaces; no real
/// organisation name has that shape.
pub(super) fn is_rpsl_org_handle(v: &str) -> bool {
    let v = v.trim();
    v.starts_with("ORG-") && !v.contains(char::is_whitespace)
}

/// The host from one nameserver line: the first whitespace-delimited token,
/// trailing root dot removed, or `None` when what is left is not a hostname
/// (a glue address on its own, an empty value, junk). Case is preserved —
/// the entity layer folds it.
pub(super) fn clean_nameserver(v: &str) -> Option<String> {
    let host = v.split_whitespace().next()?.trim_end_matches('.');
    crate::util::domains::looks_like_domain(host).then(|| host.to_string())
}

/// The slice of an RIR answer that describes the MOST SPECIFIC network object.
///
/// ARIN's port-43 server answers an address query with every enclosing
/// allocation from the least specific down — a Level 3 `/9` parent block and
/// its `OrgName`/POCs first, then the `/24` actually reassigned to the
/// operator of the address, then that block's org — so a first-match field
/// read over the whole text attributes the parent's operator, country and
/// abuse contact to the address. The most specific record is the LAST
/// `NetRange:` object; everything from its first line on is what describes
/// the address. RPSL registries (RIPE/APNIC/AFRINIC) and LACNIC return one
/// `inetnum`/`inet6num` object followed by the objects it references, so the
/// slice starts at that object (dropping only the `%` comment preamble). A
/// response with no network object is returned whole.
pub(super) fn most_specific_network_record(response: &str) -> &str {
    let mut last_netrange: Option<usize> = None;
    let mut first_inetnum: Option<usize> = None;
    let mut offset = 0usize;
    for line in response.split_inclusive('\n') {
        if starts_with_ascii_ci(line, "NetRange:") {
            last_netrange = Some(offset);
        } else if first_inetnum.is_none()
            && (starts_with_ascii_ci(line, "inetnum:") || starts_with_ascii_ci(line, "inet6num:"))
        {
            first_inetnum = Some(offset);
        }
        offset += line.len();
    }
    match last_netrange.or(first_inetnum) {
        Some(start) => &response[start..],
        None => response,
    }
}

/// The line, if any, on which a WHOIS server refused the query for load
/// reasons instead of answering it — Verisign's / PIR's `WHOIS LIMIT
/// EXCEEDED`, DENIC's `access control limit reached`, the generic `rate
/// limit` / `too many requests` / `quota` phrasings. Consulted only for a
/// response that parsed to nothing (a refusal carries no record), so a
/// genuine record whose remarks happen to mention a quota is never
/// misclassified. Such a refusal is a `RateLimited` error — the registry did
/// not say "no record", it said "not now" — where it used to read as a clean
/// "no registration data".
pub(super) fn rate_limit_notice(response: &str) -> Option<&str> {
    const MARKERS: &[&str] = &[
        "limit exceeded",
        "rate limit",
        "rate-limit",
        "too many requests",
        "quota",
        "access control limit",
        "excessive queries",
        "query limit",
        "maximum allowable queries",
    ];
    response.lines().map(str::trim).find(|line| {
        let lower = line.to_ascii_lowercase();
        MARKERS.iter().any(|m| lower.contains(m))
    })
}
