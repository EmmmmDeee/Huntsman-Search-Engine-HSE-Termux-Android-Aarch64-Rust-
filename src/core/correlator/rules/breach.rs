//! AU correlation rules — breach family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

/// True if `s` is a **salted** password-hash digest — bcrypt / sha-crypt /
/// argon2 / scrypt / yescrypt, all of which embed their salt. This is the
/// precision gate that makes credential-based identity linking sound: a salted
/// digest is globally unique by construction, so two identities carrying the
/// *identical* value share the exact stored credential (the same person reused or
/// copied it) — not a weak-password coincidence. A bare unsalted hex digest is
/// deliberately EXCLUDED: `md5("123456")` is shared by millions, and linking
/// people on it would manufacture false identities, which is the opposite of
/// finding the real one.
fn is_salted_hash(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("$2") // bcrypt $2a/$2b/$2y
        || s.starts_with("$argon2")
        || s.starts_with("$scrypt")
        || s.starts_with("$y$") // yescrypt
        || s.starts_with("$7$") // scrypt (crypt format)
        || s.starts_with("$6$") // sha512crypt
        || s.starts_with("$5$") // sha256crypt
}

/// All-ASCII-hex of digest length — the shape of an **unsalted** password hash
/// (md5/sha1/sha256/ntlm) or a raw hex token. Never treated as a plaintext
/// password: an unsalted digest may be the hash of a *common* password, so
/// linking identities on it manufactures false positives (the original AU-047
/// gate refused exactly these). A genuinely-random hex token links only via
/// explicit `session-token` provenance, not this shape.
fn is_hex_digest(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Estimated search-space entropy in bits: `len × log2(alphabet present)`. A
/// deliberately conservative proxy for "how rare is this exact string", used
/// only to decide whether a reused plaintext credential / token is unique enough
/// that sharing it across accounts is a real controller link rather than a
/// common-password coincidence.
fn estimated_entropy_bits(s: &str) -> f64 {
    let mut alphabet = 0u32;
    if s.chars().any(|c| c.is_ascii_lowercase()) {
        alphabet += 26;
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        alphabet += 26;
    }
    if s.chars().any(|c| c.is_ascii_digit()) {
        alphabet += 10;
    }
    if s.chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace())
    {
        alphabet += 33; // ASCII punctuation/symbols
    }
    if alphabet == 0 {
        return 0.0;
    }
    s.chars().count() as f64 * f64::from(alphabet).log2()
}

/// The handful of ubiquitous passwords whose reuse links nobody — millions share
/// them, so identity-linking on them is a false positive even when they clear
/// the entropy floor. Compared lowercased. (Most are short enough to fail the
/// length/entropy gate anyway; this catches the long, common ones.)
fn is_common_password(s: &str) -> bool {
    const COMMON: &[&str] = &[
        "password",
        "password1",
        "password123",
        "passw0rd",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "1q2w3e4r",
        "abc123",
        "111111",
        "000000",
        "123123",
        "iloveyou",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "welcome1",
        "monkey",
        "sunshine",
        "princess",
        "dragon",
        "football",
        "baseball",
        "superman",
        "trustno1",
        "master",
        "hello123",
        "changeme",
        "secret",
        "starwars",
    ];
    COMMON.contains(&s.trim().to_ascii_lowercase().as_str())
}

/// A **reused plaintext password** rare enough that two accounts carrying the
/// identical value share one controller. Excludes hex digests (unsalted hashes —
/// possibly of a common password), the ubiquitous-password denylist, and
/// low-variety strings (`aaaaaaaaaa`); requires ≥10 chars, ≥6 distinct chars and
/// ≥50 bits of estimated entropy.
fn is_reusable_password(s: &str) -> bool {
    let s = s.trim();
    if s.chars().count() < 10 || is_hex_digest(s) || is_common_password(s) {
        return false;
    }
    let distinct = s.chars().collect::<std::collections::BTreeSet<_>>().len();
    distinct >= 6 && estimated_entropy_bits(s) >= 50.0
}

/// A **session / cookie token** substantial enough to be a unique controller
/// key: a long, high-variety random string. Tokens are random by construction,
/// so (unlike a password) a hex/base64 shape is expected and allowed — the
/// `session-token` tag is the provenance that distinguishes it from an unsalted
/// password hash. Requires ≥16 chars, ≥8 distinct chars and ≥64 bits.
fn is_substantial_token(s: &str) -> bool {
    let s = s.trim();
    let distinct = s.chars().collect::<std::collections::BTreeSet<_>>().len();
    s.chars().count() >= 16 && distinct >= 8 && estimated_entropy_bits(s) >= 64.0
}

/// True if `e` is a secret artifact unique enough that its **reuse across
/// distinct identities** is strong evidence of a single controller. These are
/// the OPSEC seams that unmask the hardest people to find:
///   * a **salted** password hash, a crypto wallet address, or an API key —
///     globally unique by construction (near-certain);
///   * a **reused high-entropy plaintext password** ([`is_reusable_password`]) —
///     password reuse across otherwise-separate accounts;
///   * a **session / cookie token** ([`is_substantial_token`], carried with the
///     `session-token` tag) — a captured session identifier shared across
///     accounts/sites.
///
/// All three are legitimate cross-correlation join-keys; the entropy/denylist
/// gates keep a *common* password from manufacturing false identities.
fn is_linkable_secret(e: &Entity) -> bool {
    match e.kind {
        EntityKind::Credential => {
            is_salted_hash(&e.value)
                || (e.has_tag("session-token") && is_substantial_token(&e.value))
                || is_reusable_password(&e.value)
        }
        EntityKind::CryptoAddress | EntityKind::ApiKey => true,
        _ => false,
    }
}

/// Human label for the reused artifact, for the AU-047 description.
fn secret_label(e: &Entity) -> &'static str {
    if e.has_tag("session-token") {
        return "session/cookie token";
    }
    match e.kind {
        EntityKind::Credential if is_salted_hash(&e.value) => "password hash",
        EntityKind::Credential => "password",
        EntityKind::CryptoAddress => "wallet address",
        EntityKind::ApiKey => "API key",
        _ => "secret",
    }
}

/// AU-047 — Reused-secret identity link.
///
/// The unmasking rule for compartmentalised targets. When one linkable secret
/// (see [`is_linkable_secret`]) is observed against **≥2 distinct identities**
/// (the email/username the breach record carries in its evidence), those
/// identities are tied to a single controller: someone reused a secret across
/// accounts they kept otherwise separate. The linkable set covers all three of
/// the legitimate cross-correlation join-keys — a salted hash / crypto address /
/// API key, a **reused high-entropy plaintext password**, and a **session /
/// cookie token** — while the entropy + denylist gates keep a *common* password
/// from manufacturing phantom identities.
///
/// Severity reflects coincidence risk: a salted hash, crypto address, API key or
/// random session token is globally unique by construction (**Critical**); a
/// reused plaintext password is a strong but marginally less certain link, since
/// two people could conceivably pick the same strong password (**High**).
pub(in crate::core::correlator) fn rule_au_047_reused_secret_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    let mut out = Vec::new();
    for secret in entities.iter().filter(|e| is_linkable_secret(e)) {
        // The distinct ACCOUNTS this exact secret was seen against. Keyed on the
        // email — the account identifier — drawn from the breach-record evidence
        // the importer accumulates onto the secret (one evidence record per
        // entry). Counting emails (not also usernames) is deliberate: an email
        // and a username from the SAME record are one account, so admitting both
        // would false-fire on a single record; the real signal is the secret
        // spanning ≥2 distinct emails, i.e. ≥2 separate accounts.
        let emails: BTreeSet<String> = secret
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("email"))
            .map(|v| v.trim().to_lowercase())
            .filter(|v| v.contains('@') && !v.is_empty())
            .collect();
        if emails.len() < 2 {
            continue;
        }
        // Link the secret plus every implicated identity entity present in scope
        // (the emails directly, and any username co-located in those records).
        let usernames: BTreeSet<String> = secret
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("username"))
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        let mut uids = vec![secret.uid.clone()];
        for e in entities.iter() {
            let v = e.value.trim().to_lowercase();
            if (e.kind == EntityKind::Email && emails.contains(&v))
                || (e.kind == EntityKind::Username && usernames.contains(&v))
            {
                uids.push(e.uid.clone());
            }
        }
        // A reused PLAINTEXT password is a strong but marginally less certain
        // link than a construction-unique artifact (salted hash / crypto / API
        // key / random session token), so it lands one tier lower.
        let plaintext_password = secret.kind == EntityKind::Credential
            && !secret.has_tag("session-token")
            && !is_salted_hash(&secret.value);
        let severity = if plaintext_password {
            Severity::High
        } else {
            Severity::Critical
        };
        let listed: Vec<&str> = emails.iter().take(6).map(String::as_str).collect();
        out.push(Correlation {
            rule_id: "AU-047".into(),
            rule_name: "Reused-secret identity link".into(),
            severity,
            description: format!(
                "A single reused {} ties {} otherwise-separate accounts to one controller (secret reuse across accounts): {}",
                secret_label(secret),
                emails.len(),
                listed.join(", ")
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }
    out
}

pub(in crate::core::correlator) fn rule_au_001_multi_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
        "xposed_or_not",
        "breach_directory",
        "dehashed",
        "hibp",
        "oathnet_pro",
        "emailrep",
        // NOTE: the generic `search_engines` source is deliberately NOT listed.
        // A web-search hit is not breach corroboration, and counting it would let
        // one real breach + one search result fire a false Critical. (An earlier
        // `search_engines:oathnet` entry was dead — the module emits the plain
        // `search_engines` source — so it was removed rather than "fixed" to
        // `search_engines`, which would introduce exactly that false positive.)
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Email) {
        let sources = tagged_matching_sources(e, BREACH_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-001",
                "Multi-source breach corroboration",
                Severity::Critical,
                format!(
                    "{} found in {} breach sources: {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

pub(in crate::core::correlator) fn rule_au_009_stealer_log(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag(crate::core::tags::STEALER_LOG))
        .map(|e| Correlation {
            rule_id: "AU-009".into(),
            rule_name: "Stealer-log compromise".into(),
            severity: Severity::High,
            description: format!("Email {} observed in info-stealer log dumps", e.value),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_019_temporal_breach_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut breach_dates: Vec<(&Entity, &str)> = Vec::new();
    for e in entities {
        if !e.has_tag(crate::core::tags::BREACH) {
            continue;
        }
        for ev in &e.evidence {
            for field in ["breach_date", "not_before", "earliest_record", "date"] {
                if let Some(d) = ev.attributes.get(field)
                    && let Some(day) = d.get(..10)
                {
                    breach_dates.push((e, day));
                }
            }
        }
    }
    if breach_dates.len() < 3 {
        return Vec::new();
    }
    breach_dates.sort_by_key(|(_, d)| *d);
    let mut clusters: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = vec![breach_dates[0].0.uid.clone()];
    // Anchor the window to the cluster's FIRST (earliest, since sorted) date, not
    // a rolling previous date. A rolling gap chains — Jan 1 / Jan 30 / Feb 28 /
    // Mar 30 are each ≤30 days apart and would collapse into one 88-day "cluster",
    // contradicting the "within 30 days" claim. Anchoring bounds every cluster to
    // a genuine ≤30-day span (a real coordinated-compromise window).
    let mut anchor = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        if date_diff_days(anchor, d) <= 30 {
            if !current.contains(&e.uid) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push(current);
            }
            current = vec![e.uid.clone()];
            anchor = d;
        }
    }
    if current.len() >= 3 {
        clusters.push(current);
    }
    clusters
        .into_iter()
        .map(|uids| Correlation {
            rule_id: "AU-019".into(),
            rule_name: "Temporal breach cluster".into(),
            severity: Severity::High,
            description: format!(
                "{} breach entities clustered within 30 days — potential coordinated compromise",
                uids.len()
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_021_api_key_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey)
        .map(|e| {
            Correlation::new(
                "AU-021",
                "API key exposure",
                Severity::Critical,
                format!("API key '{}' discovered in breach/stealer data", e.value),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-037 — Plaintext credential exposure.
///
/// The single most actionable OSINT finding: an actual leaked secret. The
/// breach/stealer modules surface the canonical secret as a first-class
/// `Password` / `Credential` entity (distinct from `ApiKey`, which AU-021
/// covers), but nothing previously synthesised them into an alert. This fires
/// CRITICAL when any are present, links the secret entities (capped) plus the
/// exposed identity (emails/usernames) so the operator sees *whose* credentials
/// leaked, and reports only COUNTS — the raw secret values stay in the entities
/// (full-fidelity policy) and are never copied into correlation text.
pub(in crate::core::correlator) fn rule_au_037_credential_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let secrets: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Password | EntityKind::Credential))
        .collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    let passwords = secrets
        .iter()
        .filter(|e| e.kind == EntityKind::Password)
        .count();
    let credentials = secrets.len() - passwords;

    // Affected secrets first (capped), then the identity they pertain to.
    let mut uids: Vec<String> = secrets.iter().take(20).map(|e| e.uid.clone()).collect();
    uids.extend(
        entities
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
            .take(5)
            .map(|e| e.uid.clone()),
    );

    let mut parts = Vec::new();
    if passwords > 0 {
        parts.push(format!(
            "{passwords} plaintext password{}",
            if passwords == 1 { "" } else { "s" }
        ));
    }
    if credentials > 0 {
        parts.push(format!(
            "{credentials} credential record{}",
            if credentials == 1 { "" } else { "s" }
        ));
    }
    vec![Correlation::new(
        "AU-037",
        "Plaintext credential exposure",
        Severity::Critical,
        format!(
            "{} exposed in breach/stealer data — the affected identity's secret(s) are directly recoverable",
            parts.join(" and ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-043 — the subject's data appears in one or more public pastes (`psbdmp`):
/// a public-exposure signal that corroborates breach findings. `Medium`. One
/// grouped firing over all paste URLs.
pub(in crate::core::correlator) fn rule_au_043_paste_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let pastes: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag(crate::core::tags::PASTE_EXPOSED))
        .collect();
    if pastes.is_empty() {
        return Vec::new();
    }
    let uids: Vec<String> = pastes.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-043",
        "Public paste exposure",
        Severity::Medium,
        format!("Subject data found in {} public paste(s)", pastes.len()),
        uids,
        scan_id,
        ts,
    )]
}
