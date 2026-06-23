//! AU correlation rules — breach family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use std::collections::BTreeSet;

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Secret-shape primitives
//
// The AU-047 identity link stands or falls on one judgement: is a string unique
// enough that two accounts sharing it must share a controller? These helpers
// make that judgement. They are deliberately allocation-light and single-pass —
// the correlator runs them across every credential-shaped entity in a scan.
// ─────────────────────────────────────────────────────────────────────────────

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

/// Single-pass character analysis of a candidate secret: its length, distinct
/// character count, and estimated search-space entropy. Computing all three in
/// one scan replaces the previous ~10 separate passes (four `.any()` alphabet
/// probes, a `.count()`, and a `BTreeSet` build, twice over) that the password
/// and token gates each used to run.
struct CharProfile {
    /// Total `char` count (not bytes) of the trimmed string.
    len: usize,
    /// Number of distinct `char`s — the variety floor that rejects
    /// `aaaaaaaaaa`-style low-entropy strings.
    distinct: usize,
    /// `len × log2(alphabet present)` — a deliberately conservative proxy for
    /// "how rare is this exact string". The alphabet sums only the character
    /// *classes* observed (lower/upper/digit/symbol), so a 16-char all-lowercase
    /// string scores far below a 16-char mixed one.
    entropy_bits: f64,
}

impl CharProfile {
    /// Scan `s` (trimmed) once, deriving [`CharProfile`]. Whitespace counts
    /// toward `len`/`distinct` but contributes to no alphabet class, matching the
    /// original gates exactly.
    fn of(s: &str) -> Self {
        let s = s.trim();
        let mut seen = BTreeSet::new();
        let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
        let mut len = 0usize;
        for c in s.chars() {
            len += 1;
            seen.insert(c);
            if c.is_ascii_lowercase() {
                lower = true;
            } else if c.is_ascii_uppercase() {
                upper = true;
            } else if c.is_ascii_digit() {
                digit = true;
            } else if !c.is_ascii_alphanumeric() && !c.is_whitespace() {
                symbol = true; // ASCII punctuation/symbols
            }
        }
        let alphabet = u32::from(lower) * 26
            + u32::from(upper) * 26
            + u32::from(digit) * 10
            + u32::from(symbol) * 33;
        let entropy_bits = if alphabet == 0 {
            0.0
        } else {
            len as f64 * f64::from(alphabet).log2()
        };
        Self {
            len,
            distinct: seen.len(),
            entropy_bits,
        }
    }
}

/// The handful of ubiquitous passwords whose reuse links nobody — millions share
/// them, so identity-linking on them is a false positive even when they clear
/// the entropy floor. Compared lowercased. (Most are short enough to fail the
/// length/entropy gate anyway; this catches the long, common ones — chiefly
/// `password123`, which clears the entropy floor.)
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
    let t = s.trim();
    if is_hex_digest(t) || is_common_password(t) {
        return false;
    }
    let p = CharProfile::of(t);
    p.len >= 10 && p.distinct >= 6 && p.entropy_bits >= 50.0
}

/// A **session / cookie token** substantial enough to be a unique controller
/// key: a long, high-variety random string. Tokens are random by construction,
/// so (unlike a password) a hex/base64 shape is expected and allowed — the
/// `session-token` tag is the provenance that distinguishes it from an unsalted
/// password hash. Requires ≥16 chars, ≥8 distinct chars and ≥64 bits.
fn is_substantial_token(s: &str) -> bool {
    let p = CharProfile::of(s);
    p.len >= 16 && p.distinct >= 8 && p.entropy_bits >= 64.0
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret classification
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of linkable secret an entity carries — the single source of truth
/// for *whether* a secret links identities, *what* to call it, and *how certain*
/// the link is. Computing this once per secret removes the previous triple
/// recomputation of `is_salted_hash` / `has_tag` across the filter, the label,
/// and the severity decision.
#[derive(Clone, Copy)]
enum Secret {
    /// Salted password hash — globally unique by construction.
    SaltedHash,
    /// Reused high-entropy plaintext password — strong, but two people *could*
    /// pick the same one, so it is the only kind eligible for the High tier.
    PlaintextPassword,
    /// Captured session/cookie token carried with `session-token` provenance.
    SessionToken,
    /// Crypto wallet address — globally unique.
    WalletAddress,
    /// Leaked API key — globally unique.
    ApiKey,
}

impl Secret {
    /// Classify `e`, or `None` if it carries nothing unique enough to link
    /// identities on. This is the exact admission gate AU-047 fires on.
    ///
    /// The breach/stealer modules surface a leaked plaintext password (or a
    /// password *hash*) as a first-class `Password` entity — distinct from the
    /// `username@host` `Credential` string — so both kinds are credential
    /// carriers here. The salted-hash precision and entropy/denylist floors stop
    /// a common password (or an unsalted digest of one) from manufacturing
    /// phantom identities; a session token is admitted only on `Credential` with
    /// explicit `session-token` provenance, never inferred from shape alone.
    fn classify(e: &Entity) -> Option<Self> {
        match e.kind {
            EntityKind::CryptoAddress => Some(Self::WalletAddress),
            EntityKind::ApiKey => Some(Self::ApiKey),
            EntityKind::Credential | EntityKind::Password => {
                if is_salted_hash(&e.value) {
                    Some(Self::SaltedHash)
                } else if e.kind == EntityKind::Credential
                    && e.has_tag("session-token")
                    && is_substantial_token(&e.value)
                {
                    Some(Self::SessionToken)
                } else if is_reusable_password(&e.value) {
                    Some(Self::PlaintextPassword)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Human label for the reused artifact, for the AU-047 description.
    fn label(self) -> &'static str {
        match self {
            Self::SaltedHash => "password hash",
            Self::PlaintextPassword => "password",
            Self::SessionToken => "session/cookie token",
            Self::WalletAddress => "wallet address",
            Self::ApiKey => "API key",
        }
    }

    /// True only for a reused plaintext password — the one kind whose link is
    /// marginally less certain (two people could conceivably pick the same strong
    /// password) and so may land one severity tier lower absent cross-source
    /// corroboration. Every other kind is unique by construction.
    fn is_plaintext_password(self) -> bool {
        matches!(self, Self::PlaintextPassword)
    }
}

/// The distinct breach **source datasets** a secret was observed in, read from
/// the per-record provenance the importers stamp onto each evidence entry:
/// `dbname` (OathNet), `source` / `source_db` (See-Know), and
/// `database_name` / `top_databases` (DeHashed). The generic `stealer` /
/// `unknown` sentinels carry no dataset identity and are skipped. A password
/// observed across two INDEPENDENT sources is materially more individuating than
/// the same value seen twice inside a single dump — cross-source spread is the
/// "unique sources" signal that raises the shared-ownership confidence.
fn distinct_sources(secret: &Entity) -> BTreeSet<String> {
    const SOURCE_ATTRS: &[&str] = &[
        "dbname",
        "source",
        "source_db",
        "database_name",
        "database",
        "top_databases",
        "top_dbnames",
    ];
    /// Generic provenance values that name no specific dataset.
    fn is_sentinel(s: &str) -> bool {
        s.is_empty()
            || s.eq_ignore_ascii_case("unknown")
            || s.eq_ignore_ascii_case("stealer")
            || s.eq_ignore_ascii_case("n/a")
    }
    let mut out = BTreeSet::new();
    for ev in &secret.evidence {
        for attr in SOURCE_ATTRS {
            let Some(v) = ev.attributes.get(*attr) else {
                continue;
            };
            // `top_databases` / `top_dbnames` are comma-joined lists; split so
            // each named database counts as its own distinct source. Sentinels
            // are rejected before allocating the lowercased key.
            for part in v.split(',') {
                let s = part.trim();
                if !is_sentinel(s) {
                    out.insert(s.to_lowercase());
                }
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Rules
// ─────────────────────────────────────────────────────────────────────────────

/// AU-047 — Reused-secret identity link.
///
/// Links separate accounts that share one reused secret. When one linkable secret
/// (see [`Secret::classify`]) is observed against **≥2 distinct identities**
/// (the email/username the breach record carries in its evidence), those
/// identities are tied to a single controller: someone reused a secret across
/// accounts they kept otherwise separate. The linkable set covers all the
/// legitimate cross-correlation join-keys — a salted hash / crypto address /
/// API key, a **reused high-entropy plaintext password**, and a **session /
/// cookie token** — while the entropy + denylist gates keep a *common* password
/// from manufacturing phantom identities.
///
/// Severity reflects coincidence risk: a salted hash, crypto address, API key or
/// random session token is globally unique by construction (**Critical**); a
/// reused plaintext password is a strong but marginally less certain link, since
/// two people could conceivably pick the same strong password (**High**) —
/// *unless* its reuse is corroborated across **≥2 independent source datasets**
/// ([`distinct_sources`]), which removes the single-dump-coincidence doubt and
/// restores **Critical**. The implicated secret may be a `Credential` string or
/// a first-class `Password` entity alike, so a leaked plaintext password drives
/// the link directly; the corroborating unique sources are named in the finding.
pub(in crate::core::correlator) fn rule_au_047_reused_secret_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Classify every secret up front; bail before any further work if none link.
    let secrets: Vec<(&Entity, Secret)> = entities
        .iter()
        .filter_map(|e| Secret::classify(e).map(|s| (e, s)))
        .collect();
    if secrets.is_empty() {
        return Vec::new();
    }

    // Pre-index the identity entities ONCE, lowercased. The previous form
    // re-lowercased every entity's value for every secret — O(secrets×entities)
    // allocations; this is O(entities) built a single time. `is_email`
    // discriminates the two kinds the filter admits without cloning EntityKind.
    struct IdRef<'a> {
        value_lc: String,
        is_email: bool,
        uid: &'a str,
    }
    let identities: Vec<IdRef> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
        .map(|e| IdRef {
            value_lc: e.value.trim().to_lowercase(),
            is_email: e.kind == EntityKind::Email,
            uid: &e.uid,
        })
        .collect();

    let mut out = Vec::new();
    for (secret, class) in secrets {
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
            .filter(|v| v.contains('@'))
            .collect();
        if emails.len() < 2 {
            continue;
        }
        // Usernames co-located in those same records — linked as implicated
        // identities, but never counted toward the ≥2-account firing gate above.
        let usernames: BTreeSet<String> = secret
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("username"))
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();

        // The secret plus every implicated identity entity present in scope, in
        // entity order. Walks the pre-built identity index, not all entities.
        let mut uids = vec![secret.uid.clone()];
        for id in &identities {
            let hit = if id.is_email {
                emails.contains(&id.value_lc)
            } else {
                usernames.contains(&id.value_lc)
            };
            if hit {
                uids.push(id.uid.to_owned());
            }
        }

        // Cross-source spread is the individuality signal: the same strong
        // password in two INDEPENDENT corpora is far likelier a real reuse than a
        // single-dump artifact, so it raises the link's certainty. A reused
        // plaintext password confined to one source stays High; everything else
        // (construction-unique artifacts, or a password corroborated across ≥2
        // sources) is Critical.
        let sources = distinct_sources(secret);
        let cross_source = sources.len() >= 2;
        let severity = if class.is_plaintext_password() && !cross_source {
            Severity::High
        } else {
            Severity::Critical
        };

        // Name the corroborating sources when we have dataset provenance, so the
        // operator sees *which* unique sources back the reuse claim.
        let source_clause = if sources.is_empty() {
            String::new()
        } else {
            let named: Vec<&str> = sources.iter().take(5).map(String::as_str).collect();
            format!(
                " across {} source{} ({})",
                sources.len(),
                if sources.len() == 1 { "" } else { "s" },
                named.join(", ")
            )
        };
        let listed: Vec<&str> = emails.iter().take(6).map(String::as_str).collect();

        out.push(Correlation {
            rule_id: "AU-047".into(),
            rule_name: "Reused-secret identity link".into(),
            severity,
            description: format!(
                "A single reused {} ties {} otherwise-separate accounts to one controller{} — secret reuse across accounts: {}",
                class.label(),
                emails.len(),
                source_clause,
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
        // A role / provider mailbox (abuse@, noreply@, dns@, …) appears in breach
        // corpora as a matter of course — it is a shared registrar/provider desk,
        // not the subject's address — so its breach presence is NOT the subject's
        // exposure and must never raise a Critical. A live person-scan fired AU-001
        // CRITICAL on `abuse@godaddy.com` (hibp + xposed_or_not), a false positive
        // surfaced from a WHOIS/RDAP registrar-contact emitter.
        if crate::core::validation::is_role_mailbox(&e.value) {
            continue;
        }
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
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("stealer-log"))
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
        if !e.has_tag("breach") {
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
    // Track the current cluster's member uids both as an ordered list (the
    // output) and as a set (the membership test), so de-duping a uid is O(log n)
    // instead of the O(n) `Vec::contains` the rolling window previously used.
    let mut current: Vec<String> = vec![breach_dates[0].0.uid.clone()];
    let mut current_set: BTreeSet<&str> = BTreeSet::from([breach_dates[0].0.uid.as_str()]);
    // Anchor the window to the cluster's FIRST (earliest, since sorted) date, not
    // a rolling previous date. A rolling gap chains — Jan 1 / Jan 30 / Feb 28 /
    // Mar 30 are each ≤30 days apart and would collapse into one 88-day "cluster",
    // contradicting the "within 30 days" claim. Anchoring bounds every cluster to
    // a genuine ≤30-day span (a real coordinated-compromise window).
    let mut anchor = breach_dates[0].1;
    for &(e, d) in &breach_dates[1..] {
        if date_diff_days(anchor, d) <= 30 {
            if current_set.insert(e.uid.as_str()) {
                current.push(e.uid.clone());
            }
        } else {
            if current.len() >= 3 {
                clusters.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            current.push(e.uid.clone());
            current_set.clear();
            current_set.insert(e.uid.as_str());
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
    // One pass: collect the capped secret uids and tally passwords-vs-credentials
    // together, instead of filtering the whole entity list three times.
    let mut secret_uids: Vec<String> = Vec::new();
    let mut passwords = 0usize;
    let mut credentials = 0usize;
    for e in entities {
        match e.kind {
            EntityKind::Password => passwords += 1,
            EntityKind::Credential => credentials += 1,
            _ => continue,
        }
        secret_uids.push(e.uid.clone());
    }
    if passwords == 0 && credentials == 0 {
        return Vec::new();
    }

    // Affected secrets first (capped), then the identity they pertain to. Both
    // samples are sorted by uid BEFORE the cap so the same members are chosen
    // every run — a HashMap-ordered `take(N)` picked a different slice per run,
    // persisting as duplicate AU-037 rows. The caps stay so a huge credential
    // dump can't bloat one correlation's entity list.
    secret_uids.sort_unstable();
    secret_uids.truncate(20);
    let mut identity_uids: Vec<String> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
        .map(|e| e.uid.clone())
        .collect();
    identity_uids.sort_unstable();
    identity_uids.truncate(5);
    let mut uids = secret_uids;
    uids.extend(identity_uids);

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
    let uids: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag(crate::core::tags::PASTE_EXPOSED))
        .map(|e| e.uid.clone())
        .collect();
    if uids.is_empty() {
        return Vec::new();
    }
    vec![Correlation::new(
        "AU-043",
        "Public paste exposure",
        Severity::Medium,
        format!("Subject data found in {} public paste(s)", uids.len()),
        uids,
        scan_id,
        ts,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::Evidence;

    // ── is_salted_hash ────────────────────────────────────────────────────────

    #[test]
    fn is_salted_hash_accepts_every_salted_scheme() {
        for h in [
            "$2a$10$abcdefghijklmnopqrstuv",
            "$2b$12$....",
            "$2y$10$....",
            "$argon2id$v=19$m=65536",
            "$scrypt$ln=16",
            "$y$j9T$salt",
            "$7$DU..../....",
            "$6$rounds=5000$salt",
            "$5$rounds=5000$salt",
        ] {
            assert!(is_salted_hash(h), "should be salted: {h}");
        }
    }

    #[test]
    fn is_salted_hash_rejects_bare_hex_and_trims() {
        assert!(!is_salted_hash("5f4dcc3b5aa765d61d8327deb882cf99")); // md5 hex
        assert!(!is_salted_hash("not a hash"));
        // Leading/trailing whitespace is trimmed before the prefix test.
        assert!(is_salted_hash("  $2a$10$x  "));
    }

    // ── is_hex_digest ─────────────────────────────────────────────────────────

    #[test]
    fn is_hex_digest_requires_16_plus_all_hex() {
        assert!(is_hex_digest("5f4dcc3b5aa765d6")); // exactly 16 hex
        assert!(is_hex_digest("5f4dcc3b5aa765d61d8327deb882cf99")); // 32 hex
        assert!(!is_hex_digest("5f4dcc3b5aa765d")); // 15 chars — too short
        assert!(!is_hex_digest("z5f4dcc3b5aa765d6")); // contains non-hex 'z'
    }

    // ── is_common_password ────────────────────────────────────────────────────

    #[test]
    fn is_common_password_matches_denylist_case_insensitively() {
        assert!(is_common_password("password123"));
        assert!(is_common_password("PASSWORD123"));
        assert!(is_common_password("  letmein  "));
        assert!(!is_common_password("Xy7$kq2Lm9wz")); // not in the list
    }

    // ── is_reusable_password ──────────────────────────────────────────────────

    #[test]
    fn is_reusable_password_accepts_rare_high_entropy_strings() {
        // 12 chars, 7 distinct, all-lowercase entropy 12*log2(26)≈56 ≥ 50.
        assert!(is_reusable_password("correcthorse"));
    }

    #[test]
    fn is_reusable_password_rejects_hashes_common_and_low_variety() {
        assert!(!is_reusable_password("5f4dcc3b5aa765d61d8327deb882cf99")); // hex digest
        assert!(!is_reusable_password("password123")); // common
        assert!(!is_reusable_password("aaaaaaaaaa")); // 10 chars, 1 distinct
        assert!(!is_reusable_password("short1")); // < 10 chars
    }

    // ── is_substantial_token ──────────────────────────────────────────────────

    #[test]
    fn is_substantial_token_accepts_long_high_variety_string() {
        assert!(is_substantial_token("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"));
    }

    #[test]
    fn is_substantial_token_rejects_short_or_low_distinct() {
        assert!(!is_substantial_token("abc123")); // < 16 chars
        assert!(!is_substantial_token("aaaaaaaaaaaaaaaa")); // 16 chars, 1 distinct
    }

    // ── Secret::classify ──────────────────────────────────────────────────────

    #[test]
    fn classify_admits_wallet_and_api_key_unconditionally() {
        let wallet = Entity::new(EntityKind::CryptoAddress, "0xabc", 0.5, "s");
        let api = Entity::new(EntityKind::ApiKey, "sk-xyz", 0.5, "s");
        assert!(matches!(
            Secret::classify(&wallet),
            Some(Secret::WalletAddress)
        ));
        assert!(matches!(Secret::classify(&api), Some(Secret::ApiKey)));
    }

    #[test]
    fn classify_routes_salted_hash_password_to_salted_hash() {
        let e = Entity::new(EntityKind::Password, "$2a$10$abcdefghijklmnop", 0.5, "s");
        assert!(matches!(Secret::classify(&e), Some(Secret::SaltedHash)));
    }

    #[test]
    fn classify_session_token_requires_tag_and_shape() {
        let token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        // With the session-token provenance tag → SessionToken.
        let mut tagged = Entity::new(EntityKind::Credential, token, 0.5, "s");
        tagged.tag("session-token");
        assert!(matches!(
            Secret::classify(&tagged),
            Some(Secret::SessionToken)
        ));
        // Same value, no tag: the hex shape is an unsalted-digest lookalike, so it
        // is NOT admitted as a plaintext password → None.
        let untagged = Entity::new(EntityKind::Credential, token, 0.5, "s");
        assert!(Secret::classify(&untagged).is_none());
    }

    #[test]
    fn classify_reusable_plaintext_password_is_admitted() {
        let e = Entity::new(EntityKind::Password, "correcthorse", 0.5, "s");
        let c = Secret::classify(&e).expect("rare plaintext password links");
        assert!(c.is_plaintext_password());
        assert_eq!(c.label(), "password");
    }

    #[test]
    fn classify_rejects_non_credential_kinds_and_weak_passwords() {
        let email = Entity::new(EntityKind::Email, "a@b.com", 0.5, "s");
        assert!(Secret::classify(&email).is_none());
        let weak = Entity::new(EntityKind::Password, "123456", 0.5, "s");
        assert!(Secret::classify(&weak).is_none());
    }

    // ── distinct_sources ──────────────────────────────────────────────────────

    #[test]
    fn distinct_sources_unions_attrs_splits_lists_and_drops_sentinels() {
        let mut e = Entity::new(EntityKind::Password, "$2a$10$x", 0.5, "s");
        e.add_evidence(Evidence::new("oathnet", "hit").with_attr("dbname", "LinkedIn"));
        e.add_evidence(
            Evidence::new("dehashed", "hit").with_attr("top_databases", "Adobe, MySpace, unknown"),
        );
        // A pure sentinel contributes nothing.
        e.add_evidence(Evidence::new("see_know", "hit").with_attr("source", "stealer"));
        let srcs = distinct_sources(&e);
        assert!(srcs.contains("linkedin")); // lowercased
        assert!(srcs.contains("adobe"));
        assert!(srcs.contains("myspace"));
        assert!(!srcs.contains("unknown"), "sentinel dropped");
        assert!(!srcs.contains("stealer"), "sentinel dropped");
        assert_eq!(srcs.len(), 3);
    }
}
