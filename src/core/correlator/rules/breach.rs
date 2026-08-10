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
///
/// `pub(in crate::core)` (re-exported from `correlator::mod`, mirroring
/// `gap_fill_probes`/`multipath_corroborated_links`): `core::relation::builders`'
/// `derive_reused_secret_link` calls [`Secret::classify`] directly so the
/// `SharesSecretWith` graph edge and this AU-047 correlation can never
/// disagree on which secrets qualify (Rule 4: one classifier).
#[derive(Clone, Copy)]
pub(in crate::core) enum Secret {
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
    pub(in crate::core) fn classify(e: &Entity) -> Option<Self> {
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
/// accounts they kept otherwise separate. An account is identified by its email
/// local-part **or** its username (folded to one canonical handle, the same
/// scheme AU-048 uses for shared public keys), so a username-keyed breach
/// footprint (`username` + hash, no email — a very common dump shape) links its
/// accounts exactly as an email-keyed one does, while an email and its matching
/// username from the SAME record collapse to one handle and can't self-fire. The
/// linkable set covers all the
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
        // The distinct ACCOUNTS this exact secret was seen against, drawn from the
        // breach-record evidence the importer accumulates onto the secret (one
        // record per entry). An account is identified by its email and/or its
        // username, so a username-keyed footprint (`username` + hash, no email —
        // a very common dump shape) links its accounts just as an email-keyed one
        // does. Both identifier kinds are collected here…
        let emails: BTreeSet<String> = secret
            .evidence
            .iter()
            .flat_map(|ev| ev.attr_values("email"))
            .map(str::to_lowercase)
            .filter(|v| v.contains('@'))
            .collect();
        let usernames: BTreeSet<String> = secret
            .evidence
            .iter()
            .flat_map(|ev| ev.attr_values("username"))
            .map(str::to_lowercase)
            .filter(|v| !v.is_empty())
            .collect();

        // …then folded to distinct CONTROLLER HANDLES — the email local-part or
        // the username, separator-insensitive (the same canonicalisation AU-048
        // applies to key-linked accounts). Folding to a handle is the single-record
        // safety: an email and the matching username from ONE record
        // ("alice@x.com" + "alice") collapse to one handle and cannot self-fire,
        // while two genuinely different handles ("alice@x.com" + "bob_work")
        // sharing the unique secret do. ≥2 distinct handles is the
        // ≥2-separate-accounts firing gate.
        let handles: BTreeSet<String> = emails
            .iter()
            .map(|e| e.split('@').next().unwrap_or(e))
            .chain(usernames.iter().map(String::as_str))
            .map(canonical_handle)
            .filter(|h| !h.is_empty())
            .collect();
        if handles.len() < 2 {
            continue;
        }

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
            format!(
                " across {} source{} ({})",
                sources.len(),
                if sources.len() == 1 { "" } else { "s" },
                join_capped(sources.iter().map(String::as_str), 5)
            )
        };
        // List the implicated identifiers (emails first, then usernames — an
        // ExactSizeIterator chain, so join_capped's cap-and-disclose never
        // re-sorts them into one merged, alphabetically-interleaved set). The
        // separate-account COUNT is the distinct-handle count, which de-dupes an
        // email and the matching username down to the one controller they name.
        let listed = join_capped(emails.iter().chain(usernames.iter()).map(String::as_str), 6);

        out.push(Correlation {
            rule_id: "AU-047".into(),
            rule_name: "Reused-secret identity link".into(),
            severity,
            description: format!(
                "A single reused {} ties {} otherwise-separate accounts to one controller{} — secret reuse across accounts: {}",
                class.label(),
                handles.len(),
                source_clause,
                listed
            ),
            entity_uids: uids,
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }
    out
}

/// AU-106 — Shared device fingerprint links accounts.
///
/// A hardware / machine fingerprint (`hwid`, `machine_id`, a hardware
/// serial/`imei`, surfaced as a `DeviceId`, or a stealer-logged router `bssid`
/// surfaced as a `device`-tagged `MacAddress`, by the breach/stealer rich-detail
/// extractor) recorded against two
/// or more DISTINCT identities means those accounts were used on the SAME
/// physical machine — almost certainly one controller. This is the device-level
/// analogue of AU-047 (a reused secret) and AU-048 (a shared key): a stealer log
/// captures every credential saved on one machine, so the fingerprint ties the
/// owner's otherwise-separate accounts together, and the same fingerprint seen
/// across two breaches ties the machine's user across them.
///
/// Precision gates mirror AU-047/AU-048. The fingerprint must be substantial
/// (≥ `MIN_FP_LEN` chars — a real hardware id, not a short/generic hostname like
/// `USER-PC`), and the accounts must reduce to ≥2 DISTINCT canonical handles
/// (email local-part or username, separator-insensitive), so an email and its
/// matching username from ONE record can't self-fire. The rule runs on the
/// confirmed (candidate-filtered) view, so a co-occurrence stranger's machine
/// never links the subject. Severity is High, not Critical: unlike a secret only
/// its owner knows, a household / shared machine is a real — if rare — confound,
/// so the link sits one tier below the reused-secret proof.
pub(in crate::core::correlator) fn rule_au_106_shared_device_identity(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    // A fingerprint shorter than this is a short/generic hostname, not a hardware
    // id, and must never link people (hwid/machine_id GUIDs are far longer).
    const MIN_FP_LEN: usize = 12;

    // A `DeviceId` (hwid/machine_id/serial/imei) OR a breach-sourced router
    // `MacAddress` (BSSID). The `device` tag — applied only by the breach/stealer
    // rich-detail extractor — isolates a stealer-logged BSSID from a LAN/Wi-Fi MAC
    // surfaced by `local_net`/`signal_radar`/`wifi_intel` (tagged `wifi-ap`/
    // `local-arp`, never `device`); those also carry no email/username evidence,
    // so they independently fail the ≥2-handles gate below.
    let devices: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::DeviceId
                || (e.kind == EntityKind::MacAddress && e.has_tag("device"))
        })
        .collect();
    if devices.is_empty() {
        return Vec::new();
    }

    // Pre-index identity entities ONCE (lowercased), exactly as AU-047 does, so the
    // per-device linking is plain set membership.
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
    for dev in devices {
        if dev.value.trim().len() < MIN_FP_LEN {
            continue;
        }
        // The distinct accounts seen against this exact device, from the per-record
        // evidence the breach/stealer importer accumulates onto the DeviceId (one
        // record per saved credential / per breach appearance).
        let emails: BTreeSet<String> = dev
            .evidence
            .iter()
            .flat_map(|ev| ev.attr_values("email"))
            .map(str::to_lowercase)
            .filter(|v| v.contains('@'))
            .collect();
        let usernames: BTreeSet<String> = dev
            .evidence
            .iter()
            .flat_map(|ev| ev.attr_values("username"))
            .map(str::to_lowercase)
            .filter(|v| !v.is_empty())
            .collect();
        // Distinct controller HANDLES (email local-part or username, separator-
        // insensitive) — the same fold AU-047/AU-048 use, so an email and the
        // matching username from one record collapse to one and can't self-fire.
        let handles: BTreeSet<String> = emails
            .iter()
            .map(|e| e.split('@').next().unwrap_or(e))
            .chain(usernames.iter().map(String::as_str))
            .map(canonical_handle)
            .filter(|h| !h.is_empty())
            .collect();
        if handles.len() < 2 {
            continue;
        }
        // The device plus every implicated identity entity present in scope.
        let mut uids = vec![dev.uid.clone()];
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
        let listed = join_capped(emails.iter().chain(usernames.iter()).map(String::as_str), 6);
        out.push(Correlation::new(
            "AU-106",
            "Shared device fingerprint links accounts",
            Severity::High,
            format!(
                "A single device fingerprint ties {} otherwise-separate accounts to one \
                 controller — the same physical machine: {}",
                handles.len(),
                listed
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// EmailRep reports breach exposure through two explicit booleans —
/// `data_breach` and `credential_leaked` — which `emailrep`'s `build_email_entity`
/// surfaces as evidence attributes (`"true"`) and, only then, tags the entity
/// `breach`. This returns true when an `emailrep` evidence entry carries either
/// flag set to `"true"`.
///
/// It is the item-23 gate for AU-001. Unlike every other module in
/// `BREACH_SOURCES` — which emits evidence *only* on an actual breach hit —
/// EmailRep is a reputation lookup that stamps an `emailrep` evidence source on
/// EVERY address it checks, breach or not. Without this gate a CLEAN EmailRep
/// reputation report counts as a breach-corroboration vote, so one real breach
/// source plus a clean EmailRep lookup fires a false Critical multi-breach
/// finding. Requiring explicit breach-positive evidence removes that false vote
/// while leaving a genuinely breach-positive EmailRep result as full
/// corroboration.
fn emailrep_is_breach_positive(entity: &Entity) -> bool {
    entity.evidence.iter().any(|ev| {
        ev.source == "emailrep"
            && (ev.attributes.get("data_breach").map(String::as_str) == Some("true")
                || ev.attributes.get("credential_leaked").map(String::as_str) == Some("true"))
    })
}

pub(in crate::core::correlator) fn rule_au_001_multi_breach(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
        let mut sources = tagged_matching_sources(e, BREACH_SOURCES);
        // EmailRep stamps an `emailrep` evidence source on every address it checks,
        // so its bare presence is not breach corroboration. Drop it unless its
        // evidence is explicitly breach-positive (item 23); every other source in
        // BREACH_SOURCES emits evidence only on a real breach hit, so this never
        // affects them.
        if !emailrep_is_breach_positive(e) {
            sources.remove(&"emailrep");
        }
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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

/// AU-095 — Exposed API-key portfolio (ranked exposure intelligence).
///
/// AU-021 surfaces each leaked key individually; on a productive stealer-log
/// scan that is dozens of flat "Critical" findings with no order. This rule
/// reads the intelligence the harvester already stamps on every `ApiKey` entity
/// — its provider (`service:`), exposure **criticality** (`key-criticality:`,
/// what the key can do if abused) and **detection** confidence (`detection:`) —
/// and rolls the whole harvest into one *prioritised* portfolio: how many keys,
/// across how many providers, how many high-criticality, how many outright
/// exploitable (e.g. an unsigned `alg:none` JWT), and a revoke-this-first order.
///
/// This is exposure analysis only: the keys are retained and ranked so the
/// operator (or the exposed party) can act — they are never reused for HSE's own
/// calls. Keys minted by the core `found_keys` sink carry no criticality tag and
/// rank as `unrated`, still counted. Critical when any high-criticality key is
/// present, else High. One summary finding per scan.
pub(in crate::core::correlator) fn rule_au_095_exposed_key_portfolio(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeMap;

    fn tag_suffix<'a>(e: &'a Entity, prefix: &str) -> Option<&'a str> {
        e.tags.iter().find_map(|t| t.strip_prefix(prefix))
    }
    fn provider(e: &Entity) -> &str {
        tag_suffix(e, "service:").unwrap_or("unknown")
    }
    // Graver criticality / firmer detection sort first; `unrated`/absent last.
    fn crit_rank(e: &Entity) -> u8 {
        match tag_suffix(e, "key-criticality:") {
            Some("critical") => 4,
            Some("high") => 3,
            Some("medium") => 2,
            Some("low") => 1,
            _ => 0,
        }
    }
    fn detection_rank(e: &Entity) -> u8 {
        match tag_suffix(e, "detection:") {
            Some("proven") => 3,
            Some("probable") => 2,
            Some("potential") => 1,
            _ => 0,
        }
    }

    let keys: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey)
        .collect();
    if keys.is_empty() {
        return Vec::new();
    }

    let mut by_provider: BTreeMap<&str, usize> = BTreeMap::new();
    let mut high_value = 0usize;
    let mut exploitable = 0usize;
    for &k in &keys {
        *by_provider.entry(provider(k)).or_default() += 1;
        if k.has_tag("high-value") || crit_rank(k) >= 3 {
            high_value += 1;
        }
        if k.has_tag(crate::core::tags::VULNERABLE) {
            exploitable += 1;
        }
    }

    // Revoke-first order: criticality desc, then detection desc, then provider.
    let mut rows: Vec<(u8, u8, &Entity)> = keys
        .iter()
        .map(|&e| (crit_rank(e), detection_rank(e), e))
        .collect();
    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then(provider(a.2).cmp(provider(b.2)))
    });
    let top: Vec<String> = rows
        .iter()
        .take(5)
        .map(|(_, _, e)| {
            let crit = tag_suffix(e, "key-criticality:").unwrap_or("unrated");
            let det = tag_suffix(e, "detection:").unwrap_or("n/a");
            format!("{} ({crit}/{det})", provider(e))
        })
        .collect();
    // The priority list is capped at 5, but the description must never claim
    // completeness it doesn't have — a portfolio of, say, 12 keys must say so,
    // not silently show 5 with no indication 7 were omitted (the same
    // disclosure `join_capped` gives AU-047/AU-048/AU-106).
    let mut priority = top.join("; ");
    if rows.len() > 5 {
        priority.push_str(&format!(" (+{} more)", rows.len() - 5));
    }

    let n = keys.len();
    let providers = by_provider.len();
    let severity = if high_value > 0 {
        Severity::Critical
    } else {
        Severity::High
    };
    let exploit_note = if exploitable > 0 {
        format!(", {exploitable} outright exploitable (e.g. unsigned JWT / known-bad)")
    } else {
        String::new()
    };

    vec![Correlation::new(
        "AU-095",
        "Exposed API-key portfolio",
        severity,
        format!(
            "{n} exposed API key(s) across {providers} provider(s) retained as exposure \
             intelligence — {high_value} high-criticality{exploit_note}. Revoke-first priority: \
             {priority}. (Exposure scoring only — harvested keys are catalogued, not reused.)"
        ),
        keys.iter().map(|e| e.uid.clone()).collect(),
        scan_id,
        ts,
    )]
}

/// AU-096 — OSINT practitioner (holds recon/breach/threat-intel API keys).
///
/// A harvested key for an OSINT provider — Shodan, Dehashed, IntelX, Maltego,
/// Hunter, … — is more than a credential: by possession its owner *runs OSINT*.
/// The harvester tags such keys `osint-practitioner` + `osint-category:<slug>`
/// (classified by `util::osint_providers`). This rule reads those tags
/// and surfaces the attribution: the subject is an OSINT operator, with the
/// provider list and the tradecraft categories (breach-hunting vs attack-surface
/// mapping vs people-search …) that the key portfolio reveals.
///
/// This is the pivot the operator asked for — the key's *provider* is the
/// intelligence, not the secret it contains; the key is never used to
/// authenticate. Severity High (a strong, specific attribution): a single OSINT
/// key is a lead, several across categories is a profile. One finding per scan.
pub(in crate::core::correlator) fn rule_au_096_osint_practitioner(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::{BTreeMap, BTreeSet};

    let mut providers: BTreeSet<&str> = BTreeSet::new();
    // category slug → distinct providers in it, for a tradecraft breakdown.
    let mut by_category: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut uids: Vec<String> = Vec::new();

    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey && e.has_tag("osint-practitioner"))
    {
        let provider = e
            .tags
            .iter()
            .find_map(|t| t.strip_prefix("service:"))
            .unwrap_or("unknown");
        let category = e
            .tags
            .iter()
            .find_map(|t| t.strip_prefix("osint-category:"))
            .unwrap_or("uncategorised");
        providers.insert(provider);
        by_category.entry(category).or_default().insert(provider);
        uids.push(e.uid.clone());
    }

    if providers.is_empty() {
        return Vec::new();
    }

    let tradecraft = by_category
        .iter()
        .map(|(cat, provs)| {
            format!(
                "{cat} ({})",
                provs.iter().copied().collect::<Vec<_>>().join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    vec![Correlation::new(
        "AU-096",
        "OSINT practitioner (recon-tool API keys)",
        Severity::High,
        format!(
            "Subject holds {} OSINT/recon-provider API key(s) across {} provider(s) — by \
             possession an OSINT practitioner. Tradecraft: {tradecraft}. The provider is the \
             pivot (tooling, intent); keys are catalogued, not used.",
            uids.len(),
            providers.len()
        ),
        uids,
        scan_id,
        ts,
    )]
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
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

/// AU-082 — API key exposed via two independent source families.
///
/// AU-021 fires whenever a single `ApiKey` entity is present; this rule
/// fires specifically when the *same* key is independently found in two or
/// more distinct source families (e.g. `code` via `github_code_search` AND
/// `breach` via `oathnet_pro`).  The dual-pathway is the critical signal: it
/// means the key was already circulating in criminal channels at the time it
/// was leaked in source code — the window between exposure and exploitation
/// has closed, and revocation is urgent.
///
/// Severity: **Critical** (same as AU-021) but the description explicitly
/// names the dual-pathway, giving the operator an unambiguous remediation
/// directive that AU-021 (single-source) cannot provide.
pub(in crate::core::correlator) fn rule_au_082_api_key_dual_pathway(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiKey)
        .filter_map(|e| {
            // The shared `source_families` detector (also used by AU-062/AU-063)
            // — NOT a raw map over every evidence source — so a same-key replay
            // via `recall`/`cross_scan_history`, or a deterministic enrichment
            // pass riding along on the entity, can't manufacture a second
            // "independent" pathway. Mapping every evidence source directly (the
            // prior behaviour here) let a key seen once by a real harvester plus
            // once via `recall`'s same-scan-history replay trivially satisfy
            // `families.len() >= 2` (the replay falls into the unclassified
            // `"other"` bucket), firing a false Critical dual-pathway alert from
            // a single real sighting. `"other"` is removed too, matching AU-062's
            // orthogonality check — an unclassified source is not a genuine
            // second channel.
            let mut families = source_families(e);
            families.remove("other");
            if families.len() < 2 {
                return None;
            }
            let family_list: Vec<&str> = families.into_iter().collect();
            Some(Correlation::new(
                "AU-082",
                "API key dual-pathway exposure",
                Severity::Critical,
                format!(
                    "API key '{}' independently found across {} source families ({}): \
                     key was already circulating outside the original leak — revoke immediately",
                    e.value,
                    family_list.len(),
                    family_list.join(", "),
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
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
        let wallet = Entity::new(EntityKind::CryptoAddress, "0xabc", confidence::MEDIUM, "s");
        let api = Entity::new(EntityKind::ApiKey, "sk-xyz", confidence::MEDIUM, "s");
        assert!(matches!(
            Secret::classify(&wallet),
            Some(Secret::WalletAddress)
        ));
        assert!(matches!(Secret::classify(&api), Some(Secret::ApiKey)));
    }

    #[test]
    fn classify_routes_salted_hash_password_to_salted_hash() {
        let e = Entity::new(
            EntityKind::Password,
            "$2a$10$abcdefghijklmnop",
            confidence::MEDIUM,
            "s",
        );
        assert!(matches!(Secret::classify(&e), Some(Secret::SaltedHash)));
    }

    #[test]
    fn classify_session_token_requires_tag_and_shape() {
        let token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        // With the session-token provenance tag → SessionToken.
        let mut tagged = Entity::new(EntityKind::Credential, token, confidence::MEDIUM, "s");
        tagged.tag("session-token");
        assert!(matches!(
            Secret::classify(&tagged),
            Some(Secret::SessionToken)
        ));
        // Same value, no tag: the hex shape is an unsalted-digest lookalike, so it
        // is NOT admitted as a plaintext password → None.
        let untagged = Entity::new(EntityKind::Credential, token, confidence::MEDIUM, "s");
        assert!(Secret::classify(&untagged).is_none());
    }

    #[test]
    fn classify_reusable_plaintext_password_is_admitted() {
        let e = Entity::new(
            EntityKind::Password,
            "correcthorse",
            confidence::MEDIUM,
            "s",
        );
        let c = Secret::classify(&e).expect("rare plaintext password links");
        assert!(c.is_plaintext_password());
        assert_eq!(c.label(), "password");
    }

    #[test]
    fn classify_rejects_non_credential_kinds_and_weak_passwords() {
        let email = Entity::new(EntityKind::Email, "a@b.com", confidence::MEDIUM, "s");
        assert!(Secret::classify(&email).is_none());
        let weak = Entity::new(EntityKind::Password, "123456", confidence::MEDIUM, "s");
        assert!(Secret::classify(&weak).is_none());
    }

    // ── distinct_sources ──────────────────────────────────────────────────────

    #[test]
    fn distinct_sources_unions_attrs_splits_lists_and_drops_sentinels() {
        let mut e = Entity::new(EntityKind::Password, "$2a$10$x", confidence::MEDIUM, "s");
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
