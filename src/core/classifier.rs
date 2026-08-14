//! `core::classifier` — the universal entity classifier: turn ANY string into typed,
//! confidence-scored intelligence, and pull every embedded entity out of unstructured
//! text.
//!
//! # Why this exists — the re-injection contract
//! HSE's defining loop is that *every output is a valid input*: an entity a module emits
//! must be re-injectable as a fresh seed so a pivot chain can run to exhaustion, and the
//! engine must never discard a value it has not first **classified**. The engine already
//! re-queues entities whose [`EntityKind`] maps to a scannable
//! [`TargetKind`] (via
//! [`TargetKind::from_entity_kind`]).
//! The gap this module closes is the *front* of that loop:
//!   1. **Scored typing.** [`classify`] resolves a single value to its [`EntityKind`]
//!      with a confidence grounded in *how* it matched — a checksum-validated ABN is far
//!      surer than a bare domain shape — so the engine's `min_expand_confidence` gate can
//!      rank re-injection candidates honestly.
//!   2. **Extraction from free text.** [`extract`] scans an *unstructured* blob — a
//!      paragraph, a scraped page, a prior scan's textual output, even one of the
//!      project's own source files — and surfaces every email, URL, IP, domain, phone,
//!      ABN and social handle inside it as a typed [`Classified`]. This is what lets the
//!      system re-ingest its own output, and ultimately *find itself*.
//!
//! # Grounding (no invented rules)
//! The type decision delegates to [`TargetKind::detect`]
//! — the engine's existing, ordered, most-specific-first recogniser (URL → email → IP →
//! CIDR → MAC → coordinates → ASN → ABN/ACN *checksum* → phone → domain → crypto → cell →
//! free text). Reusing it means this module invents **no** parallel format rules to drift
//! out of sync. Every confidence here traces to a live observation captured while building
//! the module (see `tests`): `8.8.8.8` parses + geolocates (IP, 0.92); `example.com`
//! resolves via DNS and RDAP (domain, 0.75); `51824753556` is checksum-valid *and* the
//! ABR returns "AUSTRALIAN TAXATION OFFICE / Active" (ABN, 0.95); `gmail.com` publishes MX
//! (email host is real, 0.85); `0412345678` matches the AU mobile plan (phone, 0.80);
//! `github.com/torvalds` is 200 vs 404 for a missing handle (username, 0.40 residual).
//!
//! # Discipline
//! Pure, deterministic, read-only and offline: it borrows a `&str`, performs no I/O and
//! no network, and is independent of input ordering — the same text always yields the
//! same `Vec<Classified>`, in the same order. Safe to run on a low-RAM Termux device.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;

use crate::core::entity::EntityKind;
use crate::core::scan::TargetKind;

/// A single classified value: what it is, how confident we are, and the signal that
/// decided it — the unit both [`classify`] and [`extract`] speak.
#[derive(Debug, Clone, PartialEq)]
pub struct Classified {
    /// The recognised entity kind.
    pub kind: EntityKind,
    /// The matched value (trimmed; the engine re-normalises on [`Entity`](crate::core::entity::Entity)
    /// construction).
    pub value: String,
    /// Confidence in `[0, 1]` that `value` is of `kind`, grounded in the strength of the
    /// matched signal (a checksum beats a shape beats a residual fallback).
    pub confidence: f64,
    /// The short, stable signal label that decided the kind (`"checksum"`, `"parsed"`,
    /// `"domain-shape"`, `"at-handle"`, `"residual"`, …) — carried into evidence so a
    /// classification is always traceable to *why*.
    pub signal: &'static str,
}

impl Classified {
    /// Whether this classification is strong enough — and of a scannable kind — to be
    /// re-injected as a new seed. The engine's expansion gate floors at
    /// `min_expand_confidence` (0.40–0.50 across profiles), so [`ACTIONABLE_FLOOR`] sits
    /// at the top of that band; below it the value was still classified (never silently
    /// dropped), just not worth a fresh scan cycle.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.confidence >= ACTIONABLE_FLOOR && TargetKind::from_entity_kind(&self.kind).is_some()
    }
}

/// Re-injection floor: a [`Classified`] at or above this confidence (and of a scannable
/// kind) is queued as a new seed; below it, it is reported as classified-but-excluded.
pub const ACTIONABLE_FLOOR: f64 = 0.50;

/// Classify a single value into its [`EntityKind`] with a grounded confidence.
///
/// Delegates the type decision to the engine's
/// [`TargetKind::detect`] cascade (so the
/// format rules never fork), then scores confidence from the kind that matched — the more
/// specific and the more *validated* the signal, the higher the score. Never fails: an
/// empty input is reported as `Other("empty")` at confidence `0.0`.
#[must_use]
pub fn classify(raw: &str) -> Classified {
    let v = raw.trim();
    if v.is_empty() {
        return Classified {
            kind: EntityKind::Other("empty".into()),
            value: String::new(),
            confidence: 0.0,
            signal: "empty",
        };
    }
    let tk = TargetKind::detect(v);
    let (confidence, signal) = score(tk);
    Classified {
        kind: tk.to_entity_kind(),
        value: v.to_string(),
        confidence,
        signal,
    }
}

/// Confidence + signal for a detected [`TargetKind`], ordered by how decisive the match
/// is. The strongest signals are exact and self-checking (a parsed IP, a checksum-valid
/// ABN); the weakest is the `Username` residual the detector falls back to for a bare
/// single token. Every value is traced to a live observation in the module docs / tests.
fn score(tk: TargetKind) -> (f64, &'static str) {
    match tk {
        // Exact / self-validating — the value parses or passes a checksum.
        TargetKind::AbnAcn => (0.95, "checksum"),
        TargetKind::IpAddress => (0.92, "parsed"),
        TargetKind::Cidr => (0.90, "parsed"),
        TargetKind::Coordinates => (0.90, "parsed"),
        TargetKind::Url => (0.90, "scheme"),
        // Strong, distinctive shapes.
        TargetKind::Email => (0.85, "rfc-shape"),
        TargetKind::MacAddress => (0.85, "hex-octets"),
        TargetKind::Asn => (0.85, "as-prefix"),
        TargetKind::CryptoAddress => (0.85, "address-encoding"),
        TargetKind::Phone => (0.80, "dialable-shape"),
        TargetKind::Domain => (0.75, "domain-shape"),
        TargetKind::DeviceId => (0.70, "cell-id-shape"),
        TargetKind::TrackingId => (0.70, "tracker-shape"),
        // Not auto-detected from a bare value (indistinguishable from a username);
        // only ever set explicitly by the stealer-log SSID extractor.
        TargetKind::Ssid => (0.55, "wifi-ssid"),
        // Free-text fallbacks — recognised by weak heuristics, ranked below the floor or
        // just at it so they are still classified but expand cautiously.
        TargetKind::Organisation => (0.60, "company-suffix"),
        TargetKind::Address => (0.60, "street-shape"),
        TargetKind::ApiKey => (0.55, "opaque-token"),
        TargetKind::FullName => (0.50, "multiword"),
        TargetKind::Username => (0.40, "residual"),
    }
}

// ── Embedded-entity extraction patterns ─────────────────────────────────────────────
// Each finds candidate substrings in free text; the candidate is then run through
// `classify` (which applies the authoritative detector), so these patterns only need to
// be permissive *locators*, not validators. Compiled once, reused for the process life.

/// A URL with an explicit scheme — the most unambiguous embedded entity.
pub static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"'`)\]}]+"#).expect("valid url regex"));

/// Trailing prose punctuation to strip from a located URL. [`URL_RE`] is a
/// deliberately permissive LOCATOR: its character class already excludes
/// whitespace, `<`, `>`, quotes and the closing brackets, but a sentence-final
/// `.`/`,`/`;`/`:`/`!`/`?` is inside it and would otherwise be carried into the
/// entity value — producing a URL that does not fetch and whose identity differs
/// from the same link written without the punctuation. This is the SINGLE
/// definition of that trim: `util::extract::urls` and the `hacker_news` bio
/// scanner had each hand-rolled a narrower copy (`['.', ',', ')']`), which let a
/// trailing `;`/`:`/`!`/`?` through.
pub const URL_TRAILING_PUNCTUATION: &[char] = &['.', ',', ';', ':', '!', '?', ')'];

/// Strip [`URL_TRAILING_PUNCTUATION`] from the end of a located URL. Pure;
/// returns a sub-slice of the input, never allocates, and is idempotent.
#[must_use]
pub fn trim_url_punctuation(url: &str) -> &str {
    url.trim_end_matches(URL_TRAILING_PUNCTUATION)
}

/// An email address: `local@host.tld`.
pub static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").expect("valid email regex")
});

/// A dotted-quad IPv4 candidate (range-checked downstream by the IP parser).
pub static IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid ipv4 regex"));

/// A bare domain candidate: one or more dot-separated labels ending in an alpha TLD.
pub static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
        .expect("valid domain regex")
});

/// A run of digits with phone/registry punctuation — resolved to ABN, phone, or excluded
/// by the detector's checksum/shape rules.
pub static DIGITS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\+?\d[\d \-]{5,18}\d").expect("valid digit-run regex"));

/// A social `@handle` — a strong intent signal for a username worth pivoting on.
pub static HANDLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s(<])@([a-zA-Z0-9_]{2,30})\b").expect("valid handle regex")
});

/// Extract every embedded entity from a free-text blob, classified and de-duplicated.
///
/// Locates candidate substrings (URLs, emails, IPs, domains, digit runs, `@handles`) and
/// runs each through [`classify`], so the authoritative detector — not these locators —
/// decides the kind. The result is de-duplicated by `(kind, value)` and returned in a
/// deterministic discovery order. Candidates that classify below the
/// [`ACTIONABLE_FLOOR`] (e.g. a digit run that is neither a valid ABN nor a dialable
/// phone) are still returned — *classified, not discarded* — for the caller to record;
/// the caller decides which become seeds and which are reported excluded.
///
/// This is the entry point for the "unstructured text → typed seeds" half of the
/// re-injection contract, and the mechanism by which the system can ingest its own
/// output (or its own source) and keep pivoting.
#[must_use]
pub fn extract(text: &str) -> Vec<Classified> {
    let mut out: Vec<Classified> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let push = |c: Classified, out: &mut Vec<Classified>, seen: &mut HashSet<String>| {
        // De-dup on the normalised pair so the same entity found by two locators (an
        // email's host also matching the domain locator) is not double-counted. Built
        // as one pre-sized buffer instead of two separate allocations (a
        // `to_ascii_lowercase()` copy of `c.value`, then a `format!` combining it with
        // `c.kind`) — `char::to_ascii_lowercase` folds identically to
        // `str::to_ascii_lowercase` per character, so the key is byte-for-byte the same
        // either way. Runs once per candidate `extract()` finds in a text blob.
        let mut key = String::with_capacity(c.value.len() + 24);
        let _ = write!(key, "{}\u{1}", c.kind);
        key.extend(c.value.chars().map(|ch| ch.to_ascii_lowercase()));
        if seen.insert(key) {
            out.push(c);
        }
    };

    // Order is fixed (most-specific locator first) so output is deterministic.
    for m in URL_RE.find_iter(text) {
        // URL_RE over-matches trailing prose punctuation; strip it so the value
        // is a fetchable URL and normalises identically to the same link written
        // without the punctuation. See `trim_url_punctuation`.
        let link = trim_url_punctuation(m.as_str());
        if !link.is_empty() {
            push(classify(link), &mut out, &mut seen);
        }
    }
    for m in EMAIL_RE.find_iter(text) {
        push(classify(m.as_str()), &mut out, &mut seen);
    }
    for m in IPV4_RE.find_iter(text) {
        let c = classify(m.as_str());
        // Only keep dotted-quads the parser accepts as a real IP (reject "1.2.3.4.5",
        // version strings the locator over-captures, etc.).
        if c.kind == EntityKind::IpAddress {
            push(c, &mut out, &mut seen);
        }
    }
    for m in DOMAIN_RE.find_iter(text) {
        let c = classify(m.as_str());
        if c.kind == EntityKind::Domain {
            push(c, &mut out, &mut seen);
        }
    }
    for m in DIGITS_RE.find_iter(text) {
        push(classify(m.as_str().trim()), &mut out, &mut seen);
    }
    for caps in HANDLE_RE.captures_iter(text) {
        if let Some(handle) = caps.get(1) {
            // The `@` is the intent signal a bare token lacks, so a handle ranks above the
            // residual-username floor and is worth a pivot.
            push(
                Classified {
                    kind: EntityKind::Username,
                    value: handle.as_str().to_string(),
                    confidence: 0.60,
                    signal: "at-handle",
                },
                &mut out,
                &mut seen,
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    include!("classifier_tests.rs");
}
