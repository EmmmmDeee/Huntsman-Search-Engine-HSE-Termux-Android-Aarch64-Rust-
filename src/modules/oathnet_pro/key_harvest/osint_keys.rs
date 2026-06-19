//! Context-attributed OSINT / threat-intel key detection.
//!
//! Many OSINT and threat-intel providers (Shodan, SecurityTrails, VirusTotal,
//! Censys, GreyNoise, …) mint API keys with **no distinctive prefix** — a bare
//! 32/40/64/80-char hex or alphanumeric blob, indistinguishable by shape alone
//! from a password hash or another vendor's key. The prefix table in
//! [`super::patterns`] cannot see them, and the `generic_hex` fallback can flag a
//! 64-hex blob as *some* secret but never *which* provider's.
//!
//! The discriminator these keys carry is **context**: the identifier they sit
//! under (`SHODAN_API_KEY=…`), the `extra` object key (`securitytrails_key`), or
//! the host of the API URL they are passed to (`api.shodan.io/?key=…`). This
//! module attributes a prefix-less key to its provider when (a) the surrounding
//! context names that provider and (b) the value matches one of the provider's
//! accepted key [`Shape`]s. The caller ([`super::identify_with_context`]) still
//! applies the shared false-positive gate ([`super::is_likely_real_key`]), so a
//! placeholder / UUID / low-entropy value under a provider-named field is never
//! attributed.
//!
//! Requiring **both** signals — context AND shape — is strictly more disciplined
//! than a shape-only match: there is no "32 hex ⇒ maybe-Shodan" noise, only
//! "32 alnum under a `shodan` identifier ⇒ Shodan". Service tags are reused
//! verbatim from [`super::service_domains`] so context-attribution and
//! domain-routing emit identical `service:` tags for the same provider.
//!
//! Providers whose keys are UUID-shaped (urlscan, IntelX, Censys *IDs*) are
//! deliberately out of scope: the canonical UUID layout is suppressed as a
//! false-positive elsewhere, and overriding that here would re-admit every
//! random GUID. Their non-UUID secret halves (e.g. the Censys *secret*) are
//! still covered by an alphanumeric shape.

/// The character class a [`Shape`] admits.
#[derive(Clone, Copy)]
enum CharSet {
    /// `[0-9a-fA-F]`.
    Hex,
    /// `[0-9A-Za-z]`.
    Alnum,
}

impl CharSet {
    fn admits(self, b: u8) -> bool {
        match self {
            Self::Hex => b.is_ascii_hexdigit(),
            Self::Alnum => b.is_ascii_alphanumeric(),
        }
    }
}

/// An exact-length + charset key shape (e.g. 32-char hex, 40-char alnum). A value
/// matches only when its length is exact and every byte is in the charset — hex
/// is a subset of alphanumeric, so an [`CharSet::Alnum`] shape also admits an
/// all-hex value, while a [`CharSet::Hex`] shape rejects any letter past `f`.
pub(super) struct Shape {
    pub(super) len: usize,
    charset: CharSet,
}

impl Shape {
    fn matches(&self, v: &str) -> bool {
        v.len() == self.len && v.bytes().all(|b| self.charset.admits(b))
    }
}

const HEX40: Shape = Shape {
    len: 40,
    charset: CharSet::Hex,
};
const HEX64: Shape = Shape {
    len: 64,
    charset: CharSet::Hex,
};
const ALNUM32: Shape = Shape {
    len: 32,
    charset: CharSet::Alnum,
};
const ALNUM40: Shape = Shape {
    len: 40,
    charset: CharSet::Alnum,
};
const ALNUM80: Shape = Shape {
    len: 80,
    charset: CharSet::Alnum,
};

/// One OSINT/threat-intel provider whose key has no distinctive prefix.
pub(super) struct OsintProvider {
    /// Service tag emitted for an attributed key — reused verbatim from
    /// [`super::service_domains`] so the whole engine speaks one vocabulary.
    pub(super) service: &'static str,
    /// Identifier substrings that name this provider, **lowercase**. Matched
    /// against the lowercased context (env-var name, object key, or URL).
    pub(super) contexts: &'static [&'static str],
    /// Accepted key shapes; a value must match one of these.
    pub(super) shapes: &'static [Shape],
}

/// The provider table. Shapes follow each provider's documented key format; only
/// providers with a genuinely fixed-length hex/alphanumeric (non-UUID) key are
/// listed, so no entry is dead or over-broad. Conservative by design — a wrong
/// length is a *miss* (safe), never a misattribution.
pub(super) const OSINT_PROVIDERS: &[OsintProvider] = &[
    // Shodan — 32-char alphanumeric API key.
    OsintProvider {
        service: "shodan",
        contexts: &["shodan"],
        shapes: &[ALNUM32],
    },
    // VirusTotal — 64-char lowercase-hex API key.
    OsintProvider {
        service: "virustotal",
        contexts: &["virustotal"],
        shapes: &[HEX64],
    },
    // Hunter.io — 40-char hex API key.
    OsintProvider {
        service: "hunter",
        contexts: &["hunter"],
        shapes: &[HEX40],
    },
    // SecurityTrails — 32-char alphanumeric API key.
    OsintProvider {
        service: "securitytrails",
        contexts: &["securitytrails"],
        shapes: &[ALNUM32],
    },
    // GreyNoise — 32-char alphanumeric API key.
    OsintProvider {
        service: "greynoise",
        contexts: &["greynoise"],
        shapes: &[ALNUM32],
    },
    // Censys — 32-char alphanumeric API *secret* (its paired ID is a UUID).
    OsintProvider {
        service: "censys",
        contexts: &["censys"],
        shapes: &[ALNUM32],
    },
    // AbuseIPDB — 80-char alphanumeric API key.
    OsintProvider {
        service: "abuseipdb",
        contexts: &["abuseipdb"],
        shapes: &[ALNUM80],
    },
    // Pulsedive — 32-char alphanumeric API key.
    OsintProvider {
        service: "pulsedive",
        contexts: &["pulsedive"],
        shapes: &[ALNUM32],
    },
    // ZoomEye — 32-char (legacy) access token.
    OsintProvider {
        service: "zoomeye",
        contexts: &["zoomeye"],
        shapes: &[ALNUM32],
    },
    // Have I Been Pwned — 32-char alphanumeric API key.
    OsintProvider {
        service: "hibp",
        contexts: &["haveibeenpwned", "hibp"],
        shapes: &[ALNUM32],
    },
    // LeakIX — 40-char base64url-ish API key.
    OsintProvider {
        service: "leakix",
        contexts: &["leakix"],
        shapes: &[ALNUM40],
    },
    // Dehashed — 32-char alphanumeric API key.
    OsintProvider {
        service: "dehashed",
        contexts: &["dehashed"],
        shapes: &[ALNUM32],
    },
];

/// Attribute a prefix-less key `value` to an OSINT/threat-intel provider when
/// `context` (an env-var name, object key, or URL) names the provider and the
/// value matches one of that provider's accepted [`Shape`]s. Returns the
/// provider's service tag, or `None` when no provider both is named and fits.
///
/// **Pure** — it does not apply the false-positive gate; the caller
/// ([`super::identify_with_context`]) layers [`super::is_likely_real_key`] on top
/// so a placeholder / UUID / low-entropy value is never attributed. Allocation is
/// one lowercase of the short `context`; the length pre-gate skips it for values
/// that cannot match any shape.
pub(super) fn match_osint_provider(context: &str, value: &str) -> Option<&'static str> {
    let v = value.trim();
    // Every shape is 32..=80 chars; bail before allocating the lowercase context.
    if !(32..=80).contains(&v.len()) {
        return None;
    }
    let ctx = context.to_ascii_lowercase();
    OSINT_PROVIDERS
        .iter()
        .find(|p| {
            p.contexts.iter().any(|c| ctx.contains(c)) && p.shapes.iter().any(|s| s.matches(v))
        })
        .map(|p| p.service)
}
