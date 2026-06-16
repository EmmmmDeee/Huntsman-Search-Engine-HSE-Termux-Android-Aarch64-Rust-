use serde::{Deserialize, Serialize};
use std::fmt;

// ─── EntityKind ──────────────────────────────────────────────────────────────

/// All value types an entity can represent.
///
/// People-centric kinds (Person, Email, Phone, Username) are weighted highest
/// in module priority ordering. Infrastructure kinds are enrichment targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    // People-centric (priority identity)
    Person,
    Email,
    Phone,
    Username,

    // Document / credential
    Credential,
    ApiKey,
    Password, // never stored in evidence output

    // Network / infrastructure
    IpAddress,
    Domain,
    Url,
    Asn,
    /// A CIDR network block (`192.0.2.0/24`, `2001:db8::/48`). A scannable
    /// target that expands into its constituent host IPs (bounded).
    Cidr,

    // Physical / GEOINT
    Address,
    Coordinates,

    // Organisation
    Organisation,
    AbnAcn,

    // Device
    MacAddress,
    DeviceId,

    // Web-analytics / tracking identifier (Google Analytics `UA-`/`G-`, GTM
    // `GTM-`, AdSense `ca-pub-`, Facebook Pixel, Yandex Metrica, Hotjar). A shared
    // ID across otherwise-unrelated sites is strong evidence of common ownership —
    // the "affiliate" pivot. Not a scannable target; a correlation node only.
    TrackingId,

    // Financial — cryptocurrency wallet addresses (BTC/ETH/LTC/…). A first-class
    // OSINT artifact: case-sensitive (base58 / bech32 / 0x-hex), never an API
    // key, and the pivot point for free chain-explorer enrichment.
    CryptoAddress,

    // Catch-all
    Other(String),
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Person => f.write_str("person"),
            Self::Email => f.write_str("email"),
            Self::Phone => f.write_str("phone"),
            Self::Username => f.write_str("username"),
            Self::Credential => f.write_str("credential"),
            Self::ApiKey => f.write_str("api_key"),
            Self::Password => f.write_str("password"),
            Self::IpAddress => f.write_str("ip_address"),
            Self::Domain => f.write_str("domain"),
            Self::Url => f.write_str("url"),
            Self::Asn => f.write_str("asn"),
            Self::Cidr => f.write_str("cidr"),
            Self::Address => f.write_str("address"),
            Self::Coordinates => f.write_str("coordinates"),
            Self::Organisation => f.write_str("organisation"),
            Self::AbnAcn => f.write_str("abn_acn"),
            Self::MacAddress => f.write_str("mac_address"),
            Self::DeviceId => f.write_str("device_id"),
            Self::TrackingId => f.write_str("tracking_id"),
            Self::CryptoAddress => f.write_str("crypto_address"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

// ─── Classification ───────────────────────────────────────────────────────────

/// Derived-only classification tier from `C_eff`.
///
/// Never set directly — always call `Entity::classify()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    /// `C_eff < 0.40`
    Candidate,
    /// `0.40 ≤ C_eff < 0.75`
    Probable,
    /// `C_eff ≥ 0.75`
    Verified,
}

impl Classification {
    /// Lower bound of the Verified tier: `C_eff ≥ VERIFIED_MIN`.
    ///
    /// The tier ladder's single source of truth (with [`Self::PROBABLE_MIN`]).
    /// Consumed by [`Self::from_c_eff`] / `Entity::classify`, the CLI's
    /// confidence colouring, the engine's subject-identity gate ("every
    /// VERIFIED identity"), and the wrong-identity pivot gate ("below the
    /// Verified tier") — previously each re-stated `0.75` as a bare literal,
    /// so a recalibration would have silently diverged them.
    pub const VERIFIED_MIN: f64 = 0.75;
    /// Lower bound of the Probable tier: `C_eff ≥ PROBABLE_MIN` (and below
    /// [`Self::VERIFIED_MIN`]). Below this is Candidate.
    pub const PROBABLE_MIN: f64 = 0.40;

    /// The tier for an effective confidence — the canonical ladder. A
    /// non-finite `c_eff` (never produced by `c_effective`, which clamps)
    /// fails both bounds and lands in `Candidate`, the conservative tier.
    #[inline]
    #[must_use]
    pub fn from_c_eff(c_eff: f64) -> Self {
        if c_eff >= Self::VERIFIED_MIN {
            Self::Verified
        } else if c_eff >= Self::PROBABLE_MIN {
            Self::Probable
        } else {
            Self::Candidate
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Probable => "PROBABLE",
            Self::Verified => "VERIFIED",
        }
    }

    /// Stable, dense tier rank (0 = Candidate, 1 = Probable, 2 = Verified).
    ///
    /// This is the finite tier ladder intended to back a bounded best-first
    /// expansion: with a `(target, tier)` visited-set an entity is expanded at
    /// most once per rank, and because there are exactly
    /// [`Classification::COUNT`] ranks, total expansions are bounded by
    /// `entities × COUNT`.
    ///
    /// NOTE (current state): the engine's expansion visited-set is still keyed
    /// on `(TargetKind, normalised value)` and expands each target at most
    /// once overall — it does not yet key on tier or re-queue on tier
    /// graduation. `rank()`/[`Self::COUNT`] are the ladder that the planned
    /// tier-aware frontier will use; until that lands, this method is consumed
    /// by tests and ranking, not by the live visited-set.
    #[inline]
    pub fn rank(self) -> u8 {
        match self {
            Self::Candidate => 0,
            Self::Probable => 1,
            Self::Verified => 2,
        }
    }

    /// Number of distinct confidence tiers. Fixed and finite — the
    /// multiplier in the halting bound `expansions ≤ entities × COUNT`.
    pub const COUNT: u8 = 3;
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
