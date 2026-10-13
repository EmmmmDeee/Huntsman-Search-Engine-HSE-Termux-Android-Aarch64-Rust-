//! Entity types, canonicalization, and immutable provenance primitives.
//!
//! Entity identity is content-addressed. [`EntityKind::entity_id`] hashes a versioned,
//! injective encoding of the variant and its fields under a BLAKE3 derive-key context, so two
//! distinct entities can never share a preimage and an id is stable across processes, builds
//! and hosts. Domain names enter the model only through [`EntityKind::new_domain`], which
//! canonicalizes and validates them so one real name maps to one id.

use crate::error::HuntsmanError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// 256-bit cryptographic identifier derived deterministically.
pub type EntityId = [u8; 32];

/// BLAKE3 derive-key context separating entity ids from every other digest in the engine
/// (evidence digests use plain `blake3::hash`). The version suffix changes whenever the preimage
/// encoding changes, so an id minted under an older scheme can never equal a current one.
const ENTITY_ID_CONTEXT: &str = "huntsman/entity-id/v2";

/// RFC 1035 §2.3.4 maximum presentation length of a domain name without its root dot.
const MAX_DOMAIN_LEN: usize = 253;
/// RFC 1035 §2.3.4 maximum octets in one label.
const MAX_LABEL_LEN: usize = 63;
/// Characters of rejected input quoted (escaped) in a rejection message.
const ERROR_PREFIX_CHARS: usize = 24;

/// Epistemic validation tier for ingested indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EpistemicLevel {
    /// Directly observed over the wire (handshakes, protocol banners, active DNS).
    DirectObservation,
    /// Extracted from append-only cryptographic systems (Certificate Transparency).
    ProtocolLog,
    /// Observational evidence node from third-party indexes or exposure dumps.
    ThirdPartyIndex,
}

/// Immutable provenance ledger envelope attached to every observed entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEnvelope {
    /// Deterministic node identifier.
    pub entity_id: EntityId,
    /// Originating module identifier.
    pub source_module: String,
    /// UTC timestamp in microseconds since Unix epoch.
    pub observed_at_utc: u64,
    /// BLAKE3 digest of the raw wire payload.
    pub raw_evidence_hash: [u8; 32],
    /// Epistemic classification of this artifact.
    pub epistemic_level: EpistemicLevel,
}

impl ProvenanceEnvelope {
    /// Creates a verified provenance envelope, computing the deterministic entity ID with
    /// [`EntityKind::entity_id`] and the evidence digest from the raw payload.
    #[must_use]
    pub fn new(
        source_module: &'static str,
        observed_at_utc: u64,
        raw_payload: &[u8],
        kind: &EntityKind,
        epistemic_level: EpistemicLevel,
    ) -> Self {
        let evidence_hash = blake3::hash(raw_payload);
        Self {
            entity_id: kind.entity_id(),
            source_module: source_module.to_string(),
            observed_at_utc,
            raw_evidence_hash: *evidence_hash.as_bytes(),
            epistemic_level,
        }
    }
}

/// Canonical entity variants recognized by the correlation engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    /// Fully qualified domain name in canonical form: ASCII-lowercased LDH labels, no root dot,
    /// internationalized labels as Punycode A-labels. Build it through
    /// [`EntityKind::new_domain`], the only validating constructor; the id computation itself
    /// only folds ASCII case.
    Domain(String),
    /// Canonical IPv4 or IPv6 address.
    Ip(IpAddr),
    /// Autonomous System Number.
    Asn(u32),
    /// Service banner or cleartext daemon response.
    ServiceBanner {
        /// Target port number.
        port: u16,
        /// Hex-encoded or sanitized representation of banner bytes.
        banner: String,
    },
    /// Observational credential exposure artifact.
    CredentialExposure {
        /// Account identifier or email address.
        identity: String,
        /// Public breach or dump origin descriptor.
        source_dataset: String,
    },
}

impl EntityKind {
    /// Static string representation of the underlying entity variant.
    #[must_use]
    pub fn type_tag(&self) -> &'static str {
        match self {
            Self::Domain(_) => "DOMAIN",
            Self::Ip(_) => "IP",
            Self::Asn(_) => "ASN",
            Self::ServiceBanner { .. } => "BANNER",
            Self::CredentialExposure { .. } => "EXPOSURE",
        }
    }

    /// Deterministic content-addressed identifier of this entity.
    ///
    /// The preimage is injective. Under the `huntsman/entity-id/v2` derive-key context, the type
    /// tag and then every field are each written as a big-endian `u64` byte length followed by
    /// the bytes, so field contents can never shift a field boundary: an exposure of identity
    /// `a:b` in dataset `c` and one of identity `a` in dataset `b:c` hash differently. Fields
    /// that DNS and mail treat case-insensitively (domain names, exposure identities) are
    /// ASCII-lowercased first, so spelling variants of one entity share one id.
    #[must_use]
    pub fn entity_id(&self) -> EntityId {
        let mut hasher = blake3::Hasher::new_derive_key(ENTITY_ID_CONTEXT);
        self.hash_into(&mut hasher);
        *hasher.finalize().as_bytes()
    }

    /// Feed the framed preimage of this entity into `hasher`.
    fn hash_into(&self, hasher: &mut blake3::Hasher) {
        frame(hasher, self.type_tag().as_bytes());
        match self {
            Self::Domain(domain) => frame(hasher, domain.to_ascii_lowercase().as_bytes()),
            Self::Ip(IpAddr::V4(v4)) => frame(hasher, &v4.octets()),
            Self::Ip(IpAddr::V6(v6)) => frame(hasher, &v6.octets()),
            Self::Asn(asn) => frame(hasher, &asn.to_be_bytes()),
            Self::ServiceBanner { port, banner } => {
                frame(hasher, &port.to_be_bytes());
                frame(hasher, banner.as_bytes());
            }
            Self::CredentialExposure {
                identity,
                source_dataset,
            } => {
                frame(hasher, identity.to_ascii_lowercase().as_bytes());
                frame(hasher, source_dataset.as_bytes());
            }
        }
    }

    /// Human-readable canonical form for logs, display and ordering.
    ///
    /// This is not the identity preimage: it joins fields with `:` and is therefore ambiguous
    /// for values that contain a colon. Use [`EntityKind::entity_id`] for identity.
    #[must_use]
    pub fn canonical_value(&self) -> String {
        match self {
            Self::Domain(d) => d.to_ascii_lowercase(),
            Self::Ip(ip) => ip.to_string(),
            Self::Asn(asn) => format!("AS{asn}"),
            Self::ServiceBanner { port, banner } => format!("{port}:{banner}"),
            Self::CredentialExposure {
                identity,
                source_dataset,
            } => {
                format!("{}:{}", identity.to_ascii_lowercase(), source_dataset)
            }
        }
    }

    /// Construct a canonical domain entity from presentation-format input.
    ///
    /// Normalization performed:
    /// - surrounding whitespace is trimmed and one trailing root dot is removed;
    /// - ASCII letters are lowercased (DNS names are case-insensitive, RFC 4343).
    ///
    /// Validation performed (RFC 1035 §2.3.4 LDH syntax plus RFC 8552 underscored names):
    /// - the name is 1 to 253 bytes and every label is 1 to 63 bytes, with no empty label;
    /// - each label is ASCII letters, digits and hyphens with no leading or trailing hyphen,
    ///   optionally preceded by exactly one `_` (service and attribute labels such as `_dmarc`
    ///   or `_sip._tcp`); an underscore anywhere else is rejected;
    /// - interior whitespace, control characters and every other byte are rejected.
    ///
    /// Not performed: no IDNA/UTS #46 processing. Internationalized names must already be
    /// Punycode A-labels (`xn--…`); non-ASCII input is rejected rather than mapped, and the
    /// Punycode payload of an `xn--` label is not decoded or validated.
    ///
    /// # Errors
    /// [`HuntsmanError::Protocol`] naming the violated rule, the input's byte length and a short
    /// escaped prefix of it. The raw input is never echoed, so a hostile name cannot inject log
    /// lines or inflate error messages.
    pub fn new_domain(raw: &str) -> Result<Self, HuntsmanError> {
        canonical_domain(raw).map(Self::Domain).map_err(|reason| {
            HuntsmanError::Protocol(format!(
                "invalid domain name: {reason} (input: {} bytes, {})",
                raw.len(),
                escaped_prefix(raw)
            ))
        })
    }
}

/// Write one length-prefixed field: a big-endian `u64` byte count, then the bytes.
fn frame(hasher: &mut blake3::Hasher, field: &[u8]) {
    // usize is at most 64 bits wide on every supported target, so the conversion is lossless.
    let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
    hasher.update(&len.to_be_bytes());
    hasher.update(field);
}

/// Why presentation-format input is not a valid canonical domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainSyntaxError {
    /// Nothing is left after trimming and removing the root dot.
    Empty,
    /// The name exceeds [`MAX_DOMAIN_LEN`] bytes.
    TooLong(usize),
    /// A character outside ASCII: U-labels need Punycode encoding first.
    NonAscii(char),
    /// A leading dot or two consecutive dots.
    EmptyLabel,
    /// A label exceeds [`MAX_LABEL_LEN`] bytes.
    LabelTooLong(usize),
    /// A label is nothing but its leading underscore.
    BareUnderscore,
    /// A label starts or ends with a hyphen.
    HyphenAtLabelEdge,
    /// An underscore anywhere but the first character of a label.
    UnderscoreInsideLabel,
    /// An ASCII character LDH syntax forbids (whitespace, control or punctuation).
    ForbiddenAscii(char),
}

impl fmt::Display for DomainSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("name is empty"),
            Self::TooLong(len) => write!(f, "name is {len} bytes, longer than {MAX_DOMAIN_LEN}"),
            Self::NonAscii(c) => write!(
                f,
                "non-ASCII character U+{:04X}; Punycode-encoded (xn--) A-labels are required",
                u32::from(*c)
            ),
            Self::EmptyLabel => f.write_str("name contains an empty label"),
            Self::LabelTooLong(len) => {
                write!(f, "label is {len} bytes, longer than {MAX_LABEL_LEN}")
            }
            Self::BareUnderscore => f.write_str("label is only an underscore"),
            Self::HyphenAtLabelEdge => f.write_str("label starts or ends with a hyphen"),
            Self::UnderscoreInsideLabel => {
                f.write_str("underscore is only allowed as the first character of a label")
            }
            Self::ForbiddenAscii(c) => {
                write!(f, "character {c:?} is not a letter, digit or hyphen")
            }
        }
    }
}

/// Canonicalize and validate `raw` as described on [`EntityKind::new_domain`].
fn canonical_domain(raw: &str) -> Result<String, DomainSyntaxError> {
    let name = raw.trim();
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DomainSyntaxError::Empty);
    }
    if let Some(c) = name.chars().find(|c| !c.is_ascii()) {
        return Err(DomainSyntaxError::NonAscii(c));
    }
    if name.len() > MAX_DOMAIN_LEN {
        return Err(DomainSyntaxError::TooLong(name.len()));
    }
    for label in name.split('.') {
        validate_label(label)?;
    }
    Ok(name.to_ascii_lowercase())
}

/// Check one ASCII label against LDH syntax with an optional leading underscore.
fn validate_label(label: &str) -> Result<(), DomainSyntaxError> {
    if label.is_empty() {
        return Err(DomainSyntaxError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(DomainSyntaxError::LabelTooLong(label.len()));
    }
    let body = label.strip_prefix('_').unwrap_or(label);
    if body.is_empty() {
        return Err(DomainSyntaxError::BareUnderscore);
    }
    if body.starts_with('-') || body.ends_with('-') {
        return Err(DomainSyntaxError::HyphenAtLabelEdge);
    }
    for c in body.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {}
            '_' => return Err(DomainSyntaxError::UnderscoreInsideLabel),
            other => return Err(DomainSyntaxError::ForbiddenAscii(other)),
        }
    }
    Ok(())
}

/// A short, log-safe quotation of `raw`: at most [`ERROR_PREFIX_CHARS`] characters with
/// control, quote and non-ASCII characters escaped, and an ellipsis when truncated.
fn escaped_prefix(raw: &str) -> String {
    let mut quoted = String::from("prefix \"");
    quoted.extend(
        raw.chars()
            .take(ERROR_PREFIX_CHARS)
            .flat_map(char::escape_default),
    );
    quoted.push('"');
    if raw.chars().nth(ERROR_PREFIX_CHARS).is_some() {
        quoted.push_str("...");
    }
    quoted
}

/// Fully qualified observed entity carrying its provenance envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Invariant provenance envelope.
    pub provenance: ProvenanceEnvelope,
    /// Canonical entity descriptor.
    pub kind: EntityKind,
    /// Graph traversal depth from original seed (0-indexed).
    pub hop_depth: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The id every consumer sees: the one `ProvenanceEnvelope::new` stamps on the envelope.
    fn id_of(kind: &EntityKind) -> EntityId {
        ProvenanceEnvelope::new("test", 0, b"", kind, EpistemicLevel::ThirdPartyIndex).entity_id
    }

    fn exposure(identity: &str, source_dataset: &str) -> EntityKind {
        EntityKind::CredentialExposure {
            identity: identity.to_owned(),
            source_dataset: source_dataset.to_owned(),
        }
    }

    fn banner(port: u16, banner: &str) -> EntityKind {
        EntityKind::ServiceBanner {
            port,
            banner: banner.to_owned(),
        }
    }

    fn domain(raw: &str) -> EntityKind {
        match EntityKind::new_domain(raw) {
            Ok(kind) => kind,
            Err(err) => panic!("{raw:?} must canonicalize: {err}"),
        }
    }

    fn rejection(raw: &str) -> String {
        match EntityKind::new_domain(raw) {
            Ok(kind) => panic!("{raw:?} must be rejected, got {kind:?}"),
            Err(HuntsmanError::Protocol(message)) => message,
            Err(other) => panic!("{raw:?} must be a Protocol error, got {other}"),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- entityid-exposure-collision -------------------------------------------------------

    #[test]
    fn exposures_that_share_a_joined_string_get_distinct_ids() {
        let crafted = exposure("a:b", "c");
        let genuine = exposure("a", "b:c");
        assert_eq!(crafted.canonical_value(), genuine.canonical_value());
        assert_ne!(id_of(&crafted), id_of(&genuine));
    }

    #[test]
    fn every_split_of_an_exposure_row_is_its_own_entity() {
        let row = "alice:corp:leak2024";
        let mut ids = HashSet::new();
        for (cut, _) in row.match_indices(':') {
            let (identity, dataset) = (&row[..cut], &row[cut + 1..]);
            ids.insert(id_of(&exposure(identity, dataset)));
        }
        assert_eq!(ids.len(), 2, "both colon splits must be distinct ids");
    }

    #[test]
    fn banner_ids_do_not_collide_through_field_boundaries() {
        assert_ne!(id_of(&banner(1, "2:x")), id_of(&banner(12, "x")));
        assert_ne!(id_of(&banner(22, "")), id_of(&banner(2, "2:")));
    }

    #[test]
    fn ids_are_separated_by_variant() {
        let as1 = id_of(&EntityKind::Asn(1));
        assert_ne!(as1, id_of(&EntityKind::Domain("AS1".to_owned())));
        assert_ne!(as1, id_of(&banner(0, "AS1")));
        let v4 = id_of(&EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        let mapped = id_of(&EntityKind::Ip(IpAddr::V6(
            Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped(),
        )));
        assert_ne!(v4, mapped);
    }

    #[test]
    fn ids_fold_ascii_case_where_the_protocol_does() {
        assert_eq!(
            id_of(&EntityKind::Domain("Example.COM".to_owned())),
            id_of(&EntityKind::Domain("example.com".to_owned()))
        );
        assert_eq!(
            id_of(&exposure("Alice@Example.com", "leak")),
            id_of(&exposure("alice@example.com", "leak"))
        );
        // Dataset descriptors and banners are opaque bytes: case is significant.
        assert_ne!(
            id_of(&exposure("alice", "Leak")),
            id_of(&exposure("alice", "leak"))
        );
        assert_ne!(id_of(&banner(80, "HTTP")), id_of(&banner(80, "http")));
    }

    #[test]
    fn ids_depend_on_the_kind_alone() {
        let kind = domain("example.com");
        let a = ProvenanceEnvelope::new("seed", 1, b"one", &kind, EpistemicLevel::ProtocolLog);
        let b = ProvenanceEnvelope::new(
            "dns_resolve",
            2,
            b"two",
            &kind,
            EpistemicLevel::DirectObservation,
        );
        assert_eq!(a.entity_id, b.entity_id);
        assert_ne!(a.raw_evidence_hash, b.raw_evidence_hash);
    }

    #[test]
    fn the_envelope_carries_the_kinds_own_id() {
        for kind in [
            domain("example.com"),
            EntityKind::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            EntityKind::Asn(64512),
            banner(25, "220 mail"),
            exposure("bob", "dump"),
        ] {
            assert_eq!(id_of(&kind), kind.entity_id(), "{kind:?}");
        }
    }

    #[test]
    fn entity_id_is_blake3_derive_key_over_framed_fields() {
        // The documented preimage, built by hand: context-keyed hasher, then the type tag and
        // each field as a big-endian u64 byte length followed by the bytes.
        let mut hasher = blake3::Hasher::new_derive_key("huntsman/entity-id/v2");
        for field in [&b"EXPOSURE"[..], b"alice@example.com", b"corp:leak2024"] {
            let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
            hasher.update(&len.to_be_bytes());
            hasher.update(field);
        }
        let by_hand = *hasher.finalize().as_bytes();
        assert_eq!(
            exposure("Alice@Example.com", "corp:leak2024").entity_id(),
            by_hand
        );

        let mut hasher = blake3::Hasher::new_derive_key("huntsman/entity-id/v2");
        for field in [&b"BANNER"[..], &22u16.to_be_bytes(), b"SSH-2.0"] {
            let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
            hasher.update(&len.to_be_bytes());
            hasher.update(field);
        }
        assert_eq!(
            banner(22, "SSH-2.0").entity_id(),
            *hasher.finalize().as_bytes()
        );
    }

    #[test]
    fn entity_ids_are_pinned_across_builds_and_runs() {
        // Golden digests of the v2 scheme. A change here is a change of every stored id, so it
        // must come with a new ENTITY_ID_CONTEXT version and a store re-key, never silently.
        let vectors = [
            (
                domain("example.com"),
                "e528b0f80082c2e54afb4cb6e70eac60ec27f3cb5867820072a3531eaff32fad",
            ),
            (
                EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                "6cc2c31649808002105a5dde265dd50b09ad8f0fce77dc4d2b4bfee689615525",
            ),
            (
                EntityKind::Ip(IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
                ))),
                "4195a7f10c4a419d400604008a11599e9439c2fe667c2ab3a80a0e94d29bcd77",
            ),
            (
                EntityKind::Asn(13335),
                "f1ec5fa1c5966be8705c4092f930afb0ab662309f1ffec79112698098f4075ab",
            ),
            (
                banner(22, "SSH-2.0-OpenSSH_9.6"),
                "cb069165d4c26b2f12e7e7ca08a2454593865392ebf4cbeff44fd7692cddde58",
            ),
            (
                exposure("alice@example.com", "corp:leak2024"),
                "b982f9d051d00a786575c300661ed24f1a84a7b3c149ef32aad80e7458f33711",
            ),
        ];
        let mut drifted = Vec::new();
        for (kind, expected) in vectors {
            assert_eq!(
                id_of(&kind),
                id_of(&kind.clone()),
                "id must be a pure function"
            );
            let actual = hex(&id_of(&kind));
            if actual != expected {
                drifted.push(format!("{kind:?}: expected {expected}, got {actual}"));
            }
        }
        assert!(
            drifted.is_empty(),
            "pinned ids drifted:\n{}",
            drifted.join("\n")
        );
    }

    // --- domain-normalization-missing ------------------------------------------------------

    #[test]
    fn equivalent_domain_spellings_share_one_entity_and_id() {
        let canonical = domain("example.com");
        assert_eq!(canonical, EntityKind::Domain("example.com".to_owned()));
        for raw in [
            "Example.COM.",
            "EXAMPLE.COM",
            "  example.com  ",
            "\texample.com.\n",
            "example.com.",
        ] {
            assert_eq!(
                domain(raw),
                canonical,
                "{raw:?} must canonicalize to example.com"
            );
            assert_eq!(id_of(&domain(raw)), id_of(&canonical));
        }
    }

    #[test]
    fn valid_ldh_underscored_and_a_label_names_are_accepted() {
        let max_label = "a".repeat(MAX_LABEL_LEN);
        // Four 63-byte labels (255 bytes with dots) exceed 253; three plus a 61-byte tail hit it.
        let max_name = format!("{max_label}.{max_label}.{max_label}.{}", "b".repeat(61));
        assert_eq!(max_name.len(), MAX_DOMAIN_LEN);
        for raw in [
            "example.com",
            "a.b-c.d",
            "xn--nxasmq6b.com",
            "_dmarc.example.com",
            "_sip._tcp.example.com",
            "_acme-challenge.example.com",
            "localhost",
            "123.example",
            max_label.as_str(),
            max_name.as_str(),
        ] {
            assert_eq!(domain(raw), EntityKind::Domain(raw.to_owned()));
        }
    }

    #[test]
    fn interior_whitespace_is_rejected() {
        assert!(rejection("exa mple.com").contains("' '"));
        assert!(rejection("example\t.com").contains("'\\t'"));
        assert!(rejection("example. com").contains("' '"));
    }

    #[test]
    fn hyphen_placement_is_enforced() {
        for raw in [
            "-bad.com",
            "bad-.com",
            "bad.-com",
            "bad.com-",
            "_-x.example.com",
        ] {
            assert!(
                rejection(raw).contains("hyphen"),
                "{raw:?} must fail the hyphen rule"
            );
        }
        assert_eq!(
            domain("b-ad.c-om"),
            EntityKind::Domain("b-ad.c-om".to_owned())
        );
    }

    #[test]
    fn empty_labels_and_extra_root_dots_are_rejected() {
        for raw in [
            "a..b",
            ".a",
            "a.",
            ".",
            "",
            "   ",
            "example.com..",
            "a..",
            "..a",
        ] {
            match EntityKind::new_domain(raw) {
                Ok(kind) if raw == "a." => assert_eq!(kind, EntityKind::Domain("a".to_owned())),
                Ok(kind) => panic!("{raw:?} must be rejected, got {kind:?}"),
                Err(HuntsmanError::Protocol(message)) => {
                    assert!(
                        message.contains("empty"),
                        "{raw:?} must report an empty name or label, got: {message}"
                    );
                }
                Err(other) => panic!("{raw:?} must be a Protocol error, got {other}"),
            }
        }
    }

    #[test]
    fn label_and_name_length_limits_are_enforced() {
        let sixty_four = "a".repeat(64);
        assert!(rejection(&format!("{sixty_four}.com")).contains("64 bytes, longer than 63"));
        let sixty_five = "a".repeat(65);
        assert!(rejection(&format!("{sixty_five}.com")).contains("65 bytes, longer than 63"));
        let label = "a".repeat(MAX_LABEL_LEN);
        let too_long = format!("{label}.{label}.{label}.{}", "b".repeat(62));
        assert_eq!(too_long.len(), MAX_DOMAIN_LEN + 1);
        assert!(rejection(&too_long).contains("254 bytes, longer than 253"));
        // The limit is measured after the root dot is removed.
        let with_root = format!("{label}.{label}.{label}.{}.", "b".repeat(61));
        assert_eq!(domain(&with_root).canonical_value().len(), MAX_DOMAIN_LEN);
    }

    #[test]
    fn non_ascii_input_is_rejected_and_the_error_asks_for_punycode() {
        for raw in [
            "exämple.com",
            "例え.jp",
            "ｅxample.com",
            "example.com\u{a0}x",
        ] {
            let message = rejection(raw);
            assert!(message.contains("Punycode"), "{raw:?}: {message}");
            assert!(
                message.is_ascii(),
                "{raw:?}: message must stay ASCII: {message}"
            );
        }
        assert!(rejection("exämple.com").contains("U+00E4"));
    }

    #[test]
    fn control_characters_are_rejected() {
        for raw in [
            "exam\u{7}ple.com",
            "a\nb.com",
            "example.com\r\nforged=line",
            "a\u{0}b.com",
            "a\u{1b}[31mb.com",
        ] {
            let message = rejection(raw);
            assert!(
                message.contains("is not a letter, digit or hyphen"),
                "{raw:?}: {message}"
            );
            assert!(
                message.chars().all(|c| !c.is_control()),
                "{raw:?}: message must not carry the control character: {message:?}"
            );
        }
    }

    #[test]
    fn underscores_are_accepted_only_as_a_label_prefix() {
        assert!(rejection("foo_bar.com").contains("underscore is only allowed"));
        assert!(rejection("a_.com").contains("underscore is only allowed"));
        assert!(rejection("__dmarc.example.com").contains("underscore is only allowed"));
        assert!(rejection("_.example.com").contains("only an underscore"));
    }

    #[test]
    fn rejection_messages_never_echo_the_input() {
        let hostile = format!("{}\nforged log line {}", "x".repeat(5000), "y".repeat(5000));
        let message = rejection(&hostile);
        assert!(!message.contains('\n'), "newline leaked: {message:?}");
        assert!(
            !message.contains("forged log line"),
            "input leaked: {message}"
        );
        assert!(
            message.len() < 200,
            "message is {} bytes: {message}",
            message.len()
        );
        assert!(message.contains(&format!("{} bytes", hostile.len())));
        assert!(message.contains("prefix \"xxxxxxxxxxxxxxxxxxxxxxxx\"..."));
        // Short input is quoted whole, escaped, with no ellipsis.
        assert!(rejection("a\u{7}b").contains("prefix \"a\\u{7}b\")"));
    }
}
