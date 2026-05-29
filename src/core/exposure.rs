//! Self-exposure assessment — the defensive inversion of a scan.
//!
//! A scan answers "what can an investigator find about this target?".
//! This module answers the question that actually protects a person:
//! "given what was found, how exposed am I, and what do I do about it?".
//!
//! It is a pure, deterministic, network-free analysis over a set of
//! already-collected [`Entity`] values. It produces severity-ranked
//! [`Finding`]s, each with concrete remediation steps, plus a single
//! `exposure_score` (0–100, higher = more exposed) and a letter grade.
//!
//! Design notes:
//!   - **Collection limitation.** The analysis never reaches the network
//!     and never invents new identifiers — it only reasons over what a
//!     scan already surfaced. Output can be rendered with identifiers
//!     redacted (see [`redact_value`]) so an exposure report can be
//!     shared without re-exposing the very data it is about.
//!   - **Defensive intent.** Findings are framed for the *subject* — the
//!     person reducing their own footprint — not for an attacker. Every
//!     finding carries remediation, never an exploitation hint.
//!   - **Deterministic.** No clocks, no RNG, no I/O. Same entities in →
//!     same report out, so it is trivially unit-testable and diffable
//!     across re-scans to measure whether exposure is shrinking.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::entity::{Entity, EntityKind};

/// Severity of a single exposure finding. Ordered most-severe first so a
/// `sort` on the discriminant surfaces the things to fix soonest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }

    /// Per-finding weight subtracted from a perfect (0-exposure) posture.
    /// Used to roll individual findings up into the headline score.
    fn weight(self) -> u32 {
        match self {
            Self::Critical => 45,
            Self::High => 22,
            Self::Medium => 10,
            Self::Low => 4,
            Self::Info => 0,
        }
    }
}

/// A single exposure finding, framed for the subject who wants to reduce it.
///
/// Serialize-only: `id` is a `&'static str` catalogue key, so this type is
/// produced for output (JSON report) but never deserialized back.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `EXP-CRED-001`. Lets reports cross-reference
    /// findings the way the correlator references `AU-0xx` rules.
    pub id: &'static str,
    pub severity: Severity,
    /// Short headline.
    pub title: String,
    /// What was observed and why it matters to the subject.
    pub detail: String,
    /// Concrete steps the subject can take to shrink this exposure.
    pub remediation: Vec<String>,
    /// Representative entity values behind this finding (subject to redaction).
    pub related: Vec<String>,
}

/// The complete exposure assessment for one set of entities.
#[derive(Debug, Clone, Serialize)]
pub struct ExposureReport {
    /// 0–100, higher = more exposed. 0 = nothing of concern surfaced.
    pub exposure_score: u32,
    /// Letter grade derived from `exposure_score` (A = well-protected).
    pub grade: char,
    /// Count of entities seen, keyed by kind label (stable, sorted).
    pub entity_counts: BTreeMap<String, usize>,
    /// Findings, most-severe first.
    pub findings: Vec<Finding>,
}

impl ExposureReport {
    /// Number of findings at or above `sev`.
    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity <= sev).count()
    }
}

/// Mask an identifier so a report can be shared without re-leaking it.
///
/// Keeps just enough to recognise your own value (`j***n@h***l.com`,
/// `+61***556`) while removing the bulk. Deterministic and lossy by design.
pub fn redact_value(kind: &EntityKind, value: &str) -> String {
    match kind {
        EntityKind::Email => match value.split_once('@') {
            Some((local, domain)) => format!("{}@{}", mask_keep_ends(local), mask_keep_ends(domain)),
            None => mask_keep_ends(value),
        },
        EntityKind::Coordinates => "<coordinates redacted>".to_string(),
        EntityKind::Address => "<address redacted>".to_string(),
        _ => mask_keep_ends(value),
    }
}

/// Keep the first and last character, mask the middle. Short values are
/// fully masked so we never echo a 1–3 character secret verbatim.
fn mask_keep_ends(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    match chars.len() {
        0 => String::new(),
        1..=3 => "*".repeat(chars.len()),
        n => {
            let mut out = String::new();
            out.push(chars[0]);
            out.push_str(&"*".repeat(n - 2));
            out.push(chars[n - 1]);
            out
        }
    }
}

/// True if any evidence/tag on the entity hints it came from a breach,
/// stealer-log, or paste source — without storing any credential content.
fn looks_breached(e: &Entity) -> bool {
    const NEEDLES: [&str; 6] = ["breach", "stealer", "paste", "leak", "hibp", "pwned"];
    let tag_hit = e
        .tags
        .iter()
        .any(|t| NEEDLES.iter().any(|n| t.to_lowercase().contains(n)));
    let ev_hit = e.evidence.iter().any(|ev| {
        let s = ev.source.to_lowercase();
        let m = ev.summary.to_lowercase();
        NEEDLES.iter().any(|n| s.contains(n) || m.contains(n))
    });
    tag_hit || ev_hit
}

/// Assess exposure for a set of entities. Pure and deterministic.
pub fn assess(entities: &[Entity]) -> ExposureReport {
    // Bucket entities by kind once.
    let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }
    let entity_counts: BTreeMap<String, usize> =
        by_kind.iter().map(|(k, v)| (k.clone(), v.len())).collect();

    let get = |k: &str| by_kind.get(k).map(Vec::as_slice).unwrap_or(&[]);
    let mut findings: Vec<Finding> = Vec::new();

    // ── CRITICAL: credentials / secrets surfaced ────────────────────────────
    let cred_kinds = ["credential", "password", "api_key"];
    let creds: Vec<&Entity> = cred_kinds.iter().flat_map(|k| get(k).iter().copied()).collect();
    if !creds.is_empty() {
        findings.push(Finding {
            id: "EXP-CRED-001",
            severity: Severity::Critical,
            title: format!("{} credential/secret artefact(s) discoverable", creds.len()),
            detail: "Credentials, password material, or API keys associated with you \
                     surfaced in open sources. Anything an automated scan can reach, an \
                     attacker can too — assume these are already compromised."
                .to_string(),
            remediation: vec![
                "Rotate every affected credential and API key now; treat them as burned."
                    .to_string(),
                "Enable phishing-resistant 2FA (hardware key/passkey) on the linked accounts."
                    .to_string(),
                "Stop reusing passwords — adopt a password manager with unique per-site secrets."
                    .to_string(),
            ],
            related: creds.iter().map(|e| (e.kind.clone(), e.value.clone())).map(|(k, v)| format!("{k}:{v}")).collect(),
        });
    }

    // ── Email exposure (split breached vs merely discoverable) ──────────────
    let emails = get("email");
    let (breached_emails, plain_emails): (Vec<&Entity>, Vec<&Entity>) =
        emails.iter().partition(|e| looks_breached(e));
    if !breached_emails.is_empty() {
        findings.push(Finding {
            id: "EXP-MAIL-001",
            severity: Severity::High,
            title: format!("{} email address(es) appear in breach/stealer data", breached_emails.len()),
            detail: "One or more of your email addresses were found in breach, stealer-log, \
                     or paste sources. Even without the password itself, this confirms the \
                     address is a live target for credential-stuffing and phishing."
                .to_string(),
            remediation: vec![
                "Change passwords on any account using these addresses; never reuse them."
                    .to_string(),
                "Turn on breach monitoring (e.g. HIBP notifications) for each address."
                    .to_string(),
                "Use per-service email aliases so one breach can't pivot across accounts."
                    .to_string(),
            ],
            related: breached_emails.iter().map(|e| e.value.clone()).collect(),
        });
    }
    if !plain_emails.is_empty() {
        findings.push(Finding {
            id: "EXP-MAIL-002",
            severity: Severity::Medium,
            title: format!("{} email address(es) publicly discoverable", plain_emails.len()),
            detail: "Email addresses tied to you are findable in open sources, broadening \
                     your phishing and account-recovery attack surface."
                .to_string(),
            remediation: vec![
                "Separate public-facing from sensitive/recovery email addresses.".to_string(),
                "Use aliases or a relay so the real mailbox isn't the public handle.".to_string(),
            ],
            related: plain_emails.iter().map(|e| e.value.clone()).collect(),
        });
    }

    // ── Physical location (address + coordinates) ───────────────────────────
    let addresses = get("address");
    let coords = get("coordinates");
    if !addresses.is_empty() || !coords.is_empty() {
        let n = addresses.len() + coords.len();
        findings.push(Finding {
            id: "EXP-GEO-001",
            severity: Severity::High,
            title: format!("{n} physical-location signal(s) inferable"),
            detail: "Open sources resolve toward a physical location for you (address and/or \
                     coordinates). Physical location is high-harm — it bridges the online \
                     footprint to the real world."
                .to_string(),
            remediation: vec![
                "File removals with people-search/data-broker sites that list your address."
                    .to_string(),
                "Strip EXIF GPS from photos before posting; disable per-app location where unneeded."
                    .to_string(),
                "Use a PO box / virtual address for registrations that go on public record."
                    .to_string(),
            ],
            related: addresses
                .iter()
                .chain(coords.iter())
                .map(|e| (e.kind.clone(), e.value.clone()))
                .map(|(k, v)| format!("{k}:{v}"))
                .collect(),
        });
    }

    // ── Phone number ────────────────────────────────────────────────────────
    let phones = get("phone");
    if !phones.is_empty() {
        findings.push(Finding {
            id: "EXP-PHONE-001",
            severity: Severity::Medium,
            title: format!("{} phone number(s) discoverable", phones.len()),
            detail: "A phone number tied to you is findable. Phone numbers are prime targets \
                     for SIM-swap and SMS-interception attacks against account recovery."
                .to_string(),
            remediation: vec![
                "Move account recovery off SMS to an authenticator app or hardware key."
                    .to_string(),
                "Ask your carrier to add a port-out/SIM-swap PIN.".to_string(),
                "Use a separate VoIP number for public listings.".to_string(),
            ],
            related: phones.iter().map(|e| e.value.clone()).collect(),
        });
    }

    // ── Username reuse / cross-platform correlation ─────────────────────────
    let usernames = get("username");
    if usernames.len() >= 3 {
        findings.push(Finding {
            id: "EXP-USER-001",
            severity: Severity::Medium,
            title: format!("{} reused username(s) enable cross-platform linking", usernames.len()),
            detail: "The same handle(s) recur across platforms, letting an investigator \
                     correlate otherwise-separate accounts into one identity graph."
                .to_string(),
            remediation: vec![
                "Use distinct, unrelated handles for accounts you want kept separate.".to_string(),
                "Retire or rename high-signal legacy handles where you can.".to_string(),
            ],
            related: usernames.iter().map(|e| e.value.clone()).collect(),
        });
    } else if !usernames.is_empty() {
        findings.push(Finding {
            id: "EXP-USER-002",
            severity: Severity::Low,
            title: format!("{} username(s) attributable to you", usernames.len()),
            detail: "Handle(s) are attributable to you in open sources.".to_string(),
            remediation: vec![
                "Keep sensitive accounts on handles unrelated to your public ones.".to_string(),
            ],
            related: usernames.iter().map(|e| e.value.clone()).collect(),
        });
    }

    // ── Device / network hardware identifiers ───────────────────────────────
    let macs = get("mac_address");
    if !macs.is_empty() {
        findings.push(Finding {
            id: "EXP-DEV-001",
            severity: Severity::Medium,
            title: format!("{} hardware identifier(s) exposed", macs.len()),
            detail: "MAC/BSSID identifiers can geolocate a device or access point via \
                     wardriving databases and enable device tracking across networks."
                .to_string(),
            remediation: vec![
                "Enable MAC randomisation on Wi-Fi for all devices.".to_string(),
                "Request removal of your home AP BSSID from Wi-Fi geolocation databases."
                    .to_string(),
            ],
            related: macs.iter().map(|e| e.value.clone()).collect(),
        });
    }

    // ── IP address ──────────────────────────────────────────────────────────
    let ips = get("ip_address");
    if !ips.is_empty() {
        findings.push(Finding {
            id: "EXP-NET-001",
            severity: Severity::Low,
            title: format!("{} IP address(es) attributable to you", ips.len()),
            detail: "IP addresses linked to you give a coarse location and ISP, and can \
                     corroborate other signals into a tighter fix."
                .to_string(),
            remediation: vec![
                "Use a reputable VPN for activity you don't want tied to your home IP."
                    .to_string(),
                "Prefer ISPs/plans with rotating dynamic addresses where it matters.".to_string(),
            ],
            related: ips.iter().map(|e| e.value.clone()).collect(),
        });
    }

    // ── Infrastructure footprint (informational) ────────────────────────────
    let infra = get("domain").len() + get("url").len() + get("asn").len();
    if infra > 0 {
        findings.push(Finding {
            id: "EXP-INFRA-001",
            severity: Severity::Info,
            title: format!("{infra} infrastructure artefact(s) mapped"),
            detail: "Domains/URLs/ASNs associated with you are catalogued. Usually low-harm \
                     for an individual, but worth reviewing for unintended personal linkage."
                .to_string(),
            remediation: vec![
                "Use WHOIS privacy on personal domains.".to_string(),
                "Check that personal and professional infrastructure aren't cross-linked."
                    .to_string(),
            ],
            related: get("domain")
                .iter()
                .chain(get("url").iter())
                .chain(get("asn").iter())
                .map(|e| e.value.clone())
                .collect(),
        });
    }

    // Most-severe first; stable within a severity by id for deterministic output.
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.id.cmp(b.id)));

    let exposure_score = score(&findings);
    ExposureReport {
        exposure_score,
        grade: grade_for(exposure_score),
        entity_counts,
        findings,
    }
}

/// Roll findings into a 0–100 exposure score (higher = more exposed).
fn score(findings: &[Finding]) -> u32 {
    let raw: u32 = findings.iter().map(|f| f.severity.weight()).sum();
    raw.min(100)
}

fn grade_for(score: u32) -> char {
    match score {
        0..=9 => 'A',
        10..=24 => 'B',
        25..=44 => 'C',
        45..=69 => 'D',
        _ => 'F',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, Evidence};

    fn ent(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 0.9, "scan-test")
    }

    #[test]
    fn empty_input_is_grade_a() {
        let r = assess(&[]);
        assert_eq!(r.exposure_score, 0);
        assert_eq!(r.grade, 'A');
        assert!(r.findings.is_empty());
    }

    #[test]
    fn credential_triggers_critical() {
        let r = assess(&[ent(EntityKind::ApiKey, "AKIA_example")]);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_eq!(r.findings[0].id, "EXP-CRED-001");
        assert_eq!(r.exposure_score, 45);
        assert_eq!(r.grade, 'D');
    }

    #[test]
    fn breached_email_is_high_plain_email_is_medium() {
        let mut breached = ent(EntityKind::Email, "me@example.com");
        breached.add_evidence(Evidence::new("hibp", "found in 3 breaches"));
        let plain = ent(EntityKind::Email, "other@example.com");

        let r = assess(&[breached, plain]);
        let high = r.findings.iter().find(|f| f.id == "EXP-MAIL-001").unwrap();
        let med = r.findings.iter().find(|f| f.id == "EXP-MAIL-002").unwrap();
        assert_eq!(high.severity, Severity::High);
        assert_eq!(med.severity, Severity::Medium);
    }

    #[test]
    fn breach_detected_via_tag() {
        let mut e = ent(EntityKind::Email, "tagme@example.com");
        e.tags.push("au:breach".to_string());
        let r = assess(&[e]);
        assert!(r.findings.iter().any(|f| f.id == "EXP-MAIL-001"));
        assert!(!r.findings.iter().any(|f| f.id == "EXP-MAIL-002"));
    }

    #[test]
    fn location_signals_are_high() {
        let r = assess(&[
            ent(EntityKind::Address, "1 Test St, Nowhere"),
            ent(EntityKind::Coordinates, "0.0,0.0"),
        ]);
        let geo = r.findings.iter().find(|f| f.id == "EXP-GEO-001").unwrap();
        assert_eq!(geo.severity, Severity::High);
        assert_eq!(geo.related.len(), 2);
    }

    #[test]
    fn three_usernames_escalate_to_correlation_finding() {
        let r = assess(&[
            ent(EntityKind::Username, "alpha"),
            ent(EntityKind::Username, "beta"),
            ent(EntityKind::Username, "gamma"),
        ]);
        assert!(r.findings.iter().any(|f| f.id == "EXP-USER-001"));
        assert!(!r.findings.iter().any(|f| f.id == "EXP-USER-002"));
    }

    #[test]
    fn one_username_is_low_only() {
        let r = assess(&[ent(EntityKind::Username, "solo")]);
        assert!(r.findings.iter().any(|f| f.id == "EXP-USER-002"));
        assert!(!r.findings.iter().any(|f| f.id == "EXP-USER-001"));
    }

    #[test]
    fn findings_sorted_most_severe_first() {
        let mut breached = ent(EntityKind::Email, "me@example.com");
        breached.add_evidence(Evidence::new("stealer", "stealer log hit"));
        let r = assess(&[
            ent(EntityKind::ApiKey, "key"),
            ent(EntityKind::IpAddress, "1.2.3.4"),
            breached,
        ]);
        // Critical must come before High which must come before Low.
        let sevs: Vec<Severity> = r.findings.iter().map(|f| f.severity).collect();
        let mut sorted = sevs.clone();
        sorted.sort();
        assert_eq!(sevs, sorted);
        assert_eq!(r.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn score_is_clamped_to_100() {
        // Many high-weight findings should still cap at 100.
        let mut breached = ent(EntityKind::Email, "me@example.com");
        breached.add_evidence(Evidence::new("breach", "x"));
        let r = assess(&[
            ent(EntityKind::ApiKey, "k1"),
            ent(EntityKind::Credential, "c1"),
            breached,
            ent(EntityKind::Address, "addr"),
            ent(EntityKind::Coordinates, "1,1"),
            ent(EntityKind::Phone, "+61400000000"),
            // Three usernames push the raw total past 100 so we exercise the clamp.
            ent(EntityKind::Username, "alpha"),
            ent(EntityKind::Username, "beta"),
            ent(EntityKind::Username, "gamma"),
        ]);
        assert_eq!(r.exposure_score, 100);
        assert_eq!(r.grade, 'F');
    }

    #[test]
    fn entity_counts_are_tallied() {
        let r = assess(&[
            ent(EntityKind::Email, "a@example.com"),
            ent(EntityKind::Email, "b@example.com"),
            ent(EntityKind::Phone, "+61400000000"),
        ]);
        assert_eq!(r.entity_counts.get("email"), Some(&2));
        assert_eq!(r.entity_counts.get("phone"), Some(&1));
    }

    #[test]
    fn redaction_masks_but_keeps_recognisable_ends() {
        let red = redact_value(&EntityKind::Email, "jordan@hotmail.com");
        assert!(red.contains('@'));
        assert!(red.starts_with('j'));
        assert!(red.contains('*'));
        assert!(!red.contains("ordan"));
    }

    #[test]
    fn redaction_drops_location_entirely() {
        assert_eq!(
            redact_value(&EntityKind::Coordinates, "-27.47,153.02"),
            "<coordinates redacted>"
        );
        assert_eq!(
            redact_value(&EntityKind::Address, "1 Test St"),
            "<address redacted>"
        );
    }

    #[test]
    fn short_values_fully_masked() {
        assert_eq!(mask_keep_ends("ab"), "**");
        assert_eq!(mask_keep_ends("a"), "*");
        assert_eq!(mask_keep_ends(""), "");
    }
}
