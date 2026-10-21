//! Shared persistence core for lookup front-ends.
//!
//! Lookup-specific save modules provide only provenance mapping and the
//! "does not show" boundary. Chain construction, the complete record each claim
//! carries, evidence levels, ledger append order, and atomic persistence live
//! here once.

use std::path::Path;

use serde::Serialize;

use crate::entity::{Entity, EntityKind, Evidence};
use crate::error::Error;
use crate::ledger::{self, Claim, LedgerEntry};
use crate::source_outcome::SourceExecutionOutcome;
use crate::stage::{EvidenceLevel, Status};

pub type ProvenanceFn = for<'a> fn(&'a str) -> (&'a str, &'static str);

#[derive(Clone, Copy)]
pub struct SavePolicy {
    pub default_source: &'static str,
    pub does_not_show: &'static str,
    pub outcome_provenance: ProvenanceFn,
    pub entity_provenance: ProvenanceFn,
}

fn email_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "gravatar" => ("gravatar", "src/gravatar.rs"),
        "duolingo" => ("duolingo", "src/duolingo.rs"),
        "openpgp_keys" => ("openpgp_keys", "src/openpgp_keys.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/email_cli.rs")),
    }
}

fn username_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "github_user" => ("github_user", "src/github_user.rs"),
        "bluesky_user" => ("bluesky_user", "src/bluesky_user.rs"),
        _ => (source, "src/username_cli.rs"),
    }
}

fn phone_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "phone_intl" => ("phone_intl", "src/phone_intl.rs"),
        "phone_au" => ("phone_au", "src/phone_cli.rs"),
        "numverify" => ("numverify", "src/numverify.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/phone_cli.rs")),
    }
}

pub const EMAIL_POLICY: SavePolicy = SavePolicy {
    default_source: "email_parse",
    does_not_show: "an email-derived lead is not an identity-resolution verdict",
    outcome_provenance: email_provenance,
    entity_provenance: email_provenance,
};

pub const USERNAME_POLICY: SavePolicy = SavePolicy {
    default_source: "username_variants",
    does_not_show: "a public username-profile lead is not an identity-resolution verdict",
    outcome_provenance: username_provenance,
    entity_provenance: username_provenance,
};

fn people_outcome_provenance(label: &str) -> (&str, &'static str) {
    match label.split('.').next().unwrap_or(label) {
        "asic_director" => ("asic_director", "src/asic_director.rs"),
        _ => ("asic_persons", "src/asic_persons.rs"),
    }
}

fn people_entity_provenance(label: &str) -> (&str, &'static str) {
    let (_, component) = people_outcome_provenance(label);
    (label, component)
}

pub const PEOPLE_POLICY: SavePolicy = SavePolicy {
    default_source: "asic_persons",
    does_not_show: "a register row is not identity resolution or an ATT&CK score",
    outcome_provenance: people_outcome_provenance,
    entity_provenance: people_entity_provenance,
};

pub const PHONE_POLICY: SavePolicy = SavePolicy {
    default_source: "phone_intl",
    does_not_show: "a phone-format or numbering-plan classification is not an identity-resolution verdict",
    outcome_provenance: phone_provenance,
    entity_provenance: phone_provenance,
};

fn exposure_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "hibp_account" => ("hibp_account", "src/exposure_cli.rs"),
        "stolen_tax" => ("stolen_tax", "src/stolen_tax.rs"),
        "oathnet" => ("oathnet", "src/oathnet.rs"),
        _ => (source, "src/exposure_cli.rs"),
    }
}

pub const EXPOSURE_POLICY: SavePolicy = SavePolicy {
    default_source: "hibp_account",
    does_not_show: "a breach exposure record is not an identity-resolution verdict",
    outcome_provenance: exposure_provenance,
    entity_provenance: exposure_provenance,
};

/// The exposure legs' provenance for a source they own, else `other`'s: the rule for a lookup
/// that ran exposure alongside, so each saved claim still names the module that made it.
fn with_exposure<'a>(
    source: &'a str,
    other: fn(&'a str) -> (&'a str, &'static str),
) -> (&'a str, &'static str) {
    match source {
        "hibp_account" | "stolen_tax" | "oathnet" => exposure_provenance(source),
        _ => other(source),
    }
}

fn email_exposure_provenance(source: &str) -> (&str, &'static str) {
    with_exposure(source, email_provenance)
}

fn username_exposure_provenance(source: &str) -> (&str, &'static str) {
    with_exposure(source, username_provenance)
}

/// An email lookup that also ran the keyed exposure legs.
pub const EMAIL_EXPOSURE_POLICY: SavePolicy = SavePolicy {
    default_source: "email_parse",
    does_not_show: "an email-derived or breach exposure lead is not an identity-resolution verdict",
    outcome_provenance: email_exposure_provenance,
    entity_provenance: email_exposure_provenance,
};

/// A username lookup that also ran the keyed exposure legs.
pub const USERNAME_EXPOSURE_POLICY: SavePolicy = SavePolicy {
    default_source: "username_variants",
    does_not_show: "a public username-profile or breach exposure lead is not an identity-resolution verdict",
    outcome_provenance: username_exposure_provenance,
    entity_provenance: username_exposure_provenance,
};

fn domain_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "crtsh" => ("crtsh", "src/crtsh.rs"),
        "certspotter" => ("certspotter", "src/certspotter.rs"),
        "dns" => ("dns", "src/dns.rs"),
        "virustotal" => ("virustotal", "src/virustotal.rs"),
        "hunter" => ("hunter", "src/hunter.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/domain_cli.rs")),
    }
}

pub const DOMAIN_POLICY: SavePolicy = SavePolicy {
    default_source: "crtsh",
    does_not_show: "a domain-recon lead is not an identity-resolution verdict",
    outcome_provenance: domain_provenance,
    entity_provenance: domain_provenance,
};

fn ip_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "internetdb" => ("internetdb", "src/internetdb.rs"),
        "ripestat" => ("ripestat", "src/ripestat.rs"),
        "greynoise" => ("greynoise", "src/greynoise.rs"),
        "abuseipdb" => ("abuseipdb", "src/abuseipdb.rs"),
        "virustotal" => ("virustotal", "src/virustotal.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/ip_cli.rs")),
    }
}

/// The provider module of an indicator source, for every policy whose lookup runs them.
fn indicator_provenance(source: &str) -> Option<(&str, &'static str)> {
    Some(match source {
        "shodan" => ("shodan", "src/shodan.rs"),
        "pulsedive" => ("pulsedive", "src/pulsedive.rs"),
        "leakix" => ("leakix", "src/leakix.rs"),
        "threatfox" => ("threatfox", "src/threatfox.rs"),
        "ipqs" => ("ipqs", "src/ipqs.rs"),
        "whoxy" => ("whoxy", "src/whoxy.rs"),
        "netlas" => ("netlas", "src/netlas.rs"),
        "securitytrails" => ("securitytrails", "src/securitytrails.rs"),
        "urlhaus" => ("urlhaus", "src/urlhaus.rs"),
        "hunter" => ("hunter", "src/hunter.rs"),
        "otx" => ("otx", "src/otx.rs"),
        "urlscan" => ("urlscan", "src/urlscan.rs"),
        "ipinfo" => ("ipinfo", "src/ipinfo.rs"),
        "kickbox" => ("kickbox", "src/kickbox.rs"),
        "robtex" => ("robtex", "src/robtex.rs"),
        "hackertarget" => ("hackertarget", "src/hackertarget.rs"),
        "stopforumspam" => ("stopforumspam", "src/stopforumspam.rs"),
        "isc" => ("isc", "src/isc.rs"),
        "maltiverse" => ("maltiverse", "src/maltiverse.rs"),
        "phishstats" => ("phishstats", "src/phishstats.rs"),
        "xposed_or_not" => ("xposed_or_not", "src/xposedornot.rs"),
        "rdap" => ("rdap", "src/rdap.rs"),
        "mnemonic" => ("mnemonic", "src/mnemonic.rs"),
        "dnsresolve" => ("dnsresolve", "src/dns.rs"),
        list @ ("spamhaus" | "spamcop" | "uceprotect" | "dronebl" | "sorbs" | "surbl") => {
            (list, "src/dnsbl.rs")
        }
        filter @ ("adguard_dns" | "cleanbrowsing" | "cloudflaredns" | "comodo"
        | "dns_for_family" | "opendns" | "quad9" | "yandexdns") => (filter, "src/dns_filter.rs"),
        feed @ ("abusech" | "alienvaultiprep" | "blocklistde" | "botvrij" | "cinsscore"
        | "cleantalk" | "coinblocker" | "cybercrimetracker" | "emergingthreats"
        | "greensnow" | "openphish" | "phishtank" | "stevenblack_hosts" | "torexits"
        | "voipbl" | "vxvault") => (feed, "src/threat_feeds.rs"),
        _ => return None,
    })
}

pub const IP_POLICY: SavePolicy = SavePolicy {
    default_source: "internetdb",
    does_not_show: "an address-reputation lead is not an identity-resolution verdict",
    outcome_provenance: ip_provenance,
    entity_provenance: ip_provenance,
};

fn netblock_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "ripestat" => ("ripestat", "src/ripestat.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/netblock_cli.rs")),
    }
}

pub const NETBLOCK_POLICY: SavePolicy = SavePolicy {
    default_source: "rdap",
    does_not_show: "an address-block lead is not an identity-resolution verdict",
    outcome_provenance: netblock_provenance,
    entity_provenance: netblock_provenance,
};

fn asn_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "ripestat" => ("ripestat", "src/ripestat.rs"),
        other => indicator_provenance(other).unwrap_or((source, "src/asn_cli.rs")),
    }
}

pub const ASN_POLICY: SavePolicy = SavePolicy {
    default_source: "ripestat",
    does_not_show: "an autonomous-system lead is not an identity-resolution verdict",
    outcome_provenance: asn_provenance,
    entity_provenance: asn_provenance,
};

fn network_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "wigle" => ("wigle", "src/wigle.rs"),
        "wigle_bluetooth" => ("wigle_bluetooth", "src/wigle.rs"),
        "oui" => ("oui", "src/oui.rs"),
        _ => (source, "src/network_cli.rs"),
    }
}

pub const NETWORK_POLICY: SavePolicy = SavePolicy {
    default_source: "wigle",
    does_not_show: "a WiFi network record is not an identity-resolution verdict or a device's current location",
    outcome_provenance: network_provenance,
    entity_provenance: network_provenance,
};

fn crypto_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "blockchain" => ("blockchain", "src/blockchain.rs"),
        _ => (source, "src/crypto_cli.rs"),
    }
}

pub const CRYPTO_POLICY: SavePolicy = SavePolicy {
    default_source: "blockchain",
    does_not_show: "an on-chain balance is not an identity-resolution verdict or proof of ownership",
    outcome_provenance: crypto_provenance,
    entity_provenance: crypto_provenance,
};

/// Persist one lookup report as a fresh unverified hash chain.
///
/// # Errors
/// Refuses an empty report and propagates bounded atomic ledger-write failures.
pub fn save(
    path: &Path,
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
    policy: SavePolicy,
) -> Result<Vec<LedgerEntry>, Error> {
    let entries = chain(entities, outcomes, policy)?;
    ledger::save_chain(path, &entries)?;
    Ok(entries)
}

/// Build the ledger entries without performing I/O.
///
/// The entries follow the order a report prints in: each source outcome, then each entity, then
/// every evidence record behind that entity. Each claim is the whole record it names, serialised as
/// JSON, so no field of an outcome, an entity or an evidence record is left out, and every attribute
/// of an evidence record is kept. Each claim names the module that made its record, so a record
/// never takes another record's provenance.
///
/// # Errors
/// Refuses an empty report so a skipped lookup cannot be persisted as if it ran, and refuses a
/// record that cannot be serialised rather than saving part of it.
pub fn chain(
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
    policy: SavePolicy,
) -> Result<Vec<LedgerEntry>, Error> {
    if entities.is_empty() && outcomes.is_empty() {
        return Err(Error::Invalid("nothing to save".into()));
    }

    let mut claims = Vec::new();
    for outcome in outcomes {
        claims.push(outcome_claim(outcome, policy)?);
    }
    for entity in entities {
        claims.push(entity_claim(entity, policy)?);
        for evidence in &entity.evidence {
            claims.push(evidence_claim(entity, evidence, policy)?);
        }
    }

    let mut previous = ledger::GENESIS.to_owned();
    let mut entries = Vec::with_capacity(claims.len());
    for claim in &claims {
        let entry = ledger::append(&previous, claim);
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    Ok(entries)
}

/// One record as JSON. A record that will not serialise is refused, never saved in part.
fn record_text<T: Serialize + ?Sized>(record: &T, what: &str) -> Result<String, Error> {
    serde_json::to_string(record)
        .map_err(|err| Error::Invalid(format!("{what} cannot be saved: {err}")))
}

/// The module a record names: its own source, or the policy's default when it names none.
fn record_source<'a>(source: &'a str, default: &'a str) -> &'a str {
    if source.is_empty() { default } else { source }
}

fn outcome_claim(outcome: &SourceExecutionOutcome, policy: SavePolicy) -> Result<Claim, Error> {
    let (source, component) = (policy.outcome_provenance)(&outcome.module);
    Ok(Claim {
        claim: record_text(outcome, "a source outcome")?,
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: if outcome.kind.is_accepted() {
            EvidenceLevel::PrimaryEvidence
        } else {
            EvidenceLevel::Assertion
        },
        does_not_show: policy.does_not_show.into(),
    })
}

fn entity_claim(entity: &Entity, policy: SavePolicy) -> Result<Claim, Error> {
    let observed = entity
        .evidence
        .first()
        .map_or("", |evidence| evidence.provenance.source.as_str());
    let (source, component) =
        (policy.entity_provenance)(record_source(observed, policy.default_source));
    Ok(Claim {
        claim: entity_text(entity)?,
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: EvidenceLevel::PrimaryEvidence,
        does_not_show: policy.does_not_show.into(),
    })
}

/// The entity's own fields as JSON. Its evidence records follow as claims of their own, so they are
/// left out here rather than saved twice.
fn entity_text(entity: &Entity) -> Result<String, Error> {
    let mut fields = serde_json::to_value(entity)
        .map_err(|err| Error::Invalid(format!("an entity cannot be saved: {err}")))?;
    let Some(object) = fields.as_object_mut() else {
        return Err(Error::Invalid(
            "an entity cannot be saved: it is not a record".into(),
        ));
    };
    object.remove("evidence");
    Ok(fields.to_string())
}

/// One evidence record with the entity it belongs to, so its claim reads on its own.
#[derive(Serialize)]
struct EvidenceRecord<'a> {
    entity_uid: &'a str,
    kind: &'a EntityKind,
    raw_value: &'a str,
    evidence: &'a Evidence,
}

fn evidence_claim(
    entity: &Entity,
    evidence: &Evidence,
    policy: SavePolicy,
) -> Result<Claim, Error> {
    let (source, component) = (policy.entity_provenance)(record_source(
        &evidence.provenance.source,
        policy.default_source,
    ));
    let record = EvidenceRecord {
        entity_uid: &entity.uid,
        kind: &entity.kind,
        raw_value: &entity.raw_value,
        evidence,
    };
    Ok(Claim {
        claim: record_text(&record, "an evidence record")?,
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: if evidence.is_inferred {
            EvidenceLevel::Assertion
        } else {
            EvidenceLevel::PrimaryEvidence
        },
        does_not_show: policy.does_not_show.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::VerificationMethod;
    use crate::entity::EvidenceProvenance;
    use crate::source_outcome::SourceOutcomeKind;

    fn provenance(source: &str) -> (&str, &'static str) {
        (source, "test")
    }

    /// `beta` is its own module; every other source is `alpha`'s, so a test can tell which module
    /// each record names.
    fn named(source: &str) -> (&str, &'static str) {
        match source {
            "beta" => ("beta", "src/beta.rs"),
            _ => ("alpha", "src/alpha.rs"),
        }
    }

    const POLICY: SavePolicy = SavePolicy {
        default_source: "fallback",
        does_not_show: "not independently verified",
        outcome_provenance: provenance,
        entity_provenance: provenance,
    };

    const NAMED: SavePolicy = SavePolicy {
        default_source: "fallback",
        does_not_show: "not independently verified",
        outcome_provenance: named,
        entity_provenance: named,
    };

    fn scanned(source: &str, summary: &str) -> Evidence {
        Evidence::new(EvidenceProvenance::for_scan(source, "scan"), summary)
    }

    fn entity_with(evidence: impl IntoIterator<Item = Evidence>) -> Entity {
        let mut entity = Entity::new(EntityKind::Email, "a@example.com", 0.9, "scan");
        for item in evidence {
            entity.add_evidence(item);
        }
        entity
    }

    fn claim_json(entry: &LedgerEntry) -> serde_json::Value {
        serde_json::from_str(&entry.claim.claim).unwrap()
    }

    #[test]
    fn empty_report_is_refused() {
        assert!(matches!(
            chain(&[], &[], POLICY),
            Err(Error::Invalid(message)) if message == "nothing to save"
        ));
    }

    #[test]
    fn outcomes_precede_entities_and_failure_is_assertion() {
        let entity = entity_with([scanned("source", "fixture")]);
        let mut outcome = SourceExecutionOutcome::success("source", 1, 0);
        outcome.kind = SourceOutcomeKind::RateLimited;
        outcome.found = None;

        let entries = chain(&[entity], &[outcome], POLICY).unwrap();
        assert_eq!(
            entries.len(),
            3,
            "one outcome, one entity, one evidence record"
        );
        assert_eq!(entries[0].claim.evidence_level, EvidenceLevel::Assertion);
        let outcome_record = claim_json(&entries[0]);
        assert_eq!(outcome_record["module"], "source");
        assert_eq!(outcome_record["kind"], "rate_limited");
        assert!(outcome_record["found"].is_null());
        assert_eq!(claim_json(&entries[1])["kind"], "email");
        assert_eq!(entries[1].claim.source, "source");
        assert_eq!(entries[2].claim.source, "source");
        assert!(
            entries
                .iter()
                .all(|entry| entry.claim.status == Status::Unverified)
        );
    }

    #[test]
    fn every_evidence_record_is_saved_with_the_module_that_made_it() {
        let entity = entity_with([scanned("alpha", "first"), scanned("beta", "second")]);
        let entries = chain(&[entity], &[], NAMED).unwrap();
        assert_eq!(entries.len(), 3, "the entity, then each of its two records");
        assert_eq!(entries[1].claim.source, "alpha");
        assert_eq!(entries[1].claim.component, "src/alpha.rs");
        assert_eq!(entries[2].claim.source, "beta");
        assert_eq!(entries[2].claim.component, "src/beta.rs");
        assert_eq!(claim_json(&entries[2])["evidence"]["summary"], "second");
    }

    #[test]
    fn an_evidence_record_round_trips_with_every_attribute() {
        let entity = entity_with([scanned("alpha", "breach \"quoted\"\nline")
            .with_attr("name", "Ada Example")
            .with_attr("note", "tab\tand \u{1b}[31m escape")
            .with_verification(VerificationMethod::EmailLinked)]);
        let entries = chain(std::slice::from_ref(&entity), &[], POLICY).unwrap();
        let record = claim_json(&entries[1]);
        let restored: Evidence = serde_json::from_value(record["evidence"].clone()).unwrap();
        assert_eq!(restored, entity.evidence[0]);
        assert_eq!(record["entity_uid"], entity.uid.as_str());
    }

    #[test]
    fn an_entity_keeps_its_own_fields_and_no_evidence_is_saved_twice() {
        let mut entity = entity_with([scanned("alpha", "one"), scanned("alpha", "two")]);
        entity.tags = vec!["breach".into()];
        let entries = chain(std::slice::from_ref(&entity), &[], POLICY).unwrap();
        assert_eq!(entries.len(), 3);
        let record = claim_json(&entries[0]);
        assert_eq!(record["uid"], entity.uid.as_str());
        assert_eq!(record["raw_value"], "a@example.com");
        assert_eq!(record["tags"][0], "breach");
        assert_eq!(record["confidence"], 0.9);
        assert!(record.get("evidence").is_none());
    }

    #[test]
    fn inferred_evidence_is_an_assertion_and_direct_evidence_is_primary() {
        let entity = entity_with([
            scanned("alpha", "direct"),
            scanned("alpha", "derived").inferred(),
        ]);
        let entries = chain(&[entity], &[], POLICY).unwrap();
        assert_eq!(
            entries[1].claim.evidence_level,
            EvidenceLevel::PrimaryEvidence
        );
        assert_eq!(entries[2].claim.evidence_level, EvidenceLevel::Assertion);
    }

    #[test]
    fn a_record_that_names_no_source_takes_the_policy_default() {
        let entity = entity_with([scanned("", "anonymous")]);
        let entries = chain(&[entity], &[], POLICY).unwrap();
        assert_eq!(entries[0].claim.source, "fallback");
        assert_eq!(entries[1].claim.source, "fallback");
    }

    #[test]
    fn a_saved_report_loads_back_and_its_chain_is_intact() {
        let dir = std::env::temp_dir().join(format!("huntsman-lookup-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        let entity = entity_with([
            scanned("alpha", "one").with_attr("name", "Ada"),
            scanned("beta", "two"),
        ]);
        let outcome = SourceExecutionOutcome::success("alpha", 1, 2);
        let saved = save(&path, &[entity], &[outcome], NAMED).unwrap();
        let loaded = ledger::load_chain(&path);
        let _ = std::fs::remove_dir_all(&dir);
        let loaded = loaded.unwrap();
        assert_eq!(
            saved.len(),
            4,
            "one outcome, one entity, two evidence records"
        );
        assert_eq!(loaded, saved);
        assert!(ledger::chain_intact(&loaded));
    }

    #[test]
    fn every_outcome_kind_is_saved_under_its_wire_label() {
        let labels = [
            SourceOutcomeKind::Success,
            SourceOutcomeKind::ValidZero,
            SourceOutcomeKind::AuthRequired,
            SourceOutcomeKind::NotConfigured,
            SourceOutcomeKind::AuthRejected,
            SourceOutcomeKind::EntitlementDenied,
            SourceOutcomeKind::QuotaExhausted,
            SourceOutcomeKind::RateLimited,
            SourceOutcomeKind::BotWaf,
            SourceOutcomeKind::DnsFailure,
            SourceOutcomeKind::ConnectFailure,
            SourceOutcomeKind::TlsFailure,
            SourceOutcomeKind::TtfbTimeout,
            SourceOutcomeKind::BodyTimeout,
            SourceOutcomeKind::Upstream4xx,
            SourceOutcomeKind::Upstream5xx,
            SourceOutcomeKind::RedirectChanged,
            SourceOutcomeKind::ProtocolDrift,
            SourceOutcomeKind::InteractionDrift,
            SourceOutcomeKind::SchemaDrift,
            SourceOutcomeKind::ParserDrift,
            SourceOutcomeKind::SemanticDrift,
            SourceOutcomeKind::ZeroYieldAnomaly,
            SourceOutcomeKind::ConfirmedDead,
            SourceOutcomeKind::Inconclusive,
        ]
        .map(|kind| serde_json::to_value(kind).unwrap());
        assert_eq!(
            labels,
            [
                "success",
                "valid_zero",
                "auth_required",
                "not_configured",
                "auth_rejected",
                "entitlement_denied",
                "quota_exhausted",
                "rate_limited",
                "bot_waf",
                "dns_failure",
                "connect_failure",
                "tls_failure",
                "ttfb_timeout",
                "body_timeout",
                "upstream4xx",
                "upstream5xx",
                "redirect_changed",
                "protocol_drift",
                "interaction_drift",
                "schema_drift",
                "parser_drift",
                "semantic_drift",
                "zero_yield_anomaly",
                "confirmed_dead",
                "inconclusive",
            ]
        );
    }
}
