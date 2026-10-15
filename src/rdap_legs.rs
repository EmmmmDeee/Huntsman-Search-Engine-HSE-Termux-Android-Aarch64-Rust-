//! The RDAP leg of the domain, IP, netblock and AS front-ends: a registration record as
//! entities, as Spiderfoot's `sfp_whois` reports a WHOIS record.
//!
//! The record's subject (the domain, the address or block whose network it is, or the AS number)
//! carries one evidence
//! record with everything the registry published: the record as published under `whois`
//! (Spiderfoot's `DOMAIN_WHOIS` or `NETBLOCK_WHOIS`), the registrar under `registrar`
//! (`DOMAIN_REGISTRAR`), every event date, status, name server and network block, and each
//! contact's handle, name, organisation, kind, address, telephone and email under
//! `<role>_<field>`, as published, a privacy placeholder included. Each name server is a domain,
//! the registrar and each contact organisation an organisation, and each contact email and
//! telephone an entity of its own, all tied to the subject; a registry's privacy placeholder is
//! listed but never becomes an entity.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::canonical::{canonical_domain, canonical_email, canonical_phone};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::http::Transport;
use crate::netblock::Netblock;
use crate::rdap::{self, Answer, Contact, Record, SOURCE};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;

/// The registry's own record of its subject.
const RECORD_CONFIDENCE: f64 = 0.90;
/// A name server, registrar or contact the record names.
const NAMED_CONFIDENCE: f64 = 0.85;

/// The leg's entities and its outcome row.
#[derive(Debug, Default)]
pub struct Leg {
    pub entities: Vec<Entity>,
    pub outcome: Option<SourceExecutionOutcome>,
}

/// The registration of `domain`'s registrable domain, from its TLD's registry.
#[must_use]
pub fn domain<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Leg {
    let registered = crate::domains::registrable_domain(domain).unwrap_or_else(|| domain.into());
    let answer = rdap::lookup_domain(transport, &registered);
    leg(answer, now_unix, |record| {
        let subject = Subject {
            kind: EntityKind::Domain,
            value: &registered,
            parent_attr: "domain",
            scan_id,
        };
        subject.entities(record)
    })
}

/// The registration of the network that holds `ip`, from its regional registry.
#[must_use]
pub fn ip<T: Transport + ?Sized>(transport: &T, ip: &str, scan_id: &str, now_unix: u64) -> Leg {
    let Ok(address) = ip.parse::<IpAddr>() else {
        return Leg::default();
    };
    leg(rdap::lookup_ip(transport, address), now_unix, |record| {
        let subject = Subject {
            kind: EntityKind::IpAddress,
            value: ip,
            parent_attr: "ip",
            scan_id,
        };
        subject.entities(record)
    })
}

/// The registration of `block`: the smallest registered network that holds all of it.
#[must_use]
pub fn netblock<T: Transport + ?Sized>(
    transport: &T,
    block: Netblock,
    scan_id: &str,
    now_unix: u64,
) -> Leg {
    let value = block.to_string();
    leg(
        rdap::lookup_netblock(transport, block),
        now_unix,
        |record| {
            let subject = Subject {
                kind: EntityKind::Netblock,
                value: &value,
                parent_attr: "netblock",
                scan_id,
            };
            subject.entities(record)
        },
    )
}

/// The registration of AS number `asn`, from the registry that assigned it.
#[must_use]
pub fn asn<T: Transport + ?Sized>(transport: &T, asn: u32, scan_id: &str, now_unix: u64) -> Leg {
    let value = format!("AS{asn}");
    leg(rdap::lookup_asn(transport, asn), now_unix, |record| {
        let subject = Subject {
            kind: EntityKind::Asn,
            value: &value,
            parent_attr: "asn",
            scan_id,
        };
        subject.entities(record)
    })
}

fn leg(
    answer: Result<Answer, rdap::Failure>,
    now_unix: u64,
    entities: impl FnOnce(&Record) -> Vec<Entity>,
) -> Leg {
    match answer {
        Ok(Answer::Registered(record)) => {
            let entities = entities(&record);
            let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
                .with_http_status(200)
                .with_detail(format!("record {}", record.url));
            Leg {
                entities,
                outcome: Some(outcome),
            }
        }
        Ok(Answer::NotFound) => Leg {
            entities: Vec::new(),
            outcome: Some(
                SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                    .with_http_status(404)
                    .with_detail("not registered with the registry the IANA bootstrap names"),
            ),
        },
        Ok(Answer::NoService(why)) => Leg {
            entities: Vec::new(),
            outcome: Some(SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                why,
            )),
        },
        Err(failure) => Leg {
            entities: Vec::new(),
            outcome: Some(failure.outcome(now_unix)),
        },
    }
}

/// The entity a record is about, and the attribute that ties another entity to it.
struct Subject<'a> {
    kind: EntityKind,
    value: &'a str,
    parent_attr: &'static str,
    scan_id: &'a str,
}

impl Subject<'_> {
    fn evidence(&self, summary: String) -> Evidence {
        Evidence::new(EvidenceProvenance::for_scan(SOURCE, self.scan_id), summary)
    }

    /// Evidence for an entity the record names, tied to the subject.
    fn named(&self, summary: String) -> Evidence {
        self.evidence(summary)
            .with_attr(self.parent_attr, self.value)
    }

    fn entities(&self, record: &Record) -> Vec<Entity> {
        let mut out = Vec::new();
        push_entity(
            &mut out,
            self.kind.clone(),
            self.value,
            RECORD_CONFIDENCE,
            self.scan_id,
            self.record_evidence(record),
            &[],
        );
        for host in &record.nameservers {
            if let Some(host) = canonical_domain(host) {
                let evidence =
                    self.named(format!("Name server of {} in its registration", self.value));
                push_entity(
                    &mut out,
                    EntityKind::Domain,
                    &host,
                    NAMED_CONFIDENCE,
                    self.scan_id,
                    evidence,
                    &[],
                );
            }
        }
        for contact in &record.contacts {
            self.contact_entities(contact, &mut out);
        }
        // A contact listed under several roles, or a telephone several contacts share, is one
        // entity with an evidence record per contact.
        merge_by_uid(&mut out);
        out
    }

    /// The subject's evidence: the whole record.
    fn record_evidence(&self, record: &Record) -> Evidence {
        let registrar = record
            .with_role("registrar")
            .find_map(|contact| contact.name.clone().or_else(|| contact.org.clone()));
        let registrant = record.with_role("registrant").find_map(organisation);
        let mut summary = format!("Registration of {} (RDAP)", self.value);
        if let Some(registrar) = &registrar {
            let _ = write!(summary, ", registrar {registrar}");
        }
        if !record.cidrs.is_empty() {
            let name = record.name.as_deref().unwrap_or("network");
            let _ = write!(summary, ", {name} {}", record.cidrs.join(" "));
        } else if let (Some(name), Some(_)) = (record.name.as_deref(), record.autnums) {
            let _ = write!(summary, ", {name}");
        }
        if let Some(registrant) = registrant {
            let _ = write!(summary, ", registrant {registrant}");
        }
        for (label, action) in [("registered", "registration"), ("expires", "expiration")] {
            if let Some(date) = record.event(action) {
                let _ = write!(summary, ", {label} {date}");
            }
        }
        let mut evidence = self
            .evidence(summary)
            .with_attr("whois", record.raw.as_str())
            .with_attr("rdap_url", record.url.as_str())
            .with_optional_attrs([
                ("registrar", registrar.as_deref()),
                ("handle", record.handle.as_deref()),
                ("registered_name", record.name.as_deref()),
                ("country", record.country.as_deref()),
                ("start_address", record.start_address.as_deref()),
                ("end_address", record.end_address.as_deref()),
                ("network_type", record.kind.as_deref()),
                ("parent_handle", record.parent_handle.as_deref()),
                ("whois_server", record.port43.as_deref()),
            ]);
        for (action, date) in &record.events {
            evidence = evidence.with_attr(event_key(action), date.as_str());
        }
        for status in &record.status {
            evidence = evidence.with_attr("status", status.as_str());
        }
        for host in &record.nameservers {
            evidence = evidence.with_attr("ns", host.as_str());
        }
        for block in &record.cidrs {
            evidence = evidence.with_attr("prefix", block.as_str());
        }
        if let Some((first, last)) = record.autnums {
            let range = if first == last {
                format!("AS{first}")
            } else {
                format!("AS{first}-AS{last}")
            };
            evidence = evidence.with_attr("autnum_range", range);
        }
        for contact in &record.contacts {
            evidence = contact_attrs(evidence, contact);
        }
        evidence
    }

    /// A contact's organisation, emails and telephones as entities, unless a placeholder.
    fn contact_entities(&self, contact: &Contact, out: &mut Vec<Entity>) {
        let roles = contact.roles.join(", ");
        let registrar = contact.has_role("registrar");
        let summary = || {
            format!(
                "{} contact ({roles}) in the registration of {}",
                label(contact),
                self.value
            )
        };
        let evidence = || {
            self.named(summary())
                .with_attr("role", roles.as_str())
                .with_optional_attrs([("iana_id", contact.iana_id.as_deref())])
        };
        if let Some(org) = organisation(contact) {
            let tags: &[&str] = if registrar { &[tags::REGISTRAR] } else { &[] };
            push_entity(
                out,
                EntityKind::Organisation,
                org,
                NAMED_CONFIDENCE,
                self.scan_id,
                evidence(),
                tags,
            );
        }
        let tag: &[&str] = if contact.has_role("abuse") {
            &[tags::ABUSE_CONTACT]
        } else {
            &[tags::WHOIS_CONTACT]
        };
        for email in contact
            .emails
            .iter()
            .filter(|email| !rdap::is_redacted(email))
        {
            if let Some(email) = canonical_email(email) {
                push_entity(
                    out,
                    EntityKind::Email,
                    &email,
                    NAMED_CONFIDENCE,
                    self.scan_id,
                    evidence(),
                    tag,
                );
            }
        }
        for phone in &contact.phones {
            if let Some(phone) = canonical_phone(&phone.replace('.', "")) {
                push_entity(
                    out,
                    EntityKind::Phone,
                    &phone,
                    NAMED_CONFIDENCE,
                    self.scan_id,
                    evidence(),
                    tag,
                );
            }
        }
    }
}

/// `last changed` becomes `last_changed`; `registration` stays. **Pure.**
fn event_key(action: &str) -> String {
    action
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

/// The organisation a contact names: a registrar's name, otherwise its `org`, or its name when
/// the contact is an organisation; never a privacy placeholder or an RPSL handle such as
/// `ORG-NCC1-RIPE`, which RIPE and APNIC publish as `org`. **Pure.**
fn organisation(contact: &Contact) -> Option<&str> {
    let named = if contact.has_role("registrar") {
        contact.name.as_deref().or(contact.org.as_deref())
    } else {
        contact.org.as_deref().or_else(|| {
            (contact.kind.as_deref() == Some("org"))
                .then_some(contact.name.as_deref())
                .flatten()
        })
    };
    named.filter(|name| !rdap::is_redacted(name) && !rdap::is_rpsl_handle(name))
}

/// What to call a contact in a summary: its name, organisation or handle.
fn label(contact: &Contact) -> &str {
    contact
        .name
        .as_deref()
        .or(contact.org.as_deref())
        .or(contact.handle.as_deref())
        .unwrap_or("Unnamed")
}

/// Every field of `contact` under `<role>_<field>`, once per role, as published. **Pure.**
fn contact_attrs(mut evidence: Evidence, contact: &Contact) -> Evidence {
    for role in &contact.roles {
        let role = event_key(role);
        let key = |field: &str| format!("{role}_{field}");
        for (field, value) in [
            ("handle", contact.handle.as_deref()),
            ("name", contact.name.as_deref()),
            ("org", contact.org.as_deref()),
            ("kind", contact.kind.as_deref()),
            ("address", contact.address.as_deref()),
            ("iana_id", contact.iana_id.as_deref()),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(key(field), value);
            }
        }
        for email in &contact.emails {
            evidence = evidence.with_attr(key("email"), email.as_str());
        }
        for phone in &contact.phones {
            evidence = evidence.with_attr(key("phone"), phone.as_str());
        }
    }
    evidence
}

#[cfg(test)]
mod tests;
