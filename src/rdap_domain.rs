//! Structured, keyless RDAP domain lookup.
//!
//! The active reconstruction intentionally surfaces only public registration metadata
//! useful for infrastructure pivots. Contact vCards and other potential PII are not
//! represented in the public output type.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

const RDAP_DOMAIN_BASE: &str = "https://rdap.org/domain/";
const MAX_REDIRECTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdapDomainRecord {
    pub domain: String,
    pub handle: Option<String>,
    pub statuses: Vec<String>,
    pub events: BTreeMap<String, String>,
    pub nameservers: Vec<String>,
    pub dnssec_signed: Option<bool>,
    pub registrar_iana_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RdapLookup {
    pub outcome: SourceExecutionOutcome,
    pub record: Option<RdapDomainRecord>,
}

#[derive(Debug, Deserialize)]
struct WireRecord {
    #[serde(default, rename = "ldhName")]
    ldh_name: Option<String>,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    events: Vec<WireEvent>,
    #[serde(default)]
    nameservers: Vec<WireNameserver>,
    #[serde(default, rename = "secureDNS")]
    secure_dns: Option<WireSecureDns>,
    #[serde(default)]
    entities: Vec<WireEntity>,
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    #[serde(default, rename = "eventAction")]
    action: Option<String>,
    #[serde(default, rename = "eventDate")]
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireNameserver {
    #[serde(default, rename = "ldhName")]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireSecureDns {
    #[serde(default, rename = "delegationSigned")]
    delegation_signed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WireEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "publicIds")]
    public_ids: Vec<WirePublicId>,
}

#[derive(Debug, Deserialize)]
struct WirePublicId {
    #[serde(default, rename = "type")]
    id_type: Option<String>,
    #[serde(default)]
    identifier: Option<String>,
}

/// Perform one RDAP lookup. Redirects are permitted because `rdap.org` is a
/// bootstrap redirector; no credential is attached to the request.
pub fn lookup_domain<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    now_unix: u64,
) -> Result<RdapLookup, Error> {
    let domain = normalize_domain(domain)?;
    let fetched = fetch(
        transport,
        Request::get(format!("{RDAP_DOMAIN_BASE}{domain}")),
        None,
        &FetchOptions {
            max_redirects: MAX_REDIRECTS,
        },
        "rdap_domain",
        now_unix,
    )?;
    let outcome = fetched.outcome;

    let record = match fetched.response {
        Some(response)
            if response.status == 200
                && !response.truncated
                && outcome.kind == SourceOutcomeKind::Inconclusive =>
        {
            Some(parse_domain_record(&domain, &response.body)?)
        }
        _ => None,
    };

    Ok(RdapLookup { outcome, record })
}

/// Parse one RDAP response and bind it to the exact requested domain.
pub fn parse_domain_record(domain: &str, body: &[u8]) -> Result<RdapDomainRecord, Error> {
    let domain = normalize_domain(domain)?;
    let wire: WireRecord = serde_json::from_slice(body)
        .map_err(|error| Error::Invalid(format!("invalid RDAP JSON: {error}")))?;

    if let Some(ldh) = wire.ldh_name.as_deref() {
        let stated = normalize_domain(ldh)?;
        if stated != domain {
            return Err(Error::Invalid(format!(
                "RDAP domain mismatch: requested {domain}, response states {stated}"
            )));
        }
    }

    let statuses = wire
        .status
        .iter()
        .map(|status| status.trim().to_ascii_lowercase())
        .filter(|status| !status.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut events = BTreeMap::new();
    for event in &wire.events {
        let (Some(action), Some(date)) = (event.action.as_deref(), event.date.as_deref()) else {
            continue;
        };
        let action = action.trim().to_ascii_lowercase();
        let date = date.trim();
        if !action.is_empty() && !date.is_empty() {
            events.entry(action).or_insert_with(|| date.to_owned());
        }
    }

    let nameservers = wire
        .nameservers
        .iter()
        .filter_map(|nameserver| nameserver.name.as_deref())
        .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(RdapDomainRecord {
        domain,
        handle: clean_optional(wire.handle),
        statuses,
        events,
        nameservers,
        dnssec_signed: wire.secure_dns.and_then(|secure| secure.delegation_signed),
        registrar_iana_id: registrar_iana_id(&wire.entities),
    })
}

fn registrar_iana_id(entities: &[WireEntity]) -> Option<String> {
    entities
        .iter()
        .filter(|entity| {
            entity
                .roles
                .iter()
                .any(|role| role.trim().eq_ignore_ascii_case("registrar"))
        })
        .flat_map(|entity| &entity.public_ids)
        .find(|public_id| {
            public_id.id_type.as_deref().is_some_and(|id_type| {
                id_type
                    .to_ascii_lowercase()
                    .contains("iana registrar")
            })
        })
        .and_then(|public_id| public_id.identifier.clone())
        .and_then(|identifier| clean_optional(Some(identifier)))
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalize_domain(raw: &str) -> Result<String, Error> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return Err(Error::Invalid(format!("invalid domain: {raw}")));
    }
    let labels = domain.split('.').collect::<Vec<_>>();
    let valid = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !valid {
        return Err(Error::Invalid(format!("invalid domain: {raw}")));
    }
    Ok(domain)
}
