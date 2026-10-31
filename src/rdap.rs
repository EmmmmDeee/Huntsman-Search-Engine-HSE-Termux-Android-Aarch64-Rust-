//! Registration data over RDAP (RFC 9082/9083), the registries' JSON successor to WHOIS, as
//! Spiderfoot's `sfp_whois` reads WHOIS: keyless and from the registry itself.
//!
//! The IANA bootstrap registry (RFC 9224, `data.iana.org/rdap/{dns,ipv4,ipv6,asn}.json`) names
//! the RDAP service for a domain's TLD, an address's block or an AS number's range; the record is
//! then `GET {service}domain/{name}`, `{service}ip/{address}` or `{service}autnum/{number}`. The bootstrap is fetched with
//! redirects off; a registry's answer may redirect, as a regional registry refers an address
//! another one holds, and the referral is followed. Everything the record publishes is kept: its
//! body as published, its events, status, name servers, network range and every contact's
//! name, organisation, address, telephone and email, a role at a time. RDAP 404 means the name
//! or address is not registered there: a validated zero, not a failure.

use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport};
use crate::netblock::{Ipv4Cidr, Ipv6Cidr, Netblock};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

/// The module name on outcome rows and evidence; Spiderfoot's `sfp_whois` does its work.
pub const SOURCE: &str = "rdap";
const BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
const BOOTSTRAP_ASN: &str = "https://data.iana.org/rdap/asn.json";
const TIMEOUT: Duration = Duration::from_secs(20);
const RDAP_ACCEPT: &str = "application/rdap+json, application/json";

/// A request that got no usable answer, in the shared outcome taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub kind: SourceOutcomeKind,
    pub http_status: Option<u16>,
    pub detail: String,
    /// The delay a 429 or 503 asked for in `Retry-After`, in seconds.
    pub retry_after_secs: Option<u64>,
}

impl Failure {
    #[must_use]
    pub fn outcome(&self, now_unix: u64) -> SourceExecutionOutcome {
        let outcome = SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            self.kind,
            self.http_status,
            &self.detail,
        );
        match self.retry_after_secs {
            Some(secs) => outcome.with_retry_after(secs),
            None => outcome,
        }
    }
}

/// What the registry said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The registry's record.
    Registered(Box<Record>),
    /// RDAP 404: not registered with the registry at this URL, the hop that answered after any
    /// referral, redacted as fetch reports it.
    NotFound(String),
    /// The bootstrap names no RDAP service for the TLD or block, so there is no registry to ask.
    NoService(String),
}

/// One RDAP object, domain or IP network, with everything it publishes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    /// The URL that answered.
    pub url: String,
    /// The body as the registry published it.
    pub raw: String,
    pub handle: Option<String>,
    /// The domain's `ldhName`, or the network's name.
    pub name: Option<String>,
    pub status: Vec<String>,
    /// `(eventAction, eventDate)`, in record order.
    pub events: Vec<(String, String)>,
    pub nameservers: Vec<String>,
    pub contacts: Vec<Contact>,
    pub country: Option<String>,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    /// The network's blocks in CIDR form.
    pub cidrs: Vec<String>,
    /// An AS number record's range, first and last number.
    pub autnums: Option<(u32, u32)>,
    /// The network's type, such as `ASSIGNED PA` or `DIRECT ALLOCATION`.
    pub kind: Option<String>,
    pub parent_handle: Option<String>,
    /// The WHOIS server the record names (`port43`).
    pub port43: Option<String>,
}

impl Record {
    /// The date of the first event with `action` (`registration`, `expiration`, ...).
    #[must_use]
    pub fn event(&self, action: &str) -> Option<&str> {
        self.events
            .iter()
            .find(|(seen, _)| seen.eq_ignore_ascii_case(action))
            .map(|(_, date)| date.as_str())
    }

    /// The contacts that hold `role`.
    pub fn with_role<'a>(&'a self, role: &'a str) -> impl Iterator<Item = &'a Contact> + 'a {
        self.contacts
            .iter()
            .filter(move |contact| contact.has_role(role))
    }
}

/// One RDAP entity (a registrar, registrant, technical or abuse contact), read from its jCard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Contact {
    pub roles: Vec<String>,
    pub handle: Option<String>,
    /// The jCard's `fn`.
    pub name: Option<String>,
    pub org: Option<String>,
    /// `individual`, `org`, ...
    pub kind: Option<String>,
    pub emails: Vec<String>,
    /// As published, `tel:` stripped.
    pub phones: Vec<String>,
    /// The `adr` label, or its parts joined.
    pub address: Option<String>,
    /// A registrar's IANA id.
    pub iana_id: Option<String>,
}

impl Contact {
    /// Whether the contact holds `role` (`registrar`, `registrant`, `abuse`, ...).
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|seen| seen.eq_ignore_ascii_case(role))
    }
}

#[derive(Debug, Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Default, Deserialize)]
struct Object {
    #[serde(default)]
    handle: Option<String>,
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    events: Vec<Event>,
    #[serde(default)]
    entities: Vec<Entity>,
    #[serde(default)]
    nameservers: Vec<Nameserver>,
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(rename = "startAddress", default)]
    start_address: Option<String>,
    #[serde(rename = "endAddress", default)]
    end_address: Option<String>,
    #[serde(default)]
    cidr0_cidrs: Vec<Cidr0>,
    #[serde(rename = "startAutnum", default)]
    start_autnum: Option<Value>,
    #[serde(rename = "endAutnum", default)]
    end_autnum: Option<Value>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(rename = "parentHandle", default)]
    parent_handle: Option<String>,
    #[serde(default)]
    port43: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Event {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(rename = "eventDate", default)]
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Entity {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(rename = "vcardArray", default)]
    vcard: Option<Value>,
    #[serde(rename = "publicIds", default)]
    public_ids: Vec<PublicId>,
    /// Registries such as ARIN nest contacts (abuse, technical) inside the registrant.
    #[serde(default)]
    entities: Vec<Entity>,
}

#[derive(Debug, Deserialize)]
struct PublicId {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    identifier: String,
}

#[derive(Debug, Deserialize)]
struct Nameserver {
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Cidr0 {
    #[serde(default)]
    v4prefix: Option<String>,
    #[serde(default)]
    v6prefix: Option<String>,
    length: u8,
}

/// Look up `domain`'s registration through its TLD's RDAP service.
///
/// # Errors
/// [`Failure`] when the bootstrap or the registry gave no usable answer.
pub fn lookup_domain<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    now_unix: u64,
) -> Result<Answer, Failure> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let bootstrap = bootstrap(transport, BOOTSTRAP_DNS, now_unix)?;
    let Some(service) = service_for_domain(&bootstrap, &domain) else {
        let tld = domain.rsplit('.').next().unwrap_or(&domain);
        return Ok(Answer::NoService(format!(
            "the IANA bootstrap names no RDAP service for .{tld}"
        )));
    };
    object(transport, &format!("{service}domain/{domain}"), now_unix)
}

/// Look up the registration of the network that holds `ip`, from the registry the bootstrap
/// names for its block.
///
/// # Errors
/// [`Failure`] when the bootstrap or the registry gave no usable answer.
pub fn lookup_ip<T: Transport + ?Sized>(
    transport: &T,
    ip: IpAddr,
    now_unix: u64,
) -> Result<Answer, Failure> {
    network(transport, ip, &ip.to_string(), now_unix)
}

/// Look up the registration of `block`: the smallest registered network that holds all of it
/// (RFC 9082 `ip/{address}/{prefix}`), from the registry the bootstrap names for its first
/// address.
///
/// # Errors
/// [`Failure`] when the bootstrap or the registry gave no usable answer.
pub fn lookup_netblock<T: Transport + ?Sized>(
    transport: &T,
    block: Netblock,
    now_unix: u64,
) -> Result<Answer, Failure> {
    network(transport, block.network(), &block.to_string(), now_unix)
}

/// Look up the registration of AS number `asn`, from the registry the bootstrap names for its
/// range.
///
/// # Errors
/// [`Failure`] when the bootstrap or the registry gave no usable answer.
pub fn lookup_asn<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    now_unix: u64,
) -> Result<Answer, Failure> {
    let bootstrap = bootstrap(transport, BOOTSTRAP_ASN, now_unix)?;
    let Some(service) = service_for_asn(&bootstrap, asn) else {
        return Ok(Answer::NoService(format!(
            "the IANA bootstrap names no RDAP service for AS{asn}"
        )));
    };
    object(transport, &format!("{service}autnum/{asn}"), now_unix)
}

fn network<T: Transport + ?Sized>(
    transport: &T,
    first: IpAddr,
    resource: &str,
    now_unix: u64,
) -> Result<Answer, Failure> {
    let url = if first.is_ipv4() {
        BOOTSTRAP_IPV4
    } else {
        BOOTSTRAP_IPV6
    };
    let bootstrap = bootstrap(transport, url, now_unix)?;
    let Some(service) = service_for_ip(&bootstrap, first) else {
        return Ok(Answer::NoService(format!(
            "the IANA bootstrap names no RDAP service for {resource}"
        )));
    };
    object(transport, &format!("{service}ip/{resource}"), now_unix)
}

/// The service base URL for `domain`: the entry whose TLD is the longest dot-aligned suffix of
/// the name. **Pure.**
fn service_for_domain(bootstrap: &Bootstrap, domain: &str) -> Option<String> {
    let mut best: Option<(&str, &[String])> = None;
    for (tlds, urls) in &bootstrap.services {
        for tld in tlds {
            let tld = tld.trim_matches('.');
            let matches = domain == tld || domain.ends_with(&format!(".{tld}"));
            if matches && best.is_none_or(|(current, _)| tld.len() > current.len()) {
                best = Some((tld, urls));
            }
        }
    }
    best.and_then(|(_, urls)| base_url(urls))
}

/// The service for `ip`: the bootstrap block holding it with the longest prefix. **Pure.**
fn service_for_ip(bootstrap: &Bootstrap, ip: IpAddr) -> Option<String> {
    let mut best: Option<(u8, &[String])> = None;
    for (blocks, urls) in &bootstrap.services {
        for block in blocks {
            let held = match ip {
                IpAddr::V4(v4) => Ipv4Cidr::parse(block)
                    .filter(|cidr| cidr.contains(v4))
                    .map(Ipv4Cidr::prefix_len),
                IpAddr::V6(v6) => Ipv6Cidr::parse(block)
                    .filter(|cidr| cidr.contains(v6))
                    .map(Ipv6Cidr::prefix_len),
            };
            if held.is_some_and(|bits| best.is_none_or(|(current, _)| bits > current)) {
                best = held.map(|bits| (bits, urls.as_slice()));
            }
        }
    }
    best.and_then(|(_, urls)| base_url(urls))
}

/// The service for `asn`: the bootstrap range (`first-last`, or one number) holding it, the
/// narrowest if several do. **Pure.**
fn service_for_asn(bootstrap: &Bootstrap, asn: u32) -> Option<String> {
    let mut best: Option<(u32, &[String])> = None;
    for (ranges, urls) in &bootstrap.services {
        for range in ranges {
            let (first, last) = range
                .split_once('-')
                .unwrap_or((range.as_str(), range.as_str()));
            let (Ok(first), Ok(last)) = (first.trim().parse::<u32>(), last.trim().parse::<u32>())
            else {
                continue;
            };
            let width = last.saturating_sub(first);
            if (first..=last).contains(&asn) && best.is_none_or(|(current, _)| width < current) {
                best = Some((width, urls.as_slice()));
            }
        }
    }
    best.and_then(|(_, urls)| base_url(urls))
}

/// One bootstrap entry's service URL, `https` preferred, with a trailing slash. **Pure.**
fn base_url(urls: &[String]) -> Option<String> {
    let url = urls
        .iter()
        .find(|url| url.starts_with("https://"))
        .or_else(|| urls.first())?;
    Some(if url.ends_with('/') {
        url.clone()
    } else {
        format!("{url}/")
    })
}

fn bootstrap<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    now_unix: u64,
) -> Result<Bootstrap, Failure> {
    let reply = get(
        transport,
        url,
        "application/json",
        &FetchOptions::no_redirects(),
        now_unix,
    )?;
    let response = &reply.response;
    if !(200..300).contains(&response.status) {
        return Err(status_failure(&reply));
    }
    crate::http::parse_json_body(response).map_err(|error| Failure {
        kind: SourceOutcomeKind::SchemaDrift,
        http_status: Some(response.status),
        detail: format!("not an RDAP bootstrap registry: {error}"),
        retry_after_secs: None,
    })
}

fn object<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    now_unix: u64,
) -> Result<Answer, Failure> {
    let reply = get(
        transport,
        url,
        RDAP_ACCEPT,
        &FetchOptions::default(),
        now_unix,
    )?;
    let response = &reply.response;
    if response.status == 404 {
        return Ok(Answer::NotFound(reply.final_url));
    }
    if !(200..300).contains(&response.status) {
        return Err(status_failure(&reply));
    }
    let parsed: Object = crate::http::parse_json_body(response).map_err(|error| Failure {
        kind: SourceOutcomeKind::SchemaDrift,
        http_status: Some(response.status),
        detail: format!("not an RDAP object: {error}"),
        retry_after_secs: None,
    })?;
    // After a referral the record is the last hop's, so it names that URL.
    Ok(Answer::Registered(Box::new(record(
        parsed,
        &reply.final_url,
        response.text(),
    ))))
}

/// A response with what fetch read around it.
struct Reply {
    response: Response,
    /// The URL of the hop that answered, redacted as fetch reports it.
    final_url: String,
    /// How fetch typed the status and body.
    kind: SourceOutcomeKind,
    /// The delay a 429 or 503 asked for, counted from the scan's clock.
    retry_after_secs: Option<u64>,
}

fn get<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    accept: &str,
    options: &FetchOptions,
    now_unix: u64,
) -> Result<Reply, Failure> {
    let request = Request::get(url)
        .header("Accept", accept)
        .with_timeout(TIMEOUT);
    let fetched =
        fetch(transport, request, None, options, SOURCE, now_unix).map_err(|error| Failure {
            // `fetch` errors only before anything is sent: a blocked egress address, or a URL or
            // redirect target that could not be sent safely.
            kind: SourceOutcomeKind::RefusedBeforeSending,
            http_status: None,
            detail: error.to_string(),
            retry_after_secs: None,
        })?;
    let Some(response) = fetched.response else {
        return Err(Failure {
            kind: fetched.outcome.kind,
            http_status: None,
            detail: fetched
                .outcome
                .detail
                .unwrap_or_else(|| "no response".into()),
            retry_after_secs: None,
        });
    };
    // A 429 is a rate limit whatever its body says, as fetch types it.
    if response.status != 429 && crate::classify::is_challenge(&response.text_view()) {
        return Err(Failure {
            kind: SourceOutcomeKind::BotWaf,
            http_status: Some(response.status),
            detail: "challenge page".into(),
            retry_after_secs: fetched.outcome.retry_after_secs,
        });
    }
    if response.truncated {
        return Err(Failure {
            kind: SourceOutcomeKind::Inconclusive,
            http_status: Some(response.status),
            detail: "truncated body".into(),
            retry_after_secs: None,
        });
    }
    Ok(Reply {
        response,
        final_url: fetched.final_url,
        kind: fetched.outcome.kind,
        retry_after_secs: fetched.outcome.retry_after_secs,
    })
}

/// A status that is no answer, typed as fetch typed it, so a 403 without a challenge page to a
/// registry, which is asked without a credential, is `Upstream4xx` as [`crate::fetch::answer`]
/// types it.
fn status_failure(reply: &Reply) -> Failure {
    let status = reply.response.status;
    Failure {
        kind: reply.kind,
        http_status: Some(status),
        detail: format!("HTTP {status}"),
        retry_after_secs: reply.retry_after_secs,
    }
}

/// The record an object publishes. **Pure.**
fn record(object: Object, url: &str, raw: String) -> Record {
    let mut contacts = Vec::new();
    flatten(&object.entities, &mut contacts);
    Record {
        url: url.to_owned(),
        raw,
        handle: object.handle,
        name: object
            .ldh_name
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .or(object.name),
        status: object.status,
        events: object
            .events
            .into_iter()
            .filter_map(|event| Some((event.action, event.date?)))
            .collect(),
        nameservers: object
            .nameservers
            .into_iter()
            .filter_map(|server| server.ldh_name)
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        contacts,
        country: object.country,
        start_address: object.start_address,
        end_address: object.end_address,
        cidrs: object
            .cidr0_cidrs
            .into_iter()
            .filter_map(|cidr| {
                let network = cidr.v4prefix.or(cidr.v6prefix)?;
                Some(format!("{network}/{}", cidr.length))
            })
            .collect(),
        autnums: autnum(object.start_autnum.as_ref())
            .map(|first| (first, autnum(object.end_autnum.as_ref()).unwrap_or(first))),
        kind: object.kind,
        parent_handle: object.parent_handle,
        port43: object.port43,
    }
}

/// An AS number as a registry writes it: a JSON number, or a string of one. **Pure.**
fn autnum(value: Option<&Value>) -> Option<u32> {
    match value? {
        Value::Number(number) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(text) => text
            .trim()
            .trim_start_matches(['A', 'S', 'a', 's'])
            .parse()
            .ok(),
        _ => None,
    }
}

/// Every entity in the tree, nested ones after their parent. **Pure.**
fn flatten(entities: &[Entity], out: &mut Vec<Contact>) {
    for entity in entities {
        let mut contact = entity.vcard.as_ref().map(vcard).unwrap_or_default();
        contact.roles.clone_from(&entity.roles);
        contact.handle.clone_from(&entity.handle);
        contact.iana_id = entity
            .public_ids
            .iter()
            .find(|id| id.kind.eq_ignore_ascii_case("IANA Registrar ID"))
            .map(|id| id.identifier.clone());
        out.push(contact);
        flatten(&entity.entities, out);
    }
}

/// A jCard (RFC 7095) as a contact: its name, organisation, kind, emails, telephones and
/// address. **Pure.**
fn vcard(card: &Value) -> Contact {
    let mut contact = Contact::default();
    let properties = card.get(1).and_then(Value::as_array).into_iter().flatten();
    for property in properties {
        let Some(name) = property.get(0).and_then(Value::as_str) else {
            continue;
        };
        // A structured value (an `org` with its units) is its parts joined.
        let text = property
            .get(3)
            .map(|value| {
                let mut parts = Vec::new();
                collect_text(value, &mut parts);
                parts.join(", ")
            })
            .filter(|text| !text.is_empty());
        match (name, text) {
            ("fn", Some(text)) => contact.name = Some(text),
            ("org", Some(text)) => contact.org = Some(text),
            ("kind", Some(text)) => contact.kind = Some(text),
            ("email", Some(text)) => contact.emails.push(text),
            ("tel", Some(text)) => contact.phones.push(
                text.strip_prefix("tel:")
                    .map_or(text.clone(), str::to_owned),
            ),
            ("adr", _) => contact.address = address(property),
            _ => {}
        }
    }
    contact
}

/// An `adr` property: its `label` parameter, else its non-empty parts joined. **Pure.**
fn address(property: &Value) -> Option<String> {
    let label = property
        .get(1)
        .and_then(|parameters| parameters.get("label"))
        .and_then(Value::as_str)
        .map(|label| label.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|label| !label.is_empty());
    label.or_else(|| {
        let mut parts = Vec::new();
        collect_text(property.get(3)?, &mut parts);
        (!parts.is_empty()).then(|| parts.join(", "))
    })
}

fn collect_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) if !text.trim().is_empty() => out.push(text.trim().to_owned()),
        Value::Array(items) => {
            for item in items {
                collect_text(item, out);
            }
        }
        _ => {}
    }
}

/// Whether a published value is a registry's privacy placeholder rather than data. **Pure.**
#[must_use]
pub fn is_redacted(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("redacted") || lower.contains("not disclosed") || lower.contains("withheld")
}

/// Whether a published value is an RPSL organisation handle (`ORG-NCC1-RIPE`) rather than a
/// name. **Pure.**
#[must_use]
pub fn is_rpsl_handle(value: &str) -> bool {
    value.starts_with("ORG-") && !value.contains(char::is_whitespace)
}

#[cfg(test)]
pub(crate) mod tests;
