//! A lookup's entities as Spiderfoot data elements.
//!
//! Spiderfoot shows a scan as typed elements, each with the element it was found from and the
//! module that found it. Huntsman's lookups produce entities whose evidence records carry the same
//! facts as attributes: open ports, CVEs, AS numbers, netblocks, locations, breaches, verdicts.
//! [`elements`] turns one entity per evidence record into an element of its Spiderfoot type, and
//! each attribute Spiderfoot has a type for into a child element of it, so the scan view can be
//! browsed, counted and exported the way Spiderfoot's is.
//!
//! Nothing is dropped: every element made from an evidence record carries that record whole in
//! `raw` (summary, every attribute, provenance) with the entity's tags, and an attribute without a
//! Spiderfoot type is still in that `raw`. The mapping only adds typed views of the data.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::domains::{is_or_subdomain_of, registrable_domain};
use crate::entity::{Entity, EntityKind, Evidence};
use crate::recursion::PivotEdge;
use crate::sf_country;
use crate::sf_types::{self, base_type};
use crate::sha256::{hex32, sha256};
use crate::tags;

/// The module name of the elements Huntsman itself makes: the root, the target, and verdicts no
/// single source gave.
pub const HUNTSMAN_MODULE: &str = "huntsman";

/// The module of the domain each host belongs to, the work of Spiderfoot's `sfp_dnsresolve`.
pub const DOMAIN_MODULE: &str = "hostdomain";

/// The module of the countries a scan's data names, as Spiderfoot's `sfp_countryname` finds them.
pub const COUNTRY_MODULE: &str = "countryname";

/// Days before expiry at which a certificate is reported as expiring, as Spiderfoot does.
const EXPIRING_DAYS: i64 = 30;

/// One Spiderfoot data element.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataElement {
    /// Stable within a scan: the hash of the type, data, source element and module.
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub data: String,
    /// The element this one was found from; `None` only for the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub module: String,
    /// 0 to 100.
    pub confidence: u8,
    /// Unix milliseconds.
    pub created: u64,
    /// Marked as a false positive by the operator.
    #[serde(default)]
    pub fp: bool,
    /// The entity this element shows, when it shows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    /// The evidence record this element was made from, whole, with the entity's tags.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub raw: Value,
}

fn element_id(kind: &str, data: &str, source: Option<&str>, module: &str) -> String {
    let mut bytes = Vec::with_capacity(kind.len() + data.len() + module.len() + 40);
    for part in [kind, data, source.unwrap_or(""), module] {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    hex32(&sha256(&bytes))[..16].to_owned()
}

/// What a scan was run against.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub value: &'a str,
    /// The Spiderfoot type of the target, such as `INTERNET_NAME` or `EMAILADDR`.
    pub kind: &'a str,
}

impl Target<'_> {
    fn domain(&self) -> Option<&str> {
        matches!(self.kind, "INTERNET_NAME" | "DOMAIN_NAME").then_some(self.value)
    }

    fn is_ip(&self) -> bool {
        matches!(self.kind, "IP_ADDRESS" | "IPV6_ADDRESS")
    }

    fn is_netblock(&self) -> bool {
        matches!(self.kind, "NETBLOCK_OWNER" | "NETBLOCKV6_OWNER")
    }

    /// Whether the target is the AS `asn` (`AS13335` or `13335`): an AS target is its own
    /// owner, never a member of what it announces.
    fn is_as(&self, asn: &str) -> bool {
        let digits = |value: &str| {
            value
                .trim()
                .trim_start_matches(['A', 'S', 'a', 's'])
                .to_owned()
        };
        self.kind == "BGP_AS_OWNER" && digits(self.value) == digits(asn)
    }

    /// Whether Spiderfoot's target would claim `domain` (`SpiderFootTarget.matches`): the target
    /// domain or a name under it, a target email's domain or a name under it, and any domain at
    /// all for a target it cannot place, a name, phone number, username or bitcoin address.
    fn claims(&self, domain: &str) -> bool {
        let value = self.value.trim();
        match self.kind {
            "HUMAN_NAME" | "PHONE_NUMBER" | "USERNAME" | "BITCOIN_ADDRESS" => true,
            "INTERNET_NAME" | "DOMAIN_NAME" => is_or_subdomain_of(domain, &value.to_lowercase()),
            "EMAILADDR" => value
                .rsplit_once('@')
                .is_some_and(|(_, host)| is_or_subdomain_of(domain, &host.to_lowercase())),
            _ => false,
        }
    }

    fn names(&self, entity: &Entity) -> bool {
        let wanted = match entity.kind {
            EntityKind::Domain => matches!(self.kind, "INTERNET_NAME" | "DOMAIN_NAME"),
            EntityKind::IpAddress => self.is_ip(),
            EntityKind::Email => self.kind == "EMAILADDR",
            EntityKind::Phone => self.kind == "PHONE_NUMBER",
            EntityKind::Username => self.kind == "USERNAME",
            EntityKind::Person => self.kind == "HUMAN_NAME",
            EntityKind::Asn => self.kind == "BGP_AS_OWNER",
            EntityKind::Netblock => self.is_netblock(),
            EntityKind::MacAddress => self.kind == "HSE_MAC_ADDRESS",
            EntityKind::Ssid => self.kind == "HSE_WIFI_SSID",
            EntityKind::Coordinates => self.kind == "PHYSICAL_COORDINATES",
            _ => false,
        };
        let value = self.value.trim().trim_start_matches(['A', 'S', 'a', 's']);
        wanted
            && (entity.value.eq_ignore_ascii_case(self.value.trim())
                || entity.raw_value.eq_ignore_ascii_case(self.value.trim())
                || (entity.kind == EntityKind::Asn
                    && entity.value.trim_start_matches(['A', 'S', 'a', 's']) == value))
    }
}

/// The Spiderfoot type of an entity, refined by what the scan's target is: a host under the
/// target domain is an `INTERNET_NAME`, another domain an affiliate, a domain found on a target
/// address a co-hosted site.
fn entity_type(entity: &Entity, target: Target<'_>) -> &'static str {
    let value = entity.value.as_str();
    match entity.kind {
        EntityKind::Domain => {
            let unresolved = entity.has_tag(tags::UNRESOLVED);
            match target.domain() {
                Some(domain) if is_or_subdomain_of(value, domain) => {
                    if unresolved {
                        "INTERNET_NAME_UNRESOLVED"
                    } else {
                        "INTERNET_NAME"
                    }
                }
                Some(_) if unresolved => "AFFILIATE_INTERNET_NAME_UNRESOLVED",
                Some(_) => "AFFILIATE_INTERNET_NAME",
                // The address's own reverse zone names it: Spiderfoot takes such a name as the
                // target's alias, as it does a name of an address in a target block. Any other
                // name on the address is a site hosted there.
                None if (target.is_ip() || target.is_netblock()) && entity.has_tag(tags::PTR) => {
                    "INTERNET_NAME"
                }
                None if target.is_ip() => "CO_HOSTED_SITE",
                None if unresolved => "INTERNET_NAME_UNRESOLVED",
                None => "INTERNET_NAME",
            }
        }
        EntityKind::Email => match (target.domain(), value.rsplit_once('@')) {
            (Some(domain), Some((_, host))) if !is_or_subdomain_of(host, domain) => {
                "AFFILIATE_EMAILADDR"
            }
            _ => "EMAILADDR",
        },
        EntityKind::IpAddress if value.contains(':') => "IPV6_ADDRESS",
        // A URL that is one public Wikipedia page edit is Spiderfoot's own edit type, whatever the
        // scan target is.
        EntityKind::Url if entity.has_tag(tags::WIKIPEDIA_EDIT) => "WIKIPEDIA_PAGE_EDIT",
        // A URL the iTunes lookup tags as an App Store app page is Spiderfoot's app-store entry
        // type, whatever the scan target is.
        EntityKind::Url if entity.has_tag(tags::APP_STORE_ENTRY) => "APPSTORE_ENTRY",
        EntityKind::Url => match (target.domain(), url_host(value)) {
            (Some(domain), Some(host)) if is_or_subdomain_of(&host, domain) => {
                "LINKED_URL_INTERNAL"
            }
            _ => "LINKED_URL_EXTERNAL",
        },
        EntityKind::CryptoAddress => crypto_type(value),
        // An AS target owns the blocks it announces; any other block holds what was found.
        EntityKind::Netblock => match (target.kind == "BGP_AS_OWNER", value.contains(':')) {
            (true, false) => "NETBLOCK_OWNER",
            (true, true) => "NETBLOCKV6_OWNER",
            (false, false) => "NETBLOCK_MEMBER",
            (false, true) => "NETBLOCKV6_MEMBER",
        },
        _ => base_type(&entity.kind),
    }
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn crypto_type(value: &str) -> &'static str {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    if hex.is_some_and(|hex| hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit())) {
        "ETHEREUM_ADDRESS"
    } else if value.starts_with("bc1") || value.starts_with('1') || value.starts_with('3') {
        "BITCOIN_ADDRESS"
    } else {
        "HSE_CRYPTO_ADDRESS"
    }
}

/// The descriptor type saying an entity of this kind is malicious.
fn malicious_type(kind: &EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::IpAddress => Some("MALICIOUS_IPADDR"),
        EntityKind::Domain | EntityKind::Url => Some("MALICIOUS_INTERNET_NAME"),
        EntityKind::Email => Some("MALICIOUS_EMAILADDR"),
        EntityKind::Phone => Some("MALICIOUS_PHONE_NUMBER"),
        EntityKind::Asn => Some("MALICIOUS_ASN"),
        EntityKind::Netblock => Some("MALICIOUS_NETBLOCK"),
        _ => None,
    }
}

/// The descriptor type saying a blocklist lists an entity of this kind.
fn blacklisted_type(kind: &EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::IpAddress => Some("BLACKLISTED_IPADDR"),
        EntityKind::Domain => Some("BLACKLISTED_INTERNET_NAME"),
        EntityKind::Netblock => Some("BLACKLISTED_NETBLOCK"),
        _ => None,
    }
}

/// The descriptor type saying an entity of this kind was in a breach.
fn compromised_type(kind: &EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::Email => Some("EMAILADDR_COMPROMISED"),
        EntityKind::Phone => Some("PHONE_NUMBER_COMPROMISED"),
        EntityKind::Username => Some("ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED"),
        _ => None,
    }
}

/// The items of a list attribute: providers join with `,`, `;` or whitespace.
fn items(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn positive(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.parse::<f64>().is_ok_and(|number| number > 0.0)
}

/// Whether one evidence record says its entity is malicious, by the attributes the reputation
/// sources write.
fn says_malicious(evidence: &Evidence) -> bool {
    let attr = |key: &str| evidence.attributes.get(key).map(String::as_str);
    [
        "malicious",
        "malicious_scans",
        "pulse_count",
        "total_reports",
    ]
    .iter()
    .any(|key| attr(key).is_some_and(positive))
        || attr("risk").is_some_and(|risk| {
            matches!(
                risk.trim().to_ascii_lowercase().as_str(),
                "high" | "critical"
            )
        })
        || [
            "threats",
            "malware",
            "malware_families",
            "iocs",
            "blocklists",
        ]
        .iter()
        .any(|key| attr(key).is_some_and(|value| items(value).next().is_some()))
}

/// The child elements one evidence record's attributes describe, as `(type, data)`.
fn descriptors(entity: &Entity, evidence: &Evidence, now_unix: u64) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    host_descriptors(entity, evidence, now_unix, &mut out);
    identity_descriptors(entity, evidence, &mut out);
    out
}

/// An evidence attribute that holds something.
fn attr<'a>(evidence: &'a Evidence, key: &str) -> Option<&'a str> {
    evidence
        .attributes
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

/// What a record says about a host: ports, vulnerabilities, software, routing, place and its
/// certificate.
fn host_descriptors(
    entity: &Entity,
    evidence: &Evidence,
    now_unix: u64,
    out: &mut Vec<(&'static str, String)>,
) {
    let host = entity.raw_value.as_str();
    let attr = |key: &str| attr(evidence, key);
    if let Some(ports) = attr("ports") {
        for port in items(ports).filter_map(|port| port.parse::<u16>().ok()) {
            out.push(("TCP_PORT_OPEN", format!("{host}:{port}")));
        }
    }
    if let Some(vulns) = attr("vulns") {
        for cve in items(vulns) {
            out.push(("VULNERABILITY_GENERAL", cve.to_owned()));
        }
    }
    for key in ["software", "cpes"] {
        for item in attr(key).into_iter().flat_map(items) {
            out.push(("SOFTWARE_USED", item.to_owned()));
        }
    }
    for item in attr("technologies").into_iter().flat_map(items) {
        out.push(("WEBSERVER_TECHNOLOGY", item.to_owned()));
    }
    if let Some(os) = attr("os") {
        out.push(("OPERATING_SYSTEM", os.to_owned()));
    }
    if entity.kind != EntityKind::Asn {
        for key in ["asn", "origin_asns"] {
            for asn in attr(key).into_iter().flat_map(items) {
                let digits = asn.trim_start_matches(['A', 'S', 'a', 's']);
                if digits.parse::<u32>().is_ok() {
                    out.push(("BGP_AS_MEMBER", format!("AS{digits}")));
                }
            }
        }
    }
    for key in ["prefix", "network", "range", "route"] {
        for block in attr(key).into_iter().flat_map(items) {
            if block.contains('/') {
                let kind = if block.contains(':') {
                    "NETBLOCKV6_MEMBER"
                } else {
                    "NETBLOCK_MEMBER"
                };
                out.push((kind, block.to_owned()));
            }
        }
    }
    let place: Vec<&str> = [
        attr("city"),
        attr("region"),
        attr("country_name").or_else(|| attr("country")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !place.is_empty() {
        out.push(("GEOINFO", place.join(", ")));
    }
    if let Some(certificate) = attr("certificate") {
        out.push(("SSL_CERTIFICATE_RAW", certificate.to_owned()));
    }
    if let Some(subject) = attr("subject") {
        out.push(("SSL_CERTIFICATE_ISSUED", subject.to_owned()));
    }
    if let Some(issuer) = attr("issuer") {
        out.push(("SSL_CERTIFICATE_ISSUER", issuer.to_owned()));
    }
    if let Some(expiry) = attr("not_after").and_then(crate::timefmt::parse_timestamp) {
        let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
        if expiry < now {
            out.push(("SSL_CERTIFICATE_EXPIRED", host.to_owned()));
        } else if expiry - now < EXPIRING_DAYS * 86_400 {
            out.push(("SSL_CERTIFICATE_EXPIRING", host.to_owned()));
        }
    }
}

/// The blockchain collector serializes unsigned satoshis to exactly eight
/// fractional decimal places. Validate this fixed-point form without floating
/// point rounding or accepting arbitrary imported evidence as a BTC amount.
fn valid_btc_balance(value: &str) -> bool {
    let Some((whole, fractional)) = value.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && whole.bytes().all(|digit| digit.is_ascii_digit())
        && fractional.len() == 8
        && fractional.bytes().all(|digit| digit.is_ascii_digit())
        && whole
            .parse::<u64>()
            .ok()
            .and_then(|coins| coins.checked_mul(100_000_000))
            .and_then(|satoshis| fractional.parse::<u64>().ok()?.checked_add(satoshis))
            .is_some()
}

/// What a record says about an account, a number or an address: registrar, carrier, profile,
/// breaches, leaked credentials and malicious verdicts.
fn identity_descriptors(
    entity: &Entity,
    evidence: &Evidence,
    out: &mut Vec<(&'static str, String)>,
) {
    let host = entity.raw_value.as_str();
    let attr = |key: &str| attr(evidence, key);
    if let Some(registrar) = attr("registrar") {
        out.push(("DOMAIN_REGISTRAR", registrar.to_owned()));
    }
    // A registration record as published: an address's is its network's.
    if let Some(whois) = attr("whois") {
        let kind = match entity.kind {
            EntityKind::IpAddress | EntityKind::Asn | EntityKind::Netblock => "NETBLOCK_WHOIS",
            _ => "DOMAIN_WHOIS",
        };
        out.push((kind, whois.to_owned()));
    }
    // The name servers the registration record lists, as Spiderfoot's `PROVIDER_DNS` element (its
    // "Name Server (DNS NS Records)"). `rdap_legs` is the only writer of the `ns` attribute, so it
    // types the element unambiguously; each listed server becomes one element. Before this, the
    // name servers survived only inside the raw registration record and never appeared as a typed
    // element. This is the first producer of the otherwise-dormant PROVIDER_DNS element type. No
    // extra network request is made.
    for server in attr("ns").into_iter().flat_map(items) {
        out.push(("PROVIDER_DNS", server.to_owned()));
    }
    if let Some(carrier) = attr("carrier") {
        out.push(("PROVIDER_TELCO", carrier.to_owned()));
    }
    if let Some(line) = attr("line_type") {
        out.push(("PHONE_NUMBER_TYPE", line.to_owned()));
    }
    if attr("disposable").is_some_and(positive) {
        out.push(("EMAILADDR_DISPOSABLE", host.to_owned()));
    }
    if attr("tor").is_some_and(positive) {
        out.push(("TOR_EXIT_NODE", host.to_owned()));
    }
    for key in ["profile_url", "blog_url"] {
        if let Some(url) = attr(key) {
            out.push((
                "ACCOUNT_EXTERNAL_OWNED",
                format!("{} (Category: social)\n{url}", evidence.provenance.source),
            ));
        }
    }
    // A published OpenPGP key. `openpgp_keys` is the only writer of the `fingerprint` attribute,
    // so it types the element unambiguously; `key_url` links to the key itself, and the whole
    // record (fingerprint, key URL, creation time) rides along in `raw`, so nothing is lost. This
    // is the first producer of the otherwise-dormant PGP_KEY element type.
    if let Some(fingerprint) = attr("fingerprint") {
        let data = match attr("key_url") {
            Some(url) => format!("{fingerprint}\n{url}"),
            None => fingerprint.to_owned(),
        };
        out.push(("PGP_KEY", data));
    }
    // Only a crypto address observed by the Bitcoin collector can produce a
    // balance element. Saved evidence attributes are not inherently trustworthy:
    // malformed amounts and same-named fields from other sources are not proof.
    if entity.kind == EntityKind::CryptoAddress && evidence.provenance.source == "blockchain" {
        if let Some(balance) = attr("balance_btc").filter(|value| valid_btc_balance(value)) {
            out.push(("BITCOIN_BALANCE", format!("{balance} BTC")));
        }
    }
    // The job title a public profile lists for the subject, as Spiderfoot's JOB_TITLE. Only the
    // `gravatar` lookup writes `job_title`, and only onto the employer organisation entity (from a
    // supplied email's public profile). A saved attribute is not proof on its own, so the element
    // is gated on that genuine source and entity kind: a same-named field from another source, or
    // on another entity kind, does not establish a job title. First producer of the otherwise-
    // dormant JOB_TITLE type.
    if entity.kind == EntityKind::Organisation && evidence.provenance.source == "gravatar" {
        if let Some(title) = attr("job_title") {
            out.push(("JOB_TITLE", title.to_owned()));
        }
    }
    if let Some(kind) = compromised_type(&entity.kind) {
        let mut breaches = BTreeSet::new();
        for key in [
            "breach",
            "breach_name",
            "breaches",
            "database_name",
            "dbname",
        ] {
            breaches.extend(attr(key).into_iter().flat_map(items));
        }
        for breach in breaches {
            out.push((kind, format!("{host} [{breach}]")));
        }
    }
    // That a password or its hash was exposed, and where; never the credential itself, so a
    // third party's breached login is not handed on in a report.
    let source = &evidence.provenance.source;
    if attr("password_exposed").is_some_and(positive) || attr("password").is_some_and(exposed) {
        out.push(("PASSWORD_COMPROMISED", format!("{host} [{source}]")));
    }
    if ["password_hash", "hashed_password"]
        .iter()
        .any(|key| attr(key).is_some_and(exposed))
    {
        let kind = attr("hash_type").map_or(String::new(), |kind| format!(" ({kind})"));
        out.push(("HASH_COMPROMISED", format!("{host}{kind} [{source}]")));
    }
    reputation_descriptors(entity, evidence, out);
}

/// What a reputation source says about an entity: a blocklist, a filtering resolver or a threat
/// feed names the list and its reason and writes the blacklisted element, plus the malicious one
/// when it flags a threat; a bare malicious verdict writes only the malicious element.
fn reputation_descriptors(
    entity: &Entity,
    evidence: &Evidence,
    out: &mut Vec<(&'static str, String)>,
) {
    let host = entity.raw_value.as_str();
    let attr = |key: &str| attr(evidence, key);
    // A blocklist's listing names the list and its reason, as Spiderfoot's DNSBL modules write
    // both the blacklisted and the malicious element.
    if let Some(listing) = attr("dnsbl") {
        let data = format!("{listing} [{host}]");
        if let Some(kind) = blacklisted_type(&entity.kind) {
            out.push((kind, data.clone()));
        }
        if let Some(kind) = malicious_type(&entity.kind) {
            out.push((kind, data));
        }
    } else if let Some(reason) = attr("dns_filter") {
        // A filtering resolver's block, as Spiderfoot's DNS-filter modules write it: always the
        // blacklisted element, and the malicious one too when the filter blocks threats.
        let data = format!("{reason} [{host}]");
        if let Some(kind) = blacklisted_type(&entity.kind) {
            out.push((kind, data.clone()));
        }
        if attr("dns_filter_threat").is_some_and(positive) {
            if let Some(kind) = malicious_type(&entity.kind) {
                out.push((kind, data));
            }
        }
    } else if let Some(feed) = attr("threat_feed") {
        // A threat feed's listing, as Spiderfoot's feed modules write it: always the blacklisted
        // element, and the malicious one too when the feed lists threats.
        let data = format!("{feed} [{host}]");
        if let Some(kind) = blacklisted_type(&entity.kind) {
            out.push((kind, data.clone()));
        }
        if attr("threat_feed_threat").is_some_and(positive) {
            if let Some(kind) = malicious_type(&entity.kind) {
                out.push((kind, data));
            }
        }
    } else if says_malicious(evidence) {
        if let Some(kind) = malicious_type(&entity.kind) {
            out.push((kind, format!("{} [{host}]", evidence.provenance.source)));
        }
    }
}

/// Whether a credential attribute says one was exposed: a value, or a flag that is not negative.
fn exposed(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "false" | "no" | "0" | "none" | "null"
    )
}

/// Attributes naming the indicator a source was asked about when it found this entity: the
/// element of that indicator is the new element's source.
const PARENT_KEYS: [&str; 7] = [
    "ip", "domain", "email", "username", "phone", "host", "netblock",
];

fn raw_of(evidence: &Evidence, entity: &Entity) -> Value {
    json!({
        "entity_kind": entity.kind.as_str(),
        "entity_value": entity.value,
        "tags": entity.tags,
        "evidence": evidence,
    })
}

struct Builder {
    out: Vec<DataElement>,
    seen: BTreeSet<String>,
}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: &str,
        data: String,
        source: Option<&str>,
        module: &str,
        confidence: u8,
        created: u64,
        entity: Option<&str>,
        raw: Value,
    ) -> String {
        let id = element_id(kind, &data, source, module);
        if self.seen.insert(id.clone()) {
            self.out.push(DataElement {
                id: id.clone(),
                kind: kind.to_owned(),
                data,
                source: source.map(str::to_owned),
                module: module.to_owned(),
                confidence,
                created,
                fp: false,
                entity: entity.map(str::to_owned),
                raw,
            });
        }
        id
    }
}

fn confidence(entity: &Entity) -> u8 {
    let percent = (entity.confidence.clamp(0.0, 1.0) * 100.0).round();
    // In 0..=100 after the clamp, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let percent = percent as u8;
    percent
}

/// The scan's elements: the root, the target, then one element per entity and evidence record
/// with the typed children its attributes describe. `now_unix` decides certificate expiry and
/// stamps the root and target.
#[must_use]
pub fn elements(target: Target<'_>, entities: &[Entity], now_unix: u64) -> Vec<DataElement> {
    elements_with_lineage(target, entities, &Lineage::new(), now_unix)
}

/// Where a scan that followed its findings found each entity: an entity's lowercased value to
/// the lowercased selector of the first lookup that found it. That selector's element becomes the
/// entity's source, as a Spiderfoot event's source is the event its module was handed.
pub type Lineage = BTreeMap<String, String>;

/// The [`Lineage`] of a crawl's discovery edges: each entity's earliest lookup, other than a
/// lookup of the entity itself.
#[must_use]
pub fn lineage(edges: &[PivotEdge]) -> Lineage {
    let mut sorted: Vec<&PivotEdge> = edges.iter().collect();
    sorted.sort_by_key(|edge| edge.generation);
    let mut out = Lineage::new();
    for edge in sorted {
        let child = edge.to_value.to_ascii_lowercase();
        let parent = edge.from_selector.to_ascii_lowercase();
        if child != parent {
            out.entry(child).or_insert(parent);
        }
    }
    out
}

/// [`elements`] for a scan that followed its findings: an entity whose records name no indicator
/// it was found from takes the element of the lookup `lineage` says found it as its source, so
/// the elements form the scan's discovery tree. Entities are placed generation by generation, so
/// each source element exists before the elements found from it.
#[must_use]
pub fn elements_with_lineage(
    target: Target<'_>,
    entities: &[Entity],
    lineage: &Lineage,
    now_unix: u64,
) -> Vec<DataElement> {
    let mut walk = Walk::new(target, entities, now_unix);
    let made = walk.entities(entities, lineage);
    for (entity_index, entity) in entities.iter().enumerate() {
        walk.descriptors(entity_index, entity, &made);
    }
    walk.domains();
    walk.countries();
    walk.builder.out
}

/// One pass over a scan's entities: the elements made so far, and the first element of each
/// entity value, so a record found from another indicator can name that indicator's element as
/// its source.
struct Walk<'a> {
    builder: Builder,
    target: Target<'a>,
    target_id: String,
    by_value: BTreeMap<String, String>,
    now_unix: u64,
}

impl<'a> Walk<'a> {
    /// The root and the target, with the raw evidence of every entity that names the target.
    fn new(target: Target<'a>, entities: &[Entity], now_unix: u64) -> Self {
        let now_ms = now_unix.saturating_mul(1000);
        let mut builder = Builder {
            out: Vec::new(),
            seen: BTreeSet::new(),
        };
        let target_value = target.value.trim().to_owned();
        let root = builder.push(
            "ROOT",
            target_value.clone(),
            None,
            HUNTSMAN_MODULE,
            100,
            now_ms,
            None,
            Value::Null,
        );
        let target_raw: Vec<Value> = entities
            .iter()
            .filter(|entity| target.names(entity))
            .flat_map(|entity| {
                entity
                    .evidence
                    .iter()
                    .map(move |evidence| raw_of(evidence, entity))
            })
            .collect();
        let target_id = builder.push(
            target.kind,
            target_value,
            Some(&root),
            HUNTSMAN_MODULE,
            100,
            now_ms,
            entities
                .iter()
                .find(|entity| target.names(entity))
                .map(|entity| entity.uid.as_str()),
            if target_raw.is_empty() {
                Value::Null
            } else {
                Value::Array(target_raw)
            },
        );
        let mut by_value = BTreeMap::new();
        by_value.insert(target.value.trim().to_ascii_lowercase(), target_id.clone());
        Self {
            builder,
            target,
            target_id,
            by_value,
            now_unix,
        }
    }

    /// One element per entity and evidence record, other than the target's own; returns each
    /// one's `(entity index, evidence index, element id)`.
    fn entities(&mut self, entities: &[Entity], lineage: &Lineage) -> Vec<(usize, usize, String)> {
        let now_ms = self.now_unix.saturating_mul(1000);
        let mut pending: Vec<(usize, usize, &'static str)> = Vec::new();
        for (entity_index, entity) in entities.iter().enumerate() {
            if self.target.names(entity) {
                continue;
            }
            let kind = entity_type(entity, self.target);
            for evidence_index in 0..entity.evidence.len().max(1) {
                pending.push((entity_index, evidence_index, kind));
            }
        }
        pending.sort_by_key(|(entity_index, _, _)| entities[*entity_index].generation);
        let mut made = Vec::new();
        for (entity_index, evidence_index, kind) in pending {
            let entity = &entities[entity_index];
            let evidence = entity.evidence.get(evidence_index);
            let source = evidence
                .and_then(|evidence| {
                    PARENT_KEYS.iter().find_map(|key| {
                        evidence.attr_values(key).find_map(|value| {
                            self.by_value
                                .get(&value.to_ascii_lowercase())
                                .filter(|_| !value.eq_ignore_ascii_case(&entity.value))
                        })
                    })
                })
                .or_else(|| {
                    lineage
                        .get(&entity.value.to_ascii_lowercase())
                        .and_then(|parent| self.by_value.get(parent))
                })
                .cloned()
                .unwrap_or_else(|| self.target_id.clone());
            let module = evidence.map_or(HUNTSMAN_MODULE, |evidence| {
                evidence.provenance.source.as_str()
            });
            let created = evidence.map_or(now_ms, |evidence| {
                evidence.provenance.recorded_at_unix.saturating_mul(1000)
            });
            let data = if entity.raw_value.is_empty() {
                entity.value.clone()
            } else {
                entity.raw_value.clone()
            };
            let id = self.builder.push(
                kind,
                data,
                Some(&source),
                module,
                confidence(entity),
                created,
                Some(&entity.uid),
                evidence.map_or(Value::Null, |evidence| raw_of(evidence, entity)),
            );
            self.by_value
                .entry(entity.value.to_ascii_lowercase())
                .or_insert_with(|| id.clone());
            made.push((entity_index, evidence_index, id));
        }
        made
    }

    /// The typed children each of the entity's evidence records describes, under the element
    /// that record made.
    fn descriptors(
        &mut self,
        entity_index: usize,
        entity: &Entity,
        made: &[(usize, usize, String)],
    ) {
        let own: Vec<(usize, String)> = if self.target.names(entity) {
            (0..entity.evidence.len())
                .map(|index| (index, self.target_id.clone()))
                .collect()
        } else {
            made.iter()
                .filter(|(index, _, _)| *index == entity_index)
                .map(|(_, evidence_index, id)| (*evidence_index, id.clone()))
                .collect()
        };
        let mut said_malicious = false;
        for (evidence_index, parent) in own {
            let Some(evidence) = entity.evidence.get(evidence_index) else {
                continue;
            };
            let created = evidence.provenance.recorded_at_unix.saturating_mul(1000);
            for (kind, data) in descriptors(entity, evidence, self.now_unix) {
                if kind == "BGP_AS_MEMBER" && self.target.is_as(&data) {
                    continue;
                }
                said_malicious |= kind.starts_with("MALICIOUS_");
                self.builder.push(
                    kind,
                    data,
                    Some(&parent),
                    &evidence.provenance.source,
                    confidence(entity),
                    created,
                    Some(&entity.uid),
                    Value::Null,
                );
            }
        }
        // A malicious tag that no single record's attributes explain still reaches the view.
        if !said_malicious && entity.has_tag(tags::MALICIOUS) {
            if let Some(kind) = malicious_type(&entity.kind) {
                let parent = self
                    .by_value
                    .get(&entity.value.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| self.target_id.clone());
                let sources: Vec<String> = entity.evidence_sources().into_iter().collect();
                self.builder.push(
                    kind,
                    format!("{} [{}]", sources.join(", "), entity.raw_value),
                    Some(&parent),
                    HUNTSMAN_MODULE,
                    confidence(entity),
                    self.now_unix.saturating_mul(1000),
                    Some(&entity.uid),
                    Value::Null,
                );
            }
        }
    }
}

impl Walk<'_> {
    /// The domain each host belongs to, each domain once, as Spiderfoot's `sfp_dnsresolve`
    /// reports it: a host's domain the target claims as `DOMAIN_NAME`, one the target sits below
    /// as `DOMAIN_NAME_PARENT`, an affiliate's as `AFFILIATE_DOMAIN_NAME` and a co-hosted site's
    /// as `CO_HOSTED_SITE_DOMAIN`, each found from the first host that names it.
    fn domains(&mut self) {
        let hosts: Vec<(String, &'static str, String, u8, u64)> = self
            .builder
            .out
            .iter()
            .filter_map(|element| {
                let derived = match element.kind.as_str() {
                    "INTERNET_NAME" => "DOMAIN_NAME",
                    "AFFILIATE_INTERNET_NAME" => "AFFILIATE_DOMAIN_NAME",
                    "CO_HOSTED_SITE" => "CO_HOSTED_SITE_DOMAIN",
                    _ => return None,
                };
                Some((
                    element.id.clone(),
                    derived,
                    element
                        .data
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                    element.confidence,
                    element.created,
                ))
            })
            .collect();
        let mut reported = BTreeSet::new();
        for (source, mut derived, host, confidence, created) in hosts {
            if host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let Some(domain) = registrable_domain(&host) else {
                continue;
            };
            if derived == "DOMAIN_NAME" && !self.target.claims(&domain) {
                if !host.ends_with(&format!(".{domain}")) {
                    continue;
                }
                derived = "DOMAIN_NAME_PARENT";
            }
            if reported.insert((derived, domain.clone())) {
                self.builder.push(
                    derived,
                    domain,
                    Some(&source),
                    DOMAIN_MODULE,
                    confidence,
                    created,
                    None,
                    Value::Null,
                );
            }
        }
    }

    /// The countries the scan's phone numbers, domains, IBANs, places, addresses and WHOIS
    /// records name, as Spiderfoot's `sfp_countryname` finds them: each country a child of the
    /// element that names it, and each distinct value read once, whatever its type.
    fn countries(&mut self) {
        let mut read = BTreeSet::new();
        let named: Vec<(String, &'static str, u8, u64)> = self
            .builder
            .out
            .iter()
            .filter(|element| sf_country::WATCHED.contains(&element.kind.as_str()))
            .filter(|element| read.insert(element.data.clone()))
            .flat_map(|element| {
                sf_country::of_element(&element.kind, &element.data)
                    .into_iter()
                    .map(|country| {
                        (
                            element.id.clone(),
                            country,
                            element.confidence,
                            element.created,
                        )
                    })
            })
            .collect();
        for (source, country, confidence, created) in named {
            self.builder.push(
                "COUNTRY_NAME",
                country.to_owned(),
                Some(&source),
                COUNTRY_MODULE,
                confidence,
                created,
                None,
                Value::Null,
            );
        }
    }
}

/// Per-type counts of a scan's elements, as Spiderfoot's summary shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSummary {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: String,
    pub total: usize,
    pub unique: usize,
    /// The newest element of the type, in Unix milliseconds.
    pub last: u64,
}

/// One row per type that has elements, the root left out, by count then type.
#[must_use]
pub fn summary(elements: &[DataElement]) -> Vec<TypeSummary> {
    let mut by_type: BTreeMap<&str, (usize, BTreeSet<&str>, u64)> = BTreeMap::new();
    for element in elements.iter().filter(|element| element.kind != "ROOT") {
        let entry = by_type.entry(&element.kind).or_default();
        entry.0 += 1;
        entry.1.insert(&element.data);
        entry.2 = entry.2.max(element.created);
    }
    let mut rows: Vec<TypeSummary> = by_type
        .into_iter()
        .map(|(kind, (total, unique, last))| TypeSummary {
            kind: kind.to_owned(),
            description: sf_types::describe(kind).to_owned(),
            total,
            unique: unique.len(),
            last,
        })
        .collect();
    rows.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.kind.cmp(&b.kind)));
    rows
}

/// The elements with one element per type and data, the first kept: Spiderfoot's unique view.
#[must_use]
pub fn unique(elements: &[DataElement]) -> Vec<&DataElement> {
    let mut seen = BTreeSet::new();
    elements
        .iter()
        .filter(|element| seen.insert((element.kind.as_str(), element.data.as_str())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EvidenceProvenance;

    fn entity(kind: EntityKind, value: &str, source: &str, attrs: &[(&str, &str)]) -> Entity {
        let mut evidence = Evidence::new(EvidenceProvenance::for_scan(source, "scan"), "found it");
        evidence.provenance.recorded_at_unix = 1_700_000_000;
        for (key, val) in attrs {
            evidence = evidence.with_attr(*key, *val);
        }
        Entity::builder(kind, value, 0.8, "scan")
            .evidence(evidence)
            .build()
    }

    fn of_type<'a>(elements: &'a [DataElement], kind: &str) -> Vec<&'a DataElement> {
        elements
            .iter()
            .filter(|element| element.kind == kind)
            .collect()
    }

    const DOMAIN: Target<'static> = Target {
        value: "example.com",
        kind: "INTERNET_NAME",
    };

    #[test]
    fn hosts_under_the_target_are_internet_names_and_others_are_affiliates() {
        let found = elements(
            DOMAIN,
            &[
                entity(EntityKind::Domain, "www.example.com", "crtsh", &[]),
                entity(EntityKind::Domain, "example.net", "robtex", &[]),
                entity(EntityKind::Email, "ops@example.com", "hunter", &[]),
                entity(EntityKind::Email, "x@other.org", "hunter", &[]),
            ],
            1_700_000_000,
        );
        assert_eq!(found[0].kind, "ROOT");
        assert_eq!(found[1].kind, "INTERNET_NAME");
        assert_eq!(found[1].data, "example.com");
        assert_eq!(found[1].source.as_deref(), Some(found[0].id.as_str()));
        assert_eq!(of_type(&found, "INTERNET_NAME").len(), 2);
        assert_eq!(
            of_type(&found, "AFFILIATE_INTERNET_NAME")[0].data,
            "example.net"
        );
        assert_eq!(of_type(&found, "EMAILADDR")[0].data, "ops@example.com");
        assert_eq!(
            of_type(&found, "AFFILIATE_EMAILADDR")[0].data,
            "x@other.org"
        );
        let www = of_type(&found, "INTERNET_NAME")[1];
        assert_eq!(www.module, "crtsh");
        assert_eq!(www.source.as_deref(), Some(found[1].id.as_str()));
        assert_eq!(www.created, 1_700_000_000_000);
        assert_eq!(www.confidence, 80);
    }

    /// A name tagged unresolved is Spiderfoot's unresolved type, inside the target or out.
    #[test]
    fn a_name_that_does_not_resolve_is_an_unresolved_internet_name() {
        let mut inside = entity(EntityKind::Domain, "old.example.com", "dnsresolve", &[]);
        inside.tag(tags::UNRESOLVED);
        let mut outside = entity(EntityKind::Domain, "old.example.net", "robtex", &[]);
        outside.tag(tags::UNRESOLVED);
        let found = elements(DOMAIN, &[inside.clone(), outside], 1_700_000_000);
        assert_eq!(
            of_type(&found, "INTERNET_NAME_UNRESOLVED")[0].data,
            "old.example.com"
        );
        assert_eq!(
            of_type(&found, "AFFILIATE_INTERNET_NAME_UNRESOLVED")[0].data,
            "old.example.net"
        );
        // A name with no domain target is still unresolved.
        let found = elements(
            Target {
                value: "ops@example.org",
                kind: "EMAILADDR",
            },
            &[inside],
            1_700_000_000,
        );
        assert_eq!(of_type(&found, "INTERNET_NAME_UNRESOLVED").len(), 1);
    }

    /// A URL tagged as a Wikipedia edit is Spiderfoot's `WIKIPEDIA_PAGE_EDIT`; an untagged URL is a
    /// plain linked URL, so the type is driven by the tag, not the host.
    #[test]
    fn a_wikipedia_edit_url_is_the_wikipedia_page_edit_type() {
        let mut edit = entity(
            EntityKind::Url,
            "https://en.wikipedia.org/w/index.php?oldid=555001",
            "wikipedia",
            &[],
        );
        edit.tag(tags::WIKIPEDIA_EDIT);
        let found = elements(DOMAIN, &[edit], 1_700_000_000);
        assert_eq!(
            of_type(&found, "WIKIPEDIA_PAGE_EDIT")[0].data,
            "https://en.wikipedia.org/w/index.php?oldid=555001"
        );

        let plain = entity(EntityKind::Url, "https://example.com/x", "web", &[]);
        let found = elements(DOMAIN, &[plain], 1_700_000_000);
        assert!(of_type(&found, "WIKIPEDIA_PAGE_EDIT").is_empty());
        let linked = of_type(&found, "LINKED_URL_INTERNAL").len()
            + of_type(&found, "LINKED_URL_EXTERNAL").len();
        assert_eq!(linked, 1, "an untagged URL is still a linked URL");
    }

    /// A URL the iTunes lookup tags as an App Store entry is Spiderfoot's `APPSTORE_ENTRY`
    /// (the dormant type's first producer); an untagged URL stays a plain linked URL.
    #[test]
    fn an_app_store_url_is_the_appstore_entry_type() {
        let mut app = entity(
            EntityKind::Url,
            "https://apps.apple.com/us/app/example-trail-app/id1",
            "apple_itunes",
            &[],
        );
        app.tag(tags::APP_STORE_ENTRY);
        let found = elements(DOMAIN, &[app], 1_700_000_000);
        assert_eq!(
            of_type(&found, "APPSTORE_ENTRY")[0].data,
            "https://apps.apple.com/us/app/example-trail-app/id1"
        );

        let plain = entity(EntityKind::Url, "https://example.com/x", "web", &[]);
        let found = elements(DOMAIN, &[plain], 1_700_000_000);
        assert!(of_type(&found, "APPSTORE_ENTRY").is_empty());
        let linked = of_type(&found, "LINKED_URL_INTERNAL").len()
            + of_type(&found, "LINKED_URL_EXTERNAL").len();
        assert_eq!(linked, 1, "an untagged URL is still a linked URL");
    }

    #[test]
    fn each_hosts_domain_and_each_named_country_is_derived_once_as_spiderfoot_does() {
        let found = elements(
            DOMAIN,
            &[
                entity(EntityKind::Domain, "www.example.com", "crtsh", &[]),
                entity(EntityKind::Domain, "mail.example.com", "crtsh", &[]),
                entity(EntityKind::Domain, "shop.example.com.au", "robtex", &[]),
                entity(EntityKind::Domain, "cdn.example.com.au", "robtex", &[]),
                entity(EntityKind::Phone, "+442071838750", "hunter", &[]),
                entity(
                    EntityKind::IpAddress,
                    "8.8.8.8",
                    "ipinfo",
                    &[("city", "Mountain View"), ("country", "US")],
                ),
            ],
            1_700_000_000,
        );
        let data = |kind: &str| -> Vec<&str> {
            of_type(&found, kind)
                .iter()
                .map(|element| element.data.as_str())
                .collect()
        };
        // The target's domain once, from the target, though three hosts sit in it.
        assert_eq!(data("DOMAIN_NAME"), ["example.com"]);
        assert_eq!(
            of_type(&found, "DOMAIN_NAME")[0].source.as_deref(),
            Some(found[1].id.as_str())
        );
        assert_eq!(of_type(&found, "DOMAIN_NAME")[0].module, DOMAIN_MODULE);
        assert_eq!(data("AFFILIATE_DOMAIN_NAME"), ["example.com.au"]);
        let mut countries = data("COUNTRY_NAME");
        countries.sort_unstable();
        // .com is the United States to Spiderfoot, and so is the place; .com.au is Australia.
        assert_eq!(
            countries,
            [
                "Australia",
                "United Kingdom",
                "United States",
                "United States"
            ]
        );
        let uk = of_type(&found, "COUNTRY_NAME")
            .into_iter()
            .find(|element| element.data == "United Kingdom")
            .unwrap();
        let phone = of_type(&found, "PHONE_NUMBER")[0];
        assert_eq!(uk.source.as_deref(), Some(phone.id.as_str()));
        assert_eq!(uk.module, COUNTRY_MODULE);
    }

    #[test]
    fn a_host_above_a_named_target_gives_its_parent_domain_and_an_address_target_gives_co_hosts() {
        let host = Target {
            value: "www.example.com",
            kind: "INTERNET_NAME",
        };
        let found = elements(
            host,
            &[entity(EntityKind::Domain, "api.example.com", "crtsh", &[])],
            1_700_000_000,
        );
        let parent: Vec<&str> = of_type(&found, "DOMAIN_NAME_PARENT")
            .iter()
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(parent, ["example.com"]);
        assert!(of_type(&found, "DOMAIN_NAME").is_empty());
        let address = Target {
            value: "8.8.8.8",
            kind: "IP_ADDRESS",
        };
        let found = elements(
            address,
            &[entity(EntityKind::Domain, "dns.google", "robtex", &[])],
            1_700_000_000,
        );
        assert_eq!(
            of_type(&found, "CO_HOSTED_SITE_DOMAIN")[0].data,
            "dns.google"
        );
        assert!(
            of_type(&found, "COUNTRY_NAME").is_empty(),
            ".google names no country"
        );
    }

    #[test]
    fn attributes_become_typed_children_of_their_record_and_raw_keeps_every_attribute() {
        let ip = entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "internetdb",
            &[
                ("ports", "22,443"),
                ("vulns", "CVE-2021-44228"),
                ("cpes", "cpe:/a:nginx:nginx:1.18.0"),
                ("asn", "AS64500"),
                ("prefix", "198.51.100.0/24"),
                ("city", "Sydney"),
                ("country", "AU"),
                ("unmapped_detail", "kept in raw"),
            ],
        );
        let found = elements(
            Target {
                value: "198.51.100.7",
                kind: "IP_ADDRESS",
            },
            &[ip],
            1_700_000_000,
        );
        let target = &found[1];
        assert_eq!(target.kind, "IP_ADDRESS");
        let ports: Vec<&str> = of_type(&found, "TCP_PORT_OPEN")
            .iter()
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(ports, ["198.51.100.7:22", "198.51.100.7:443"]);
        assert!(
            of_type(&found, "TCP_PORT_OPEN")
                .iter()
                .all(
                    |element| element.source.as_deref() == Some(target.id.as_str())
                        && element.module == "internetdb"
                )
        );
        assert_eq!(
            of_type(&found, "VULNERABILITY_GENERAL")[0].data,
            "CVE-2021-44228"
        );
        assert_eq!(
            of_type(&found, "SOFTWARE_USED")[0].data,
            "cpe:/a:nginx:nginx:1.18.0"
        );
        assert_eq!(of_type(&found, "BGP_AS_MEMBER")[0].data, "AS64500");
        assert_eq!(
            of_type(&found, "NETBLOCK_MEMBER")[0].data,
            "198.51.100.0/24"
        );
        assert_eq!(of_type(&found, "GEOINFO")[0].data, "Sydney, AU");
        let raw = target.raw.to_string();
        assert!(
            raw.contains("unmapped_detail") && raw.contains("kept in raw"),
            "{raw}"
        );
    }

    #[test]
    fn a_record_found_from_another_indicator_names_that_indicators_element_as_its_source() {
        let ip = entity(EntityKind::IpAddress, "198.51.100.7", "dns", &[]);
        let cohost = entity(
            EntityKind::Domain,
            "shop.example.net",
            "hackertarget",
            &[("ip", "198.51.100.7")],
        );
        let found = elements(DOMAIN, &[ip, cohost], 1_700_000_000);
        let ip_id = &of_type(&found, "IP_ADDRESS")[0].id;
        let affiliate = of_type(&found, "AFFILIATE_INTERNET_NAME")[0];
        assert_eq!(affiliate.source.as_ref(), Some(ip_id));
    }

    #[test]
    fn breaches_passwords_and_verdicts_become_descriptors() {
        let mut email = entity(
            EntityKind::Email,
            "jane@example.org",
            "xposed_or_not",
            &[
                ("breaches", "Adobe; LinkedIn"),
                ("password", "hunter2"),
                ("password_hash", "5f4dcc3b5aa765d61d8327deb882cf99"),
                ("hash_type", "md5"),
            ],
        );
        email.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("ipqs", "scan"), "verdict")
                .with_attr("malicious", "1"),
        );
        let found = elements(
            Target {
                value: "jane@example.org",
                kind: "EMAILADDR",
            },
            &[email],
            1_700_000_000,
        );
        let breaches: Vec<&str> = of_type(&found, "EMAILADDR_COMPROMISED")
            .iter()
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(
            breaches,
            ["jane@example.org [Adobe]", "jane@example.org [LinkedIn]"]
        );
        // The exposure and where it was seen, never the password or hash.
        assert_eq!(
            of_type(&found, "PASSWORD_COMPROMISED")[0].data,
            "jane@example.org [xposed_or_not]"
        );
        assert_eq!(
            of_type(&found, "HASH_COMPROMISED")[0].data,
            "jane@example.org (md5) [xposed_or_not]"
        );
        let descriptors: Vec<&DataElement> = found
            .iter()
            .filter(|element| element.raw.is_null())
            .collect();
        assert!(
            descriptors.iter().all(
                |element| !element.data.contains("hunter2") && !element.data.contains("5f4dcc")
            ),
            "{descriptors:?}"
        );
        let flagged = elements(
            Target {
                value: "jane@example.org",
                kind: "EMAILADDR",
            },
            &[entity(
                EntityKind::Email,
                "jane@example.org",
                "oathnet",
                &[("password_exposed", "true")],
            )],
            1_700_000_000,
        );
        assert_eq!(
            of_type(&flagged, "PASSWORD_COMPROMISED")[0].data,
            "jane@example.org [oathnet]"
        );
        let malicious = of_type(&found, "MALICIOUS_EMAILADDR");
        assert_eq!(malicious.len(), 1);
        assert_eq!(malicious[0].module, "ipqs");
    }

    #[test]
    fn a_malicious_tag_without_a_record_that_explains_it_still_shows() {
        let mut ip = entity(EntityKind::IpAddress, "203.0.113.9", "greynoise", &[]);
        ip.tag(tags::MALICIOUS);
        let found = elements(DOMAIN, &[ip], 1_700_000_000);
        let malicious = of_type(&found, "MALICIOUS_IPADDR");
        assert_eq!(malicious.len(), 1);
        assert_eq!(malicious[0].module, HUNTSMAN_MODULE);
        assert_eq!(malicious[0].data, "greynoise [203.0.113.9]");
    }

    #[test]
    fn certificates_past_or_near_expiry_are_reported() {
        let now = 1_700_000_000;
        let expired = entity(
            EntityKind::Domain,
            "old.example.com",
            "crtsh",
            &[
                ("not_after", "2020-01-01T00:00:00Z"),
                ("issuer", "Let's Encrypt"),
            ],
        );
        let soon = entity(
            EntityKind::Domain,
            "soon.example.com",
            "crtsh",
            &[("not_after", "2023-11-20T00:00:00Z")],
        );
        let found = elements(DOMAIN, &[expired, soon], now);
        assert_eq!(
            of_type(&found, "SSL_CERTIFICATE_EXPIRED")[0].data,
            "old.example.com"
        );
        assert_eq!(
            of_type(&found, "SSL_CERTIFICATE_EXPIRING")[0].data,
            "soon.example.com"
        );
        assert_eq!(
            of_type(&found, "SSL_CERTIFICATE_ISSUER")[0].data,
            "Let's Encrypt"
        );
    }

    /// `openpgp_keys` keeps a found key's fingerprint and fetch URL as evidence; that record
    /// becomes a `PGP_KEY` element (the dormant type's first producer). An identity with no key
    /// evidence produces none.
    #[test]
    fn an_openpgp_key_fingerprint_becomes_a_pgp_key_element() {
        let fingerprint = "8F17777118A33DDA9BA48E62AACB3243630052D9";
        let key_url = "https://keys.openpgp.org/vks/v1/by-fingerprint/8F17777118A33DDA9BA48E62AACB3243630052D9";
        let email = entity(
            EntityKind::Email,
            "neal@gnupg.org",
            "openpgp_keys",
            &[("fingerprint", fingerprint), ("key_url", key_url)],
        );
        let found = elements(
            Target {
                value: "neal@gnupg.org",
                kind: "EMAILADDR",
            },
            &[email],
            1_700_000_000,
        );
        assert_eq!(
            of_type(&found, "PGP_KEY")[0].data,
            format!("{fingerprint}\n{key_url}")
        );

        let plain = entity(EntityKind::Email, "x@example.com", "gravatar", &[]);
        let found = elements(
            Target {
                value: "x@example.com",
                kind: "EMAILADDR",
            },
            &[plain],
            1_700_000_000,
        );
        assert!(of_type(&found, "PGP_KEY").is_empty());
    }

    #[test]
    fn registration_name_servers_become_provider_dns_elements() {
        // `rdap_legs` writes one `ns` attribute per name server; `with_attr` joins repeats with
        // "; ", which the mapping splits back into one element each.
        let domain = entity(
            EntityKind::Domain,
            "example.com",
            "rdap",
            &[("ns", "ns1.example.net"), ("ns", "ns2.example.net")],
        );
        let found = elements(DOMAIN, &[domain], 1_700_000_000);
        let servers: Vec<&str> = of_type(&found, "PROVIDER_DNS")
            .iter()
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(servers, ["ns1.example.net", "ns2.example.net"]);

        // A domain with no registration name servers produces no PROVIDER_DNS element.
        let plain = entity(EntityKind::Domain, "bare.example.com", "crtsh", &[]);
        let found = elements(DOMAIN, &[plain], 1_700_000_000);
        assert!(of_type(&found, "PROVIDER_DNS").is_empty());
    }

    #[test]
    fn a_bitcoin_address_balance_becomes_a_bitcoin_balance_element() {
        // `blockchain` writes `balance_btc` only for Bitcoin addresses, so the attribute alone
        // types the balance.
        let address = entity(
            EntityKind::CryptoAddress,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "blockchain",
            &[("balance_btc", "107.69281547")],
        );
        let found = elements(DOMAIN, &[address], 1_700_000_000);
        assert_eq!(
            of_type(&found, "BITCOIN_BALANCE")[0].data,
            "107.69281547 BTC"
        );

        // Zero is an observed amount, not a missing record.
        let zero = entity(
            EntityKind::CryptoAddress,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "blockchain",
            &[("balance_btc", "0.00000000")],
        );
        let found = elements(DOMAIN, &[zero], 1_700_000_000);
        assert_eq!(of_type(&found, "BITCOIN_BALANCE")[0].data, "0.00000000 BTC");

        // Neither another provider's attribute nor another entity type establishes
        // a Bitcoin balance, even if the field name matches.
        let other_source = entity(
            EntityKind::CryptoAddress,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "mnemonic",
            &[("balance_btc", "25.00000000")],
        );
        let other_type = entity(
            EntityKind::Domain,
            "example.com",
            "blockchain",
            &[("balance_btc", "25.00000000")],
        );
        let found = elements(DOMAIN, &[other_source, other_type], 1_700_000_000);
        assert!(of_type(&found, "BITCOIN_BALANCE").is_empty());

        for invalid in [
            "",
            "-1.00000000",
            "NaN",
            "1.0000000",
            "1.000000000",
            "184467440738.00000000",
        ] {
            assert!(!valid_btc_balance(invalid), "{invalid}");
        }
        assert!(valid_btc_balance("107.69281547"));
        assert!(valid_btc_balance("0.00000000"));

        // A crypto address with no balance summary produces no BITCOIN_BALANCE element.
        let bare = entity(
            EntityKind::CryptoAddress,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "mnemonic",
            &[],
        );
        let found = elements(DOMAIN, &[bare], 1_700_000_000);
        assert!(of_type(&found, "BITCOIN_BALANCE").is_empty());
    }

    #[test]
    fn a_profile_job_title_becomes_a_job_title_element() {
        // `gravatar` writes `job_title` on the employer organisation entity.
        let employer = entity(
            EntityKind::Organisation,
            "Example Corp",
            "gravatar",
            &[("job_title", "Principal Engineer")],
        );
        let found = elements(DOMAIN, &[employer], 1_700_000_000);
        assert_eq!(of_type(&found, "JOB_TITLE")[0].data, "Principal Engineer");

        // An organisation with no job title produces no JOB_TITLE element.
        let bare = entity(EntityKind::Organisation, "Other Corp", "rdap", &[]);
        let found = elements(DOMAIN, &[bare], 1_700_000_000);
        assert!(of_type(&found, "JOB_TITLE").is_empty());

        // Neither another provider's attribute nor another entity kind establishes a job title,
        // even when the field name matches.
        let other_source = entity(
            EntityKind::Organisation,
            "Example Corp",
            "rdap",
            &[("job_title", "Principal Engineer")],
        );
        let other_kind = entity(
            EntityKind::Person,
            "Jane Example",
            "gravatar",
            &[("job_title", "Principal Engineer")],
        );
        let found = elements(DOMAIN, &[other_source, other_kind], 1_700_000_000);
        assert!(of_type(&found, "JOB_TITLE").is_empty());
    }

    #[test]
    fn every_type_the_mapping_can_emit_is_catalogued() {
        let emitted = [
            "ROOT",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
            "EMAILADDR",
            "AFFILIATE_EMAILADDR",
            "IPV6_ADDRESS",
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "WIKIPEDIA_PAGE_EDIT",
            "APPSTORE_ENTRY",
            "ETHEREUM_ADDRESS",
            "BITCOIN_ADDRESS",
            "TCP_PORT_OPEN",
            "VULNERABILITY_GENERAL",
            "SOFTWARE_USED",
            "WEBSERVER_TECHNOLOGY",
            "OPERATING_SYSTEM",
            "BGP_AS_MEMBER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "GEOINFO",
            "SSL_CERTIFICATE_ISSUER",
            "SSL_CERTIFICATE_EXPIRED",
            "SSL_CERTIFICATE_EXPIRING",
            "DOMAIN_REGISTRAR",
            "PROVIDER_DNS",
            "BITCOIN_BALANCE",
            "JOB_TITLE",
            "PROVIDER_TELCO",
            "PHONE_NUMBER_TYPE",
            "EMAILADDR_DISPOSABLE",
            "TOR_EXIT_NODE",
            "ACCOUNT_EXTERNAL_OWNED",
            "PGP_KEY",
            "EMAILADDR_COMPROMISED",
            "PHONE_NUMBER_COMPROMISED",
            "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED",
            "PASSWORD_COMPROMISED",
            "HASH_COMPROMISED",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_EMAILADDR",
            "MALICIOUS_PHONE_NUMBER",
            "MALICIOUS_ASN",
            "DOMAIN_NAME",
            "DOMAIN_NAME_PARENT",
            "AFFILIATE_DOMAIN_NAME",
            "CO_HOSTED_SITE_DOMAIN",
            "COUNTRY_NAME",
        ];
        for kind in emitted {
            assert!(sf_types::find(kind).is_some(), "{kind} is not catalogued");
        }
    }

    #[test]
    fn the_summary_counts_totals_and_unique_data_per_type_and_the_unique_view_dedups() {
        let mut a = entity(EntityKind::Domain, "a.example.com", "crtsh", &[]);
        a.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("robtex", "scan"),
            "seen",
        ));
        let found = elements(DOMAIN, &[a], 1_700_000_000);
        let rows = summary(&found);
        let names = rows.iter().find(|row| row.kind == "INTERNET_NAME").unwrap();
        assert_eq!((names.total, names.unique), (3, 2));
        assert_eq!(names.description, "Internet Name");
        assert!(rows.iter().all(|row| row.kind != "ROOT"));
        assert_eq!(unique(&found).len(), found.len() - 1);
    }

    #[test]
    fn ids_are_stable_for_the_same_input() {
        let input = [entity(
            EntityKind::Domain,
            "a.example.com",
            "crtsh",
            &[("ports", "80")],
        )];
        let first = elements(DOMAIN, &input, 1_700_000_000);
        let second = elements(DOMAIN, &input, 1_700_000_000);
        assert_eq!(first, second);
        let ids: BTreeSet<&str> = first.iter().map(|element| element.id.as_str()).collect();
        assert_eq!(ids.len(), first.len());
    }
}
