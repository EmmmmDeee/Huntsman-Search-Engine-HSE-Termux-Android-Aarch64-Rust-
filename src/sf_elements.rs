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
            EntityKind::Document => self.kind == "HSE_DOCUMENT",
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
                Some(_) if entity.has_tag(tags::LOOKALIKE) => "SIMILARDOMAIN",
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
fn descriptors(
    entity: &Entity,
    evidence: &Evidence,
    cve_scores: &BTreeMap<String, f64>,
    now_unix: u64,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    host_descriptors(entity, evidence, cve_scores, now_unix, &mut out);
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

/// Role/contact email addresses a whois record publishes, as Spiderfoot's `EMAILADDR_GENERIC`.
/// Each key has a single keyless writer, so the element is gated on that genuine source; the value
/// is accepted only when it parses as one address, so a malformed field cannot forge an email.
/// First producer of the otherwise-dormant `EMAILADDR_GENERIC` type.
fn generic_contact_emails(evidence: &Evidence, out: &mut Vec<(&'static str, String)>) {
    let keys: &[&str] = if evidence.provenance.source == crate::netlas::SOURCE {
        &["abuse_email", "registrar_email"]
    } else if evidence.provenance.source == crate::isc::SOURCE {
        &["abuse_contact"]
    } else {
        &[]
    };
    for key in keys {
        if let Some(email) = attr(evidence, key).and_then(crate::canonical::canonical_email) {
            out.push(("EMAILADDR_GENERIC", email));
        }
    }
}

/// The CVSS score of every CVE any record of the scan scores, by upper-cased CVE id, the highest
/// when records disagree: Shodan writes each scored CVE in `cve_scores` as `CVE-ID SCORE`. A
/// score belongs to the CVE, not the host, so one scan types a CVE alike wherever it is listed.
/// **Pure.**
fn cvss_scores(entities: &[Entity]) -> BTreeMap<String, f64> {
    let mut scores = BTreeMap::new();
    let entries = entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .filter_map(|evidence| attr(evidence, "cve_scores"))
        .flat_map(items);
    for entry in entries {
        let Some((id, score)) = entry.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(score) = score.trim().parse::<f64>() else {
            continue;
        };
        if !(0.0..=10.0).contains(&score) {
            continue;
        }
        let best = scores.entry(id.to_ascii_uppercase()).or_insert(score);
        if score > *best {
            *best = score;
        }
    }
    scores
}

/// A vulnerability's type by its CVSS score, as Spiderfoot's `cveInfo` rates one: CRITICAL from
/// 9.0, HIGH from 7.0, MEDIUM from 4.0, LOW below, and GENERAL when nothing scores it. The
/// CRITICAL, HIGH and MEDIUM/LOW correlation rules read these types. **Pure.**
fn vulnerability_type(score: Option<f64>) -> &'static str {
    match score {
        Some(score) if score >= 9.0 => "VULNERABILITY_CVE_CRITICAL",
        Some(score) if score >= 7.0 => "VULNERABILITY_CVE_HIGH",
        Some(score) if score >= 4.0 => "VULNERABILITY_CVE_MEDIUM",
        Some(_) => "VULNERABILITY_CVE_LOW",
        None => "VULNERABILITY_GENERAL",
    }
}

/// An HTTP status line code is exactly three ASCII digits naming a 1xx-5xx class. Validate the
/// saved value so a malformed or non-status field cannot be surfaced as an `HTTP_CODE`.
fn valid_http_status(value: &str) -> bool {
    value.len() == 3
        && value.bytes().all(|digit| digit.is_ascii_digit())
        && value
            .parse::<u16>()
            .is_ok_and(|code| (100..=599).contains(&code))
}

/// What a record says about a host: ports, vulnerabilities, software, routing, place and its
/// certificate.
fn host_descriptors(
    entity: &Entity,
    evidence: &Evidence,
    cve_scores: &BTreeMap<String, f64>,
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
            let score = cve_scores.get(&cve.to_ascii_uppercase()).copied();
            out.push((vulnerability_type(score), cve.to_owned()));
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
    // The web server a host advertises in its HTTP `Server` banner, as Spiderfoot's
    // WEBSERVER_BANNER. Only the keyless `pulsedive` lookup writes `http_server`, onto the IP or
    // domain it observed. A saved attribute is not proof on its own, so the element is gated on
    // that genuine source and host entity kind: a same-named field from another source, or on
    // another entity kind, does not establish a server banner. First producer of the otherwise-
    // dormant WEBSERVER_BANNER type.
    if matches!(entity.kind, EntityKind::IpAddress | EntityKind::Domain)
        && evidence.provenance.source == "pulsedive"
    {
        if let Some(server) = attr("http_server") {
            out.push(("WEBSERVER_BANNER", server.to_owned()));
        }
        // The HTTP status a host's web server returned, as Spiderfoot's HTTP_CODE. The same
        // keyless `pulsedive` probe writes `http_status`; it is emitted only when the value is a
        // real 1xx-5xx status, so a malformed field cannot forge the element. First producer of
        // the otherwise-dormant HTTP_CODE type.
        if let Some(code) = attr("http_status").filter(|value| valid_http_status(value)) {
            out.push(("HTTP_CODE", code.to_owned()));
        }
    }
    // The passive-DNS record set a host resolves to or from, as Spiderfoot's RAW_DNS_RECORDS
    // ("Raw DNS Records"). Only the keyless `mnemonic` passive-DNS lookup writes `passive_dns`,
    // onto the domain or IP it queried, as one pipe-delimited dump of every record line. A saved
    // attribute is not proof on its own, so the element is gated on that genuine source and host
    // entity kind: a same-named field from another source, or on another entity kind, does not
    // establish a passive-DNS record set. The dump is emitted whole — it is one raw record by
    // design, not a re-splittable list. First producer of the otherwise-dormant RAW_DNS_RECORDS
    // type. No extra network request is made.
    if matches!(entity.kind, EntityKind::IpAddress | EntityKind::Domain)
        && evidence.provenance.source == crate::mnemonic::SOURCE
    {
        if let Some(records) = attr("passive_dns") {
            out.push(("RAW_DNS_RECORDS", records.to_owned()));
        }
    }
    if let Some(os) = attr("os") {
        out.push(("OPERATING_SYSTEM", os.to_owned()));
    }
    // The AS a host belongs to, as Spiderfoot's BGP_AS_MEMBER. A record keeps every AS its
    // provider named, RIPEstat's reserved origins too, so only a public AS number counts, read
    // and written as an ASN entity is.
    if entity.kind != EntityKind::Asn {
        for key in ["asn", "origin_asns"] {
            for asn in attr(key)
                .into_iter()
                .flat_map(items)
                .filter_map(crate::canonical::canonical_asn)
            {
                out.push(("BGP_AS_MEMBER", asn));
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
    // The ISP / hosting organisation a host sits behind, as Spiderfoot's PROVIDER_HOSTING. The
    // IP-reputation and geolocation sources write it as `isp` (pulsedive keyless; ipqs, shodan,
    // abuseipdb when their keys are set), from the IP's registry, onto the IP or the domain that
    // resolved to it. A saved attribute is not proof on its own, so the element is gated on that
    // set of genuine sources; no other source writes `isp`, so nothing else can forge it. First
    // producer of the otherwise-dormant PROVIDER_HOSTING type.
    if matches!(
        evidence.provenance.source.as_str(),
        "pulsedive" | "ipqs" | "shodan" | "abuseipdb"
    ) {
        if let Some(isp) = attr("isp") {
            out.push(("PROVIDER_HOSTING", isp.to_owned()));
        }
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
    generic_contact_emails(evidence, out);
    // A registration record as published: an address's is its network's.
    if let Some(whois) = attr("whois") {
        let kind = match entity.kind {
            EntityKind::IpAddress | EntityKind::Asn | EntityKind::Netblock => "NETBLOCK_WHOIS",
            _ => "DOMAIN_WHOIS",
        };
        out.push((kind, whois.to_owned()));
    }
    // A name server declared in the registry record, not an independently
    // observed DNS response. Only RDAP registration-subject evidence can create
    // this typed element: saved attributes named "ns" from unrelated sources
    // or from a non-registration entity must not be attributed to the registry.
    if matches!(
        entity.kind,
        EntityKind::Domain | EntityKind::IpAddress | EntityKind::Netblock | EntityKind::Asn
    ) && evidence.provenance.source == crate::rdap::SOURCE
    {
        for server in attr("ns").into_iter().flat_map(items) {
            out.push(("PROVIDER_DNS", server.to_owned()));
        }
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
    // Only the OpenPGP collector's person/email subjects establish a PGP public key.
    // Saved evidence attributes alone are not authoritative: an unrelated provider's
    // "fingerprint" may describe a TLS, SSH, device or other non-PGP identity.
    // Preserve the bounded raw source record and its key URL on legitimate findings.
    if let Some(fingerprint) = attr("fingerprint").filter(|_| {
        matches!(entity.kind, EntityKind::Email | EntityKind::Person)
            && evidence.provenance.source == crate::openpgp_keys::SRC
    }) {
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
    // both the blacklisted and the malicious element. A listing that records no abuse of the
    // subject itself (a policy listing of its range, a listing of its network or AS) is
    // blacklisted only; one saved before listings carried a class is read as abuse, as it was.
    if let Some(listing) = attr("dnsbl") {
        let data = format!("{listing} [{host}]");
        if let Some(kind) = blacklisted_type(&entity.kind) {
            out.push((kind, data.clone()));
        }
        let abuse = attr(crate::dnsbl::LISTING_CLASS)
            .is_none_or(|class| class == crate::dnsbl::Class::Abuse.as_str());
        if let Some(kind) = malicious_type(&entity.kind).filter(|_| abuse) {
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
        // element, and the malicious one too when the feed lists threats. A listing on a list
        // that stopped updating says what the list once held, so it is neither: Spiderfoot's
        // correlations read both as a current verdict.
        if attr("threat_feed_stale").is_some_and(positive) {
            return;
        }
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
    /// Each element's index in `out`, by id.
    seen: BTreeMap<String, usize>,
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
        match self.seen.get(&id) {
            None => {
                self.seen.insert(id.clone(), self.out.len());
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
            // A second record of the same source about the same data is the same element, as
            // Spiderfoot keys an event, but it is still a record the operator can read: the
            // element keeps every record, and is created when the earliest was recorded.
            Some(&at) => {
                let element = &mut self.out[at];
                element.created = element.created.min(created);
                if !raw.is_null() {
                    match &mut element.raw {
                        Value::Null => element.raw = raw,
                        Value::Array(records) => records.push(raw),
                        first => {
                            let first = std::mem::take(first);
                            element.raw = Value::Array(vec![first, raw]);
                        }
                    }
                }
            }
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
/// the lowercased identity ([`PivotEdge::from_identity`]) of the first lookup that found it, the
/// key the source entity's own value carries whichever spelling the lookup ran under. That selector's element becomes the
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
        let parent = edge.from_identity().to_ascii_lowercase();
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
    /// Every CVE any record of the scan scores (see [`cvss_scores`]).
    cve_scores: BTreeMap<String, f64>,
    now_unix: u64,
}

impl<'a> Walk<'a> {
    /// The root and the target, with the raw evidence of every entity that names the target.
    fn new(target: Target<'a>, entities: &[Entity], now_unix: u64) -> Self {
        let now_ms = now_unix.saturating_mul(1000);
        let mut builder = Builder {
            out: Vec::new(),
            seen: BTreeMap::new(),
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
        // A crawl's lineage names a lookup by the identity it ran under (`PivotEdge::from_identity`).
        // A username target is also known by its identity key, so what a lookup of the target found
        // stays under the target, never under another element that spells the same handle.
        if target.kind == "USERNAME" {
            by_value.insert(
                crate::recursion::selector_identity(
                    crate::scan_route::ScanKind::Username,
                    target.value.trim(),
                )
                .to_ascii_lowercase(),
                target_id.clone(),
            );
        }
        Self {
            builder,
            target,
            target_id,
            by_value,
            cve_scores: cvss_scores(entities),
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
            for (kind, data) in descriptors(entity, evidence, &self.cve_scores, self.now_unix) {
                if kind == "BGP_AS_MEMBER" && self.target.is_as(&data) {
                    continue;
                }
                said_malicious |= kind.starts_with("MALICIOUS_");
                // Keep the DNSBL classification on its typed blacklist descriptor as well as
                // the parent evidence. Correlation rules consume descriptors, and the target
                // parent can hold records from several providers with different classes.
                let descriptor_raw = if kind.starts_with("BLACKLISTED_") {
                    evidence
                        .attr_values(crate::dnsbl::LISTING_CLASS)
                        .next()
                        .map_or(Value::Null, |class| json!({ "dnsbl_class": class }))
                } else {
                    Value::Null
                };
                self.builder.push(
                    kind,
                    data,
                    Some(&parent),
                    &evidence.provenance.source,
                    confidence(entity),
                    created,
                    Some(&entity.uid),
                    descriptor_raw,
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

    /// A lookup of a username target records its edges under the target's identity key. An echo of
    /// the handle under another separator is its own element with that key, but what the target's
    /// lookup found stays under the target.
    #[test]
    fn findings_of_a_username_target_stay_under_the_target_beside_a_respelled_echo() {
        let echo = entity(EntityKind::Username, "PG-Smith", "github_user", &[]);
        let site = entity(EntityKind::Domain, "pg-smith.example", "github_user", &[]);
        let edges: Vec<PivotEdge> = [&echo, &site]
            .into_iter()
            .map(|to| PivotEdge {
                from_kind: "username".to_owned(),
                from_selector: "PG_Smith".to_owned(),
                to_kind: to.kind.as_str().to_owned(),
                to_value: to.value.clone(),
                generation: 0,
            })
            .collect();
        let target = Target {
            value: "PG_Smith",
            kind: "USERNAME",
        };
        let found = elements_with_lineage(target, &[echo, site], &lineage(&edges), 1_700_000_200);
        let target_element = of_type(&found, "USERNAME")
            .into_iter()
            .find(|element| element.data == "PG_Smith")
            .expect("target element")
            .id
            .clone();
        let site_element = of_type(&found, "INTERNET_NAME")
            .into_iter()
            .find(|element| element.data == "pg-smith.example")
            .expect("site element");
        assert_eq!(
            site_element.source.as_deref(),
            Some(target_element.as_str())
        );
    }

    /// A crawl follows a handle by the spelling it was observed with (`PG_Smith`), while the handle
    /// entity's value is its identity key (`pgsmith`). The discovery tree still places what that
    /// lookup found under the handle's element, not under the scan target.
    #[test]
    fn findings_of_a_handle_followed_by_its_observed_spelling_stay_under_that_handle() {
        let handle = entity(EntityKind::Username, "PG_Smith", "email_cli", &[]);
        let mut site = entity(EntityKind::Domain, "pg-smith.example", "github_user", &[]);
        site.generation = 1;
        let edge = |from_kind: &str, from_selector: &str, to: &Entity, generation| PivotEdge {
            from_kind: from_kind.to_owned(),
            from_selector: from_selector.to_owned(),
            to_kind: to.kind.as_str().to_owned(),
            to_value: to.value.clone(),
            generation,
        };
        let edges = [
            edge("email", "person@example.com", &handle, 0),
            edge("username", "PG_Smith", &site, 1),
        ];
        let lineage = lineage(&edges);
        assert_eq!(
            lineage.get("pg-smith.example").map(String::as_str),
            Some("pgsmith")
        );
        let target = Target {
            value: "person@example.com",
            kind: "EMAILADDR",
        };
        let found = elements_with_lineage(target, &[handle, site], &lineage, 1_700_000_200);
        let handle_element = of_type(&found, "USERNAME")[0].id.clone();
        let site_element = of_type(&found, "INTERNET_NAME")
            .into_iter()
            .find(|element| element.data == "pg-smith.example")
            .expect("site element");
        assert_eq!(
            site_element.source.as_deref(),
            Some(handle_element.as_str())
        );
    }

    /// Two records from one source about one host are one element, as Spiderfoot keys an event,
    /// but both stay readable: the element's raw lists each record, and the element is created
    /// when the earliest was recorded.
    #[test]
    fn a_second_record_from_the_same_source_joins_the_element_instead_of_vanishing() {
        let mut first = Evidence::new(
            EvidenceProvenance::for_scan("crtsh", "scan"),
            "certificate 1",
        )
        .with_attr("unmapped_detail", "v1-first");
        first.provenance.recorded_at_unix = 1_700_000_100;
        let mut second = Evidence::new(
            EvidenceProvenance::for_scan("crtsh", "scan"),
            "certificate 2",
        )
        .with_attr("unmapped_detail", "v2-second");
        second.provenance.recorded_at_unix = 1_700_000_000;
        let host = Entity::builder(EntityKind::Domain, "www.example.com", 0.8, "scan")
            .evidence(first)
            .evidence(second)
            .build();
        let found = elements(DOMAIN, &[host], 1_700_000_200);
        let names: Vec<&DataElement> = of_type(&found, "INTERNET_NAME")
            .into_iter()
            .filter(|element| element.data == "www.example.com")
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        let element = names[0];
        assert_eq!(element.created, 1_700_000_000_000);
        let records = element.raw.as_array().expect("every record of the element");
        assert_eq!(records.len(), 2, "{records:?}");
        let details: Vec<&str> = records
            .iter()
            .map(|record| {
                record["evidence"]["attributes"]["unmapped_detail"]
                    .as_str()
                    .unwrap_or("")
            })
            .collect();
        assert_eq!(details, ["v1-first", "v2-second"]);
        assert_eq!(records[1]["evidence"]["summary"], "certificate 2");
    }

    #[test]
    fn a_lookalike_domain_is_a_similar_domain_not_an_affiliate() {
        let mut lookalike = entity(EntityKind::Domain, "examp1e.com", "dns", &[]);
        lookalike.tag(tags::LOOKALIKE);
        let found = elements(
            DOMAIN,
            &[
                lookalike,
                entity(EntityKind::Domain, "example.net", "robtex", &[]),
            ],
            1_700_000_000,
        );
        assert_eq!(of_type(&found, "SIMILARDOMAIN")[0].data, "examp1e.com");
        assert_eq!(
            of_type(&found, "AFFILIATE_INTERNET_NAME")[0].data,
            "example.net"
        );
    }

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
                ("asn", "AS13335"),
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
        assert_eq!(of_type(&found, "BGP_AS_MEMBER")[0].data, "AS13335");
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

    /// A CVE a record scores is typed by its CVSS score, as Spiderfoot types one, so the
    /// CRITICAL and HIGH vulnerability rules can fire; a score on any record of the scan types
    /// the CVE wherever it is listed, on any host, and one nothing scores stays GENERAL.
    /// The bands meet where Spiderfoot's `cveInfo` puts them, each lower edge in its own band:
    /// 9.0 CRITICAL, 7.0 HIGH, 4.0 MEDIUM, and just below each the band under it. Records that
    /// score one CVE differently type it by the highest, whichever comes first, its id read in
    /// any case; a score outside 0 to 10, or no number, is no score.
    #[test]
    fn a_cves_type_takes_its_band_edges_and_its_highest_valid_score() {
        for (score, typed) in [
            (10.0, "VULNERABILITY_CVE_CRITICAL"),
            (9.0, "VULNERABILITY_CVE_CRITICAL"),
            (8.9, "VULNERABILITY_CVE_HIGH"),
            (7.0, "VULNERABILITY_CVE_HIGH"),
            (6.9, "VULNERABILITY_CVE_MEDIUM"),
            (4.0, "VULNERABILITY_CVE_MEDIUM"),
            (3.9, "VULNERABILITY_CVE_LOW"),
            (0.0, "VULNERABILITY_CVE_LOW"),
        ] {
            assert_eq!(vulnerability_type(Some(score)), typed, "{score}");
        }
        assert_eq!(vulnerability_type(None), "VULNERABILITY_GENERAL");

        let listing = |scores: &str| {
            entity(
                EntityKind::IpAddress,
                "198.51.100.7",
                "shodan",
                &[("cve_scores", scores)],
            )
        };
        for (first, second) in [
            ("CVE-2024-0001 5.0", "cve-2024-0001 9.8"),
            ("cve-2024-0001 9.8", "CVE-2024-0001 5.0"),
        ] {
            let scores = cvss_scores(&[listing(first), listing(second)]);
            assert_eq!(
                scores.get("CVE-2024-0001"),
                Some(&9.8),
                "{first} then {second}"
            );
        }
        let scores = cvss_scores(&[listing(
            "CVE-2024-0002 10.5,CVE-2024-0003 -1,CVE-2024-0004 NaN,CVE-2024-0005 inf,\
             CVE-2024-0006 high,CVE-2024-0007 7.5",
        )]);
        assert_eq!(
            scores.into_iter().collect::<Vec<_>>(),
            [("CVE-2024-0007".to_owned(), 7.5)]
        );
    }

    #[test]
    fn a_scored_vulnerability_is_typed_by_its_cvss_score() {
        let mut ip = entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "shodan",
            &[
                (
                    "vulns",
                    "CVE-2021-44228,CVE-2014-0160,CVE-2020-0001,CVE-2019-0002,CVE-2018-0003",
                ),
                (
                    "cve_scores",
                    "CVE-2021-44228 10.0,CVE-2014-0160 7.5,CVE-2020-0001 5.0,CVE-2019-0002 2.6",
                ),
            ],
        );
        ip.absorb(entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "internetdb",
            &[("vulns", "CVE-2021-44228")],
        ));
        // Another host that only InternetDB lists the CVE on: a score belongs to the CVE, so the
        // scan types it alike there.
        let other = entity(
            EntityKind::IpAddress,
            "198.51.100.8",
            "internetdb",
            &[("vulns", "cve-2021-44228")],
        );
        let found = elements(
            Target {
                value: "198.51.100.7",
                kind: "IP_ADDRESS",
            },
            &[ip, other],
            1_700_000_000,
        );
        let typed = |kind: &str| -> Vec<(String, String)> {
            of_type(&found, kind)
                .iter()
                .map(|element| (element.module.clone(), element.data.clone()))
                .collect()
        };
        assert_eq!(
            typed("VULNERABILITY_CVE_CRITICAL"),
            [
                ("shodan".to_owned(), "CVE-2021-44228".to_owned()),
                ("internetdb".to_owned(), "CVE-2021-44228".to_owned()),
                ("internetdb".to_owned(), "cve-2021-44228".to_owned()),
            ]
        );
        assert_eq!(
            typed("VULNERABILITY_CVE_HIGH"),
            [("shodan".to_owned(), "CVE-2014-0160".to_owned())]
        );
        assert_eq!(
            typed("VULNERABILITY_CVE_MEDIUM"),
            [("shodan".to_owned(), "CVE-2020-0001".to_owned())]
        );
        assert_eq!(
            typed("VULNERABILITY_CVE_LOW"),
            [("shodan".to_owned(), "CVE-2019-0002".to_owned())]
        );
        assert_eq!(
            typed("VULNERABILITY_GENERAL"),
            [("shodan".to_owned(), "CVE-2018-0003".to_owned())]
        );
        // So the shipped CRITICAL and HIGH rules fire on the host; with every CVE GENERAL, neither
        // could.
        let rules: Vec<_> = crate::sf_correlate::shipped()
            .iter()
            .filter(|rule| {
                matches!(
                    rule.id.as_str(),
                    "vulnerability_critical" | "vulnerability_high"
                )
            })
            .cloned()
            .collect();
        let mut fired: Vec<String> = crate::sf_correlate::run(&rules, &found)
            .into_iter()
            .map(|finding| finding.title)
            .collect();
        fired.sort();
        assert_eq!(
            fired,
            [
                "Critical-rated vulnerability found on 198.51.100.7",
                "Critical-rated vulnerability found on 198.51.100.8",
                "High-rated vulnerability found on 198.51.100.7",
            ]
        );
        assert_eq!(vulnerability_type(Some(9.0)), "VULNERABILITY_CVE_CRITICAL");
        assert_eq!(vulnerability_type(Some(8.9)), "VULNERABILITY_CVE_HIGH");
        assert_eq!(vulnerability_type(Some(6.9)), "VULNERABILITY_CVE_MEDIUM");
        assert_eq!(vulnerability_type(Some(3.9)), "VULNERABILITY_CVE_LOW");
        assert_eq!(vulnerability_type(Some(0.0)), "VULNERABILITY_CVE_LOW");
    }

    #[test]
    fn only_a_public_as_number_is_an_as_the_host_belongs_to() {
        // RIPEstat's `origin_asns` keeps a reserved origin on the record; it is no member AS,
        // and a bare number is written as an ASN entity is.
        let ripestat = entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "ripestat",
            &[(
                "origin_asns",
                "AS64512,AS13335,AS0,AS23456,ASN8075,AS 3356,AS+174",
            )],
        );
        let shodan = entity(
            EntityKind::IpAddress,
            "198.51.100.8",
            "shodan",
            &[("asn", "AS64500,15169")],
        );
        let found = elements(
            Target {
                value: "198.51.100.7",
                kind: "IP_ADDRESS",
            },
            &[ripestat, shodan],
            1_700_000_000,
        );
        let members: Vec<&str> = of_type(&found, "BGP_AS_MEMBER")
            .iter()
            .map(|element| element.data.as_str())
            .collect();
        assert_eq!(members, ["AS13335", "AS8075", "AS3356", "AS15169"]);
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
    fn pgp_key_rejects_unrelated_fingerprints_but_preserves_key_holder() {
        let fingerprint = "8F17777118A33DDA9BA48E62AACB3243630052D9";
        let forged = entity(
            EntityKind::Email,
            "unrelated@example.org",
            "gravatar",
            &[("fingerprint", fingerprint)],
        );
        let wrong_kind = entity(
            EntityKind::Domain,
            "example.org",
            crate::openpgp_keys::SRC,
            &[("fingerprint", fingerprint)],
        );
        let found = elements(
            Target {
                value: "example.org",
                kind: "DOMAIN_NAME",
            },
            &[forged, wrong_kind],
            1_700_000_000,
        );
        assert!(of_type(&found, "PGP_KEY").is_empty());

        // The collector also emits the verified holder as a Person with the same evidence.
        let holder = entity(
            EntityKind::Person,
            "Neal H. Walfield",
            crate::openpgp_keys::SRC,
            &[("fingerprint", fingerprint)],
        );
        let found = elements(
            Target {
                value: "Neal H. Walfield",
                kind: "HUMAN_NAME",
            },
            &[holder],
            1_700_000_000,
        );
        assert_eq!(of_type(&found, "PGP_KEY")[0].data, fingerprint);
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
    fn only_rdap_registration_subjects_create_provider_dns_elements() {
        // A saved same-named field from another provider does not independently
        // establish the registry's list of name servers.
        let unrelated_source = entity(
            EntityKind::Domain,
            "example.com",
            "crtsh",
            &[("ns", "ns1.example.net")],
        );
        // An unrelated kind does not become a registered domain merely because
        // an evidence record uses the RDAP source identifier.
        let unrelated_kind = entity(
            EntityKind::Email,
            "hello@example.com",
            "rdap",
            &[("ns", "ns2.example.net")],
        );
        let found = elements(DOMAIN, &[unrelated_source, unrelated_kind], 1_700_000_000);
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
    fn a_pulsedive_http_server_becomes_a_webserver_banner_element() {
        // `pulsedive` (keyless) writes `http_server` on the IP or domain it observed.
        let host = entity(
            EntityKind::IpAddress,
            "203.0.113.10",
            "pulsedive",
            &[("http_server", "cloudflare")],
        );
        let found = elements(DOMAIN, &[host], 1_700_000_000);
        assert_eq!(of_type(&found, "WEBSERVER_BANNER")[0].data, "cloudflare");

        // A host with no server banner produces no WEBSERVER_BANNER element.
        let bare = entity(EntityKind::IpAddress, "203.0.113.11", "pulsedive", &[]);
        let found = elements(DOMAIN, &[bare], 1_700_000_000);
        assert!(of_type(&found, "WEBSERVER_BANNER").is_empty());

        // Neither another provider's attribute nor another entity kind establishes a banner,
        // even when the field name matches.
        let other_source = entity(
            EntityKind::IpAddress,
            "203.0.113.10",
            "shodan",
            &[("http_server", "cloudflare")],
        );
        let other_kind = entity(
            EntityKind::Email,
            "root@example.com",
            "pulsedive",
            &[("http_server", "cloudflare")],
        );
        let found = elements(DOMAIN, &[other_source, other_kind], 1_700_000_000);
        assert!(of_type(&found, "WEBSERVER_BANNER").is_empty());
    }

    #[test]
    fn a_pulsedive_http_status_becomes_an_http_code_element() {
        // `pulsedive` (keyless) writes `http_status` on the IP or domain it probed.
        let host = entity(
            EntityKind::Domain,
            "example.com",
            "pulsedive",
            &[("http_status", "200")],
        );
        let found = elements(DOMAIN, &[host], 1_700_000_000);
        assert_eq!(of_type(&found, "HTTP_CODE")[0].data, "200");

        // A host with no status produces no HTTP_CODE element.
        let bare = entity(EntityKind::Domain, "bare.example", "pulsedive", &[]);
        let found = elements(DOMAIN, &[bare], 1_700_000_000);
        assert!(of_type(&found, "HTTP_CODE").is_empty());

        // A malformed value, another provider's attribute, and another entity kind each produce
        // nothing, even when the field name matches.
        let malformed = entity(
            EntityKind::Domain,
            "example.com",
            "pulsedive",
            &[("http_status", "99999")],
        );
        let other_source = entity(
            EntityKind::Domain,
            "example.com",
            "wayback",
            &[("http_status", "200")],
        );
        let other_kind = entity(
            EntityKind::Email,
            "root@example.com",
            "pulsedive",
            &[("http_status", "200")],
        );
        let found = elements(
            DOMAIN,
            &[malformed, other_source, other_kind],
            1_700_000_000,
        );
        assert!(of_type(&found, "HTTP_CODE").is_empty());

        assert!(valid_http_status("200"));
        assert!(valid_http_status("404"));
        assert!(valid_http_status("599"));
        for invalid in ["", "20", "2000", "099", "600", "abc", "2x0"] {
            assert!(!valid_http_status(invalid), "{invalid}");
        }
    }

    #[test]
    fn an_isp_from_a_reputation_source_becomes_a_provider_hosting_element() {
        // Every IP-reputation/geo source writes the hosting org as `isp`; each produces one
        // PROVIDER_HOSTING element, whether the seed was an IP or the domain that resolved to it.
        for (kind, source) in [
            (EntityKind::IpAddress, "pulsedive"),
            (EntityKind::Domain, "pulsedive"),
            (EntityKind::IpAddress, "ipqs"),
            (EntityKind::IpAddress, "shodan"),
            (EntityKind::IpAddress, "abuseipdb"),
        ] {
            let host = entity(kind, "198.51.100.7", source, &[("isp", "Cloudflare, Inc.")]);
            let found = elements(DOMAIN, &[host], 1_700_000_000);
            assert_eq!(
                of_type(&found, "PROVIDER_HOSTING")[0].data,
                "Cloudflare, Inc.",
                "{source}"
            );
        }

        // No isp attribute, and an isp from a source that does not report hosting, each produce
        // nothing — the latter proving the source gate.
        let bare = entity(EntityKind::IpAddress, "198.51.100.8", "pulsedive", &[]);
        let other_source = entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "rdap",
            &[("isp", "Cloudflare, Inc.")],
        );
        let found = elements(DOMAIN, &[bare, other_source], 1_700_000_000);
        assert!(of_type(&found, "PROVIDER_HOSTING").is_empty());
    }

    #[test]
    fn mnemonic_passive_dns_becomes_a_raw_dns_records_element() {
        // The keyless `mnemonic` passive-DNS lookup writes `passive_dns` on the queried domain or
        // IP as one pipe-delimited dump; it is surfaced whole as a single RAW_DNS_RECORDS element.
        let dump = "example.com A 203.0.113.10 | example.com MX 10 mail.example.com";
        for kind in [EntityKind::Domain, EntityKind::IpAddress] {
            let label = format!("{kind:?}");
            let host = entity(kind, "example.com", "mnemonic", &[("passive_dns", dump)]);
            let found = elements(DOMAIN, &[host], 1_700_000_000);
            let records = of_type(&found, "RAW_DNS_RECORDS");
            assert_eq!(records.len(), 1, "{label}");
            assert_eq!(records[0].data, dump, "{label}");
        }

        // Neither another source's same-named attribute nor another entity kind establishes a
        // record set, and a host with no passive-DNS dump produces nothing.
        let other_source = entity(
            EntityKind::Domain,
            "example.com",
            "otx",
            &[("passive_dns", dump)],
        );
        let other_kind = entity(
            EntityKind::Email,
            "root@example.com",
            "mnemonic",
            &[("passive_dns", dump)],
        );
        let bare = entity(EntityKind::Domain, "bare.example", "mnemonic", &[]);
        let found = elements(DOMAIN, &[other_source, other_kind, bare], 1_700_000_000);
        assert!(of_type(&found, "RAW_DNS_RECORDS").is_empty());
    }

    #[test]
    fn whois_contact_emails_become_generic_email_elements() {
        // netlas writes abuse + registrar contact emails; isc writes an abuse contact.
        let netlas = entity(
            EntityKind::Domain,
            "example.com",
            "netlas",
            &[
                ("abuse_email", "abuse@example.net"),
                ("registrar_email", "registrar@example.org"),
            ],
        );
        let found = elements(DOMAIN, &[netlas], 1_700_000_000);
        let mut generic: Vec<&str> = of_type(&found, "EMAILADDR_GENERIC")
            .iter()
            .map(|e| e.data.as_str())
            .collect();
        generic.sort_unstable();
        assert_eq!(generic, ["abuse@example.net", "registrar@example.org"]);

        let isc = entity(
            EntityKind::IpAddress,
            "198.51.100.7",
            "isc",
            &[("abuse_contact", "soc@example.com")],
        );
        let found = elements(DOMAIN, &[isc], 1_700_000_000);
        assert_eq!(
            of_type(&found, "EMAILADDR_GENERIC")[0].data,
            "soc@example.com"
        );

        // A source that does not publish a contact email, and a malformed value, each produce
        // nothing — the former proving the source gate, the latter the address validation.
        let other_source = entity(
            EntityKind::Domain,
            "example.com",
            "rdap",
            &[("abuse_email", "abuse@example.net")],
        );
        let malformed = entity(
            EntityKind::Domain,
            "example.com",
            "netlas",
            &[("abuse_email", "not-an-email")],
        );
        let found = elements(DOMAIN, &[other_source, malformed], 1_700_000_000);
        assert!(of_type(&found, "EMAILADDR_GENERIC").is_empty());
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
            "EMAILADDR_GENERIC",
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
            "WEBSERVER_BANNER",
            "HTTP_CODE",
            "RAW_DNS_RECORDS",
            "OPERATING_SYSTEM",
            "BGP_AS_MEMBER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "GEOINFO",
            "PROVIDER_HOSTING",
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
