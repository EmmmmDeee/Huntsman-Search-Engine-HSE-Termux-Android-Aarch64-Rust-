//! `VirusTotal` v3 reputation for one domain or IP (free key: 4 lookups a minute, 500 a day).
//!
//! One lookup is one `GET https://www.virustotal.com/api/v3/domains/{domain}` or
//! `.../ip_addresses/{ip}` with the key in the `x-apikey` header. It runs only when
//! `HUNTSMAN_VIRUSTOTAL_KEY` is set. Everything the answer holds is kept: the last analysis
//! verdict counts and each engine that flagged it, the community reputation and votes, every
//! category, tag and popularity rank, the WHOIS text line by line, the last DNS records (their
//! addresses and host names are pivots), the last HTTPS certificate (its names are pivots), the
//! crowd-sourced context, every date, the registry context (registrar and creation date for a
//! domain; AS number, AS owner, network, country, continent and RIR for an address), and the
//! whole answer as JSON. A `404` `NotFoundError` is "`VirusTotal` has no object for it", a valid
//! zero. An answer must be the looked-up object (its `id` names the domain or address) and carry
//! `last_analysis_stats`; one that does not is drift, never "0 of 0 engines flag it".

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::keys::Keys;

pub const SOURCE: &str = "virustotal";
pub const KEY_SLOT: &str = crate::environment::VIRUSTOTAL_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "virustotal.com",
    origin: "https://www.virustotal.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("x-apikey"),
        required: true,
    }),
};
/// What a lookup is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Domain,
    Ip,
}

/// `VirusTotal`'s report on one object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub reputation: i64,
    /// Distinct category labels the engines give it, sorted.
    pub categories: Vec<String>,
    pub registrar: Option<String>,
    /// Unix seconds.
    pub creation_date: Option<i64>,
    pub asn: Option<u32>,
    pub as_owner: Option<String>,
    pub network: Option<String>,
    pub country: Option<String>,
    /// Everything else the answer says, as `(attribute, value)` pairs in answer order; a name
    /// that repeats is a list.
    pub details: Vec<(String, String)>,
    /// The addresses the domain's last DNS records resolve to, as written.
    pub addresses: Vec<String>,
    /// The host names the answer names, each with the record type or `certificate` that names
    /// it: lower case, no root dot, a wildcard's `*.` dropped, an address left out.
    pub hosts: Vec<(String, String)>,
    /// The whole answer as compact JSON.
    pub raw_answer: String,
}

impl Report {
    /// Engines that flagged it malicious or suspicious.
    #[must_use]
    pub const fn flagged(&self) -> u32 {
        self.malicious.saturating_add(self.suspicious)
    }
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    attributes: Attributes,
}

#[derive(Deserialize)]
struct Attributes {
    last_analysis_stats: Stats,
    #[serde(default)]
    reputation: i64,
    #[serde(default)]
    categories: BTreeMap<String, String>,
    #[serde(default)]
    registrar: Option<String>,
    #[serde(default)]
    creation_date: Option<i64>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize, Default)]
struct Stats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    undetected: u32,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
}

/// The request URL for `value`. **Pure.**
#[must_use]
pub fn url(object: Object, value: &str) -> String {
    let collection = match object {
        Object::Domain => "domains",
        Object::Ip => "ip_addresses",
    };
    format!(
        "https://www.virustotal.com/api/v3/{collection}/{}",
        percent_encode_component(value)
    )
}

/// Look `value` up. `Ok(None)` is "no such object".
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no key is configured; otherwise the
/// [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    object: Object,
    value: &str,
    now_unix: u64,
) -> Result<Option<Report>, LegError> {
    decode(
        api_leg::get(transport, &API, keys, &url(object, value), now_unix)?,
        object,
        value,
    )
}

/// Whether the object `id` `VirusTotal` answered about is `value`: the same domain in any case,
/// or the same address however it is written. **Pure.**
fn is_about(id: &str, object: Object, value: &str) -> bool {
    match object {
        Object::Domain => id.eq_ignore_ascii_case(value),
        Object::Ip => crate::canonical::same_ip(id, value),
    }
}

/// One answer as a report on the `object` `value`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape, is another object type, or
/// is about another domain or address.
pub fn decode(answer: Answer, object: Object, value: &str) -> Result<Option<Report>, LegError> {
    let body = match answer {
        Answer::NotFound(body) => {
            let error: ErrorEnvelope = api_leg::decode(&body)?;
            return if error.error.code == "NotFoundError" {
                Ok(None)
            } else {
                Err(LegError::Decode("404 without NotFoundError".into()))
            };
        }
        Answer::Body(body) => body,
    };
    let data = api_leg::decode::<Envelope>(&body)?.data;
    let expected = match object {
        Object::Domain => "domain",
        Object::Ip => "ip_address",
    };
    if data.kind != expected {
        return Err(LegError::Decode("answer is another object type".into()));
    }
    if !is_about(&data.id, object, value) {
        return Err(LegError::Decode("answer is about another object".into()));
    }
    let whole: Value = api_leg::decode(&body)?;
    let a = data.attributes;
    let mut categories: Vec<String> = a
        .categories
        .values()
        .filter_map(|c| api_leg::clean(Some(c)))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    categories.sort();
    categories.dedup();
    let mut read = ReadOut::default();
    if let Some(attributes) = whole
        .get("data")
        .and_then(|data| data.get("attributes"))
        .and_then(Value::as_object)
    {
        read.attributes(attributes);
    }
    Ok(Some(Report {
        malicious: a.last_analysis_stats.malicious,
        suspicious: a.last_analysis_stats.suspicious,
        harmless: a.last_analysis_stats.harmless,
        undetected: a.last_analysis_stats.undetected,
        reputation: a.reputation,
        categories,
        registrar: api_leg::clean(a.registrar.as_deref()),
        creation_date: a.creation_date,
        asn: a.asn,
        as_owner: api_leg::clean(a.as_owner.as_deref()),
        network: api_leg::clean(a.network.as_deref()),
        country: api_leg::clean(a.country.as_deref()),
        details: read.details,
        addresses: read.addresses,
        hosts: read.hosts,
        raw_answer: whole.to_string(),
    }))
}

/// The top-level attributes a [`Report`] field holds; the read-out skips them.
const REPORT_FIELDS: [&str; 7] = [
    "reputation",
    "registrar",
    "creation_date",
    "asn",
    "as_owner",
    "network",
    "country",
];

/// The DNS record types whose value is a host name.
const HOST_RECORDS: [&str; 5] = ["NS", "MX", "CNAME", "PTR", "SOA"];

/// The members of a DNS record after its type, in the order a zone file writes them.
const RECORD_MEMBERS: [&str; 10] = [
    "flag", "tag", "priority", "value", "rname", "serial", "refresh", "retry", "expire", "minimum",
];

/// What the answer's `attributes` say beyond the [`Report`] fields.
#[derive(Default)]
struct ReadOut {
    details: Vec<(String, String)>,
    addresses: Vec<String>,
    hosts: Vec<(String, String)>,
}

impl ReadOut {
    fn push(&mut self, name: impl Into<String>, value: Option<String>) {
        if let Some(value) = value {
            self.details.push((name.into(), value));
        }
    }

    fn host(&mut self, role: &str, name: &str) {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let name = name.strip_prefix("*.").unwrap_or(&name).to_owned();
        let entry = (role.to_ascii_lowercase(), name);
        // A certificate can name an address; that is not a host name to pivot on.
        if entry.1.is_empty() || entry.1.parse::<IpAddr>().is_ok() {
            return;
        }
        if !self.hosts.contains(&entry) {
            self.hosts.push(entry);
        }
    }

    /// Every attribute: the shapes `VirusTotal` documents read out by name, any other scalar as
    /// itself (a `*_date` as `*_date_unix`), any other object's scalar members as
    /// `{name}_{member}`, any other list's scalars as `{name}`. Deeper values stay in
    /// `raw_answer`.
    fn attributes(&mut self, attributes: &Map<String, Value>) {
        for (name, value) in attributes {
            match (name.as_str(), value) {
                (field, _) if REPORT_FIELDS.contains(&field) => {}
                ("last_analysis_stats", Value::Object(stats)) => {
                    for (verdict, count) in stats {
                        if !matches!(verdict.as_str(), "malicious" | "suspicious") {
                            self.push(verdict.replace('-', "_"), api_leg::scalar(count));
                        }
                    }
                }
                ("last_analysis_results", Value::Object(engines)) => self.engines(engines),
                ("categories", Value::Object(by_engine)) => {
                    for (engine, label) in by_engine {
                        let label =
                            api_leg::scalar(label).map(|label| format!("{engine}: {label}"));
                        self.push("categories_by_engine", label);
                    }
                }
                ("popularity_ranks", Value::Object(ranks)) => {
                    for (list, entry) in ranks {
                        let rank = entry.get("rank").and_then(api_leg::scalar);
                        self.push(
                            "popularity_ranks",
                            rank.map(|rank| format!("{list} {rank}")),
                        );
                    }
                }
                ("whois", Value::String(text)) => {
                    for line in text.lines() {
                        self.push("whois", api_leg::clean(Some(line)));
                    }
                }
                ("last_dns_records", Value::Array(records)) => {
                    for record in records {
                        self.dns_record(record);
                    }
                }
                ("last_https_certificate", Value::Object(certificate)) => {
                    self.certificate(certificate);
                }
                ("crowdsourced_context", Value::Array(items)) => {
                    for item in items {
                        let parts: Vec<String> = ["source", "title", "severity", "details"]
                            .iter()
                            .filter_map(|member| item.get(*member).and_then(api_leg::scalar))
                            .collect();
                        let line = (!parts.is_empty()).then(|| parts.join(" | "));
                        self.push("crowdsourced_context", line);
                    }
                }
                (_, Value::Object(members)) => {
                    for (member, value) in members {
                        self.push(format!("{name}_{member}"), api_leg::scalar(value));
                    }
                }
                (_, Value::Array(items)) => {
                    for item in items {
                        self.push(name.as_str(), api_leg::scalar(item));
                    }
                }
                (_, Value::Number(_)) if name.ends_with("_date") => {
                    self.push(format!("{name}_unix"), api_leg::scalar(value));
                }
                _ => self.push(name.as_str(), api_leg::scalar(value)),
            }
        }
    }

    /// Each engine that called it malicious or suspicious, with what it called it.
    fn engines(&mut self, engines: &Map<String, Value>) {
        for (engine, verdict) in engines {
            let category = verdict.get("category").and_then(Value::as_str);
            if matches!(category, Some("malicious" | "suspicious")) {
                let said = verdict
                    .get("result")
                    .and_then(api_leg::scalar)
                    .or_else(|| category.map(str::to_owned));
                self.push("flagged_by", said.map(|said| format!("{engine}: {said}")));
            }
        }
    }

    /// One of the last DNS records as a zone file writes it, `MX 10 mail.example.com ttl 300`;
    /// an address is kept for a pivot and a host name with its record type.
    fn dns_record(&mut self, record: &Value) {
        let Some(kind) = record.get("type").and_then(Value::as_str) else {
            return;
        };
        let mut line = vec![kind.to_owned()];
        line.extend(
            RECORD_MEMBERS
                .iter()
                .filter_map(|member| record.get(*member).and_then(api_leg::scalar)),
        );
        if let Some(ttl) = record.get("ttl").and_then(api_leg::scalar) {
            line.push(format!("ttl {ttl}"));
        }
        self.push("dns_records", Some(line.join(" ")));
        let Some(target) = record.get("value").and_then(Value::as_str) else {
            return;
        };
        if matches!(kind, "A" | "AAAA") {
            let address = target.trim().to_owned();
            if !self.addresses.contains(&address) {
                self.addresses.push(address);
            }
        } else if HOST_RECORDS.contains(&kind) {
            self.host(kind, target);
        }
    }

    /// The last HTTPS certificate: subject, issuer, validity, serial, digests, signature
    /// algorithm and every name, each name a host.
    fn certificate(&mut self, certificate: &Map<String, Value>) {
        for (field, name) in [("subject", "subject"), ("issuer", "issuer")] {
            let line = certificate
                .get(field)
                .and_then(Value::as_object)
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|(key, value)| {
                            api_leg::scalar(value).map(|value| format!("{key}={value}"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                });
            self.push(
                format!("certificate_{name}"),
                line.filter(|l| !l.is_empty()),
            );
        }
        let validity = certificate.get("validity");
        for bound in ["not_before", "not_after"] {
            let at = validity
                .and_then(|v| v.get(bound))
                .and_then(api_leg::scalar);
            self.push(format!("certificate_{bound}"), at);
        }
        for (field, name) in [
            ("serial_number", "serial"),
            ("thumbprint", "sha1"),
            ("thumbprint_sha256", "sha256"),
            ("signature_algorithm", "signature_algorithm"),
        ] {
            self.push(
                format!("certificate_{name}"),
                certificate.get(field).and_then(api_leg::scalar),
            );
        }
        let common_name = certificate
            .get("subject")
            .and_then(|subject| subject.get("CN"))
            .and_then(Value::as_str);
        let alternative = certificate
            .get("extensions")
            .and_then(|extensions| extensions.get("subject_alternative_name"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        let mut seen = Vec::new();
        for name in common_name.into_iter().chain(alternative) {
            if !seen.contains(&name) {
                seen.push(name);
                self.push("certificate_names", api_leg::clean(Some(name)));
                self.host("certificate", name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped as the v3 `domains/{domain}` object of the `VirusTotal` API reference.
    const DOMAIN: &str = r#"{"data":{"id":"example.com","type":"domain","links":{"self":"https://www.virustotal.com/api/v3/domains/example.com"},"attributes":{"last_analysis_stats":{"harmless":66,"malicious":2,"suspicious":1,"undetected":24,"timeout":0},"reputation":-3,"registrar":"RESERVED-Internet Assigned Numbers Authority","creation_date":808372800,"categories":{"Forcepoint ThreatSeeker":"Reference Materials","BitDefender":"computersandsoftware","Sophos":"reference materials"},"tags":[]}}}"#;
    /// Shaped as the v3 `ip_addresses/{ip}` object.
    const IP: &str = r#"{"data":{"id":"1.1.1.1","type":"ip_address","attributes":{"last_analysis_stats":{"harmless":60,"malicious":0,"suspicious":0,"undetected":30},"reputation":20,"asn":13335,"as_owner":"CLOUDFLARENET","network":"1.1.1.0/24","country":"AU"}}}"#;

    #[test]
    fn a_domain_report_keeps_verdicts_registrar_and_categories() {
        let report = decode(Answer::Body(DOMAIN.into()), Object::Domain, "example.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("domain body must decode"));
        assert_eq!(report.malicious, 2);
        assert_eq!(report.flagged(), 3);
        assert_eq!(report.reputation, -3);
        assert_eq!(report.creation_date, Some(808_372_800));
        assert_eq!(
            report.categories,
            ["computersandsoftware", "reference materials"]
        );
    }

    /// The details named `name`, in answer order.
    fn detail<'a>(report: &'a Report, name: &str) -> Vec<&'a str> {
        report
            .details
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    #[test]
    fn every_documented_attribute_is_read_out_and_the_answer_kept_whole() {
        let body = r#"{"data":{"id":"example.com","type":"domain","attributes":{
            "last_analysis_stats":{"harmless":66,"malicious":1,"suspicious":1,"undetected":24,"timeout":2,"type-unsupported":3},
            "last_analysis_results":{"Kaspersky":{"category":"malicious","engine_name":"Kaspersky","method":"blacklist","result":"phishing"},"Sophos":{"category":"suspicious","result":null},"Google Safebrowsing":{"category":"harmless","result":"clean"}},
            "categories":{"a":"one","b":"two","c":"three","d":"four","e":"five","f":"six","g":"seven","h":"eight","i":"nine"},
            "popularity_ranks":{"Tranco":{"rank":122,"timestamp":1760000000}},
            "total_votes":{"harmless":12,"malicious":3},
            "tags":["parking","dga"],
            "whois":"Domain Name: EXAMPLE.COM\nName Server: A.IANA-SERVERS.NET\n",
            "last_dns_records":[{"type":"A","value":"93.184.215.14","ttl":300},{"type":"MX","priority":10,"value":"MX.Example.NET.","ttl":300},{"type":"TXT","value":"v=spf1 -all","ttl":60},{"type":"SOA","value":"ns.icann.org","rname":"noc.dns.icann.org","serial":2025011500,"ttl":3600}],
            "last_https_certificate":{"subject":{"CN":"www.example.org"},"issuer":{"C":"US","O":"DigiCert Inc"},"validity":{"not_after":"2025-03-01 23:59:59","not_before":"2024-01-30 00:00:00"},"serial_number":"075bcef3","thumbprint":"4da25a6d","thumbprint_sha256":"455943cf","extensions":{"subject_alternative_name":["www.example.org","*.example.edu"]}},
            "crowdsourced_context":[{"source":"ArcSight Threat Intelligence","title":"Phishing kit host","severity":"high","details":"seen in a lure","timestamp":1760000000}],
            "favicon":{"dhash":"71cc969aa2b28e71","raw_md5":"84c9"},
            "rdap":{"handle":"2336799_DOMAIN_COM-VRSN","events":[{"event_action":"registration"}]},
            "jarm":"29d29d00029d29d00042d43d00041d","tld":"com","last_analysis_date":1760000123,
            "reputation":-3,"creation_date":808372800}}}"#;
        let report = decode(Answer::Body(body.into()), Object::Domain, "example.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("domain body must decode"));
        assert_eq!(report.categories.len(), 9, "{:?}", report.categories);
        assert_eq!(
            detail(&report, "flagged_by"),
            ["Kaspersky: phishing", "Sophos: suspicious"]
        );
        assert_eq!(detail(&report, "timeout"), ["2"]);
        assert_eq!(detail(&report, "type_unsupported"), ["3"]);
        assert_eq!(detail(&report, "malicious"), Vec::<&str>::new());
        assert_eq!(detail(&report, "popularity_ranks"), ["Tranco 122"]);
        assert_eq!(detail(&report, "total_votes_malicious"), ["3"]);
        assert_eq!(detail(&report, "tags"), ["parking", "dga"]);
        assert_eq!(
            detail(&report, "whois"),
            [
                "Domain Name: EXAMPLE.COM",
                "Name Server: A.IANA-SERVERS.NET"
            ]
        );
        assert_eq!(
            detail(&report, "dns_records"),
            [
                "A 93.184.215.14 ttl 300",
                "MX 10 MX.Example.NET. ttl 300",
                "TXT v=spf1 -all ttl 60",
                "SOA ns.icann.org noc.dns.icann.org 2025011500 ttl 3600"
            ]
        );
        assert_eq!(report.addresses, ["93.184.215.14"]);
        let hosts: Vec<(&str, &str)> = report
            .hosts
            .iter()
            .map(|(role, name)| (role.as_str(), name.as_str()))
            .collect();
        assert_eq!(
            hosts,
            [
                ("mx", "mx.example.net"),
                ("soa", "ns.icann.org"),
                ("certificate", "www.example.org"),
                ("certificate", "example.edu")
            ]
        );
        assert_eq!(
            detail(&report, "certificate_names"),
            ["www.example.org", "*.example.edu"]
        );
        assert_eq!(
            detail(&report, "certificate_issuer"),
            ["C=US, O=DigiCert Inc"]
        );
        assert_eq!(
            detail(&report, "certificate_not_after"),
            ["2025-03-01 23:59:59"]
        );
        assert_eq!(detail(&report, "certificate_sha256"), ["455943cf"]);
        assert_eq!(
            detail(&report, "crowdsourced_context"),
            ["ArcSight Threat Intelligence | Phishing kit host | high | seen in a lure"]
        );
        assert_eq!(detail(&report, "favicon_dhash"), ["71cc969aa2b28e71"]);
        assert_eq!(detail(&report, "rdap_handle"), ["2336799_DOMAIN_COM-VRSN"]);
        assert_eq!(detail(&report, "last_analysis_date_unix"), ["1760000123"]);
        assert_eq!(detail(&report, "jarm"), ["29d29d00029d29d00042d43d00041d"]);
        // A value a report field holds is not read out twice.
        assert_eq!(detail(&report, "reputation"), Vec::<&str>::new());
        assert_eq!(detail(&report, "creation_date_unix"), Vec::<&str>::new());
        let raw: Value = serde_json::from_str(&report.raw_answer)
            .unwrap_or_else(|e| panic!("raw answer is JSON: {e}"));
        assert_eq!(
            raw["data"]["attributes"]["rdap"]["events"][0]["event_action"],
            "registration"
        );
    }

    #[test]
    fn an_ip_report_keeps_its_network_context() {
        let report = decode(Answer::Body(IP.into()), Object::Ip, "1.1.1.1")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("ip body must decode"));
        assert_eq!(report.asn, Some(13335));
        assert_eq!(report.network.as_deref(), Some("1.1.1.0/24"));
        assert_eq!(report.flagged(), 0);
    }

    #[test]
    fn a_report_on_another_object_type_is_refused() {
        assert!(decode(Answer::Body(IP.into()), Object::Domain, "1.1.1.1").is_err());
    }

    #[test]
    fn not_found_error_is_a_valid_zero_and_other_404s_are_not() {
        let missing =
            r#"{"error":{"code":"NotFoundError","message":"Domain \"x.invalid\" not found"}}"#;
        assert_eq!(
            decode(
                Answer::NotFound(missing.into()),
                Object::Domain,
                "x.invalid"
            ),
            Ok(None)
        );
        let other = r#"{"error":{"code":"WrongCredentialsError","message":"x"}}"#;
        assert!(decode(Answer::NotFound(other.into()), Object::Domain, "x.invalid").is_err());
    }

    /// `lookup` with a configured key, answered by `body`.
    fn looked_up(object: Object, value: &str, body: &str) -> Result<Option<Report>, LegError> {
        let keys = Keys::parse(&format!("{KEY_SLOT}=virustotal-test-key\n"))
            .unwrap_or_else(|e| panic!("keys: {e}"));
        let transport = crate::test_support::OneResponse::json(200, body);
        lookup(&transport, &keys, object, value, 1)
    }

    #[test]
    fn a_report_on_another_object_or_without_verdicts_is_drift_not_a_clean_verdict() {
        for (object, value, body) in [
            (Object::Domain, "example.org", DOMAIN),
            (Object::Ip, "8.8.8.8", IP),
            (
                Object::Domain,
                "example.com",
                r#"{"data":{"id":"example.com","type":"domain","attributes":{}}}"#,
            ),
            (
                Object::Ip,
                "1.1.1.1",
                r#"{"data":{"type":"ip_address","attributes":{"last_analysis_stats":{"malicious":0}}}}"#,
            ),
        ] {
            let got = looked_up(object, value, body);
            assert!(
                matches!(got, Err(LegError::Decode(_))),
                "{object:?} {value}: {got:?}"
            );
        }
        // The same address written in full, and the same domain in another case, are the subject.
        let full = r#"{"data":{"id":"2606:4700:4700:0:0:0:0:1111","type":"ip_address","attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":61,"undetected":29}}}}"#;
        assert!(matches!(
            looked_up(Object::Ip, "2606:4700:4700::1111", full),
            Ok(Some(_))
        ));
        assert!(matches!(
            looked_up(Object::Domain, "EXAMPLE.com", DOMAIN),
            Ok(Some(_))
        ));
    }
}
