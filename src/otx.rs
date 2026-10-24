//! `AlienVault` OTX: the community threat pulses that name one IP or domain.
//!
//! One lookup is one `GET https://otx.alienvault.com/api/v1/indicators/{IPv4|IPv6|domain}/{value}/general`.
//! OTX answers without a key; with `HUNTSMAN_OTX_KEY` set the key goes in the `X-OTX-API-KEY`
//! header and the account's limit applies. OTX answers an indicator it has never seen with `200`
//! and a `pulse_info` whose count is 0, and gives a 404 only for a path it does not have (both
//! checked 2026-10-15): an answer without `pulse_info`, and a 404, are drift.
//!
//! Everything in the answer is kept. Each pulse OTX lists is kept whole as JSON in `raw_pulses`,
//! and the rest of the answer in `raw_general`. Read out of them, across every pulse: the names,
//! ids, authors, TLP, tags, references, targeted countries and industries, ATT&CK techniques,
//! malware families and adversaries, and the first and last pulse; OTX's validations and
//! false-positive assessments; and for an address its reputation, place, position and AS. An
//! answer with no pulse, validation, false positive, AS or place is a valid zero.
//!
//! The position is an entity only when OTX names its city: without one it is the country's
//! centre (`37.751,-97.822` for every unplaced US address), which would tie unrelated addresses
//! together. It is kept as `coordinates` either way.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Number, Value};

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "otx";
pub const KEY_SLOT: &str = crate::environment::OTX_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "otx.alienvault.com",
    origin: "https://otx.alienvault.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("X-OTX-API-KEY"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};

/// The fields of the answer this module reads. The pulses are read from the JSON itself, and
/// everything is also kept raw (see [`decode`]).
#[derive(Deserialize)]
struct Body {
    indicator: String,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    continent_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    postal_code: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    accuracy_radius: Option<Number>,
    #[serde(default)]
    reputation: Option<Number>,
    #[serde(default)]
    false_positive: Option<Vec<FalsePositive>>,
    pulse_info: PulseInfo,
    #[serde(default)]
    validation: Vec<Validation>,
}

#[derive(Deserialize)]
struct PulseInfo {
    #[serde(default)]
    count: u64,
    #[serde(default)]
    references: Option<Vec<Value>>,
    #[serde(default)]
    related: Option<Related>,
}

#[derive(Deserialize, Default)]
struct Related {
    #[serde(default)]
    alienvault: Option<Group>,
    #[serde(default)]
    other: Option<Group>,
}

#[derive(Deserialize, Default)]
struct Group {
    #[serde(default)]
    adversary: Vec<String>,
    #[serde(default)]
    malware_families: Vec<String>,
    #[serde(default)]
    industries: Vec<String>,
}

#[derive(Deserialize)]
struct Validation {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct FalsePositive {
    #[serde(default)]
    assessment: Option<String>,
    #[serde(default)]
    assessment_date: Option<String>,
    #[serde(default)]
    report_date: Option<String>,
}

/// The request URL for `indicator`, or `None` for a kind OTX is not asked about. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let section = match indicator {
        Indicator::Ip(ip) if ip.contains(':') => "IPv6",
        Indicator::Ip(_) => "IPv4",
        Indicator::Domain(_) => "domain",
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => return None,
    };
    Some(format!(
        "https://otx.alienvault.com/api/v1/indicators/{section}/{}/general",
        percent_encode_component(indicator.value())
    ))
}

/// Look `indicator` up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Some(url) = url(indicator) else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body, indicator),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// Cleaned values in the order first seen, each once. **Pure.**
#[derive(Default)]
struct Distinct {
    values: Vec<String>,
    seen: HashSet<String>,
}

impl Distinct {
    fn extend<'a>(&mut self, values: impl IntoIterator<Item = &'a str>) {
        for value in values {
            if let Some(value) = api_leg::clean(Some(value)) {
                if self.seen.insert(value.clone()) {
                    self.values.push(value);
                }
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// An item of an OTX list: a name, or an object with a `display_name`, `name` or `id`. **Pure.**
fn name_of(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s),
        Value::Object(o) => ["display_name", "name", "id"]
            .into_iter()
            .find_map(|key| o.get(key).and_then(Value::as_str)),
        _ => None,
    }
}

/// The names in `pulse`'s `key` list. **Pure.**
fn names<'a>(pulse: &'a Value, key: &str) -> impl Iterator<Item = &'a str> {
    pulse
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(name_of)
}

/// `pulse`'s `key` text. **Pure.**
fn text<'a>(pulse: &'a Value, key: &str) -> Option<&'a str> {
    pulse.get(key).and_then(Value::as_str)
}

/// What the listed pulses and OTX's related groups say, across them all. **Pure.**
#[derive(Default)]
struct Pulses {
    names: Distinct,
    ids: Distinct,
    authors: Distinct,
    tlp: Distinct,
    tags: Distinct,
    references: Distinct,
    countries: Distinct,
    attack_ids: Distinct,
    families: Distinct,
    adversaries: Distinct,
    industries: Distinct,
    first: Option<String>,
    last: Option<String>,
}

impl Pulses {
    fn read(pulses: &[Value], info: &PulseInfo) -> Self {
        let mut out = Self::default();
        for pulse in pulses {
            out.names.extend(text(pulse, "name"));
            out.ids.extend(text(pulse, "id"));
            out.authors
                .extend(pulse.pointer("/author/username").and_then(Value::as_str));
            out.tlp.extend(text(pulse, "TLP"));
            out.tags.extend(names(pulse, "tags"));
            out.references.extend(names(pulse, "references"));
            out.countries.extend(names(pulse, "targeted_countries"));
            out.attack_ids.extend(names(pulse, "attack_ids"));
            out.families.extend(names(pulse, "malware_families"));
            out.adversaries.extend(text(pulse, "adversary"));
            out.industries.extend(names(pulse, "industries"));
            if let Some(created) = text(pulse, "created") {
                if out.first.as_deref().is_none_or(|first| created < first) {
                    out.first = Some(created.to_owned());
                }
            }
            if let Some(modified) = text(pulse, "modified") {
                if out.last.as_deref().is_none_or(|last| modified > last) {
                    out.last = Some(modified.to_owned());
                }
            }
        }
        out.references
            .extend(info.references.iter().flatten().filter_map(name_of));
        let related = info.related.as_ref();
        for group in related
            .into_iter()
            .flat_map(|r| [r.alienvault.as_ref(), r.other.as_ref()])
            .flatten()
        {
            out.families
                .extend(group.malware_families.iter().map(String::as_str));
            out.adversaries
                .extend(group.adversary.iter().map(String::as_str));
            out.industries
                .extend(group.industries.iter().map(String::as_str));
        }
        out
    }

    fn into_finding(self, finding: Finding) -> Finding {
        let malicious = !self.families.is_empty() || !self.adversaries.is_empty();
        finding
            .list_attr("pulses", &self.names.values)
            .list_attr("pulse_ids", &self.ids.values)
            .list_attr("pulse_authors", &self.authors.values)
            .list_attr("pulse_tlp", &self.tlp.values)
            .list_attr("pulse_tags", &self.tags.values)
            .list_attr("references", &self.references.values)
            .list_attr("targeted_countries", &self.countries.values)
            .list_attr("targeted_industries", &self.industries.values)
            .list_attr("attack_ids", &self.attack_ids.values)
            .list_attr("malware_families", &self.families.values)
            .list_attr("adversaries", &self.adversaries.values)
            .opt_attr("first_pulse", self.first)
            .opt_attr("last_pulse", self.last)
            .tag_if(malicious, tags::MALICIOUS)
    }
}

/// Whether `answered`, the indicator an answer names, is `indicator`. An address is compared as
/// an address: OTX writes an IPv6 address uncompressed (`2606:4700:4700:0:0:0:0:1111`). **Pure.**
fn is_about(answered: &str, indicator: Indicator<'_>) -> bool {
    match indicator {
        Indicator::Ip(ip) => crate::canonical::same_ip(answered, ip),
        _ => answered.eq_ignore_ascii_case(indicator.value()),
    }
}

impl Body {
    /// The position OTX gives, in the crate's one form. **Pure.**
    fn position(&self) -> Option<String> {
        let (lat, lon) = (self.latitude?, self.longitude?);
        canonical_coordinates(&format!("{lat},{lon}"))
    }

    /// The city OTX names, if any. **Pure.**
    fn city(&self) -> Option<&str> {
        self.city.as_deref().filter(|c| !c.trim().is_empty())
    }

    /// Whether the answer says anything at all about the indicator. **Pure.**
    fn says_anything(&self, pulses: &[Value]) -> bool {
        self.pulse_info.count > 0
            || !pulses.is_empty()
            || !self.validation.is_empty()
            || self.false_positive.as_ref().is_some_and(|f| !f.is_empty())
            || self.asn.is_some()
            || self.country_code.is_some()
            || self.position().is_some()
    }

    /// OTX's validations and false-positive assessments. **Pure.**
    fn assessments(&self, finding: Finding) -> Finding {
        let mut validations = Distinct::default();
        validations.extend(
            self.validation
                .iter()
                .filter_map(|v| v.name.as_deref().or(v.source.as_deref())),
        );
        let mut messages = Distinct::default();
        messages.extend(self.validation.iter().filter_map(|v| v.message.as_deref()));
        let false_positive: Vec<String> = self
            .false_positive
            .iter()
            .flatten()
            .filter_map(|f| {
                let assessment = f.assessment.as_deref()?;
                Some(
                    match f.assessment_date.as_deref().or(f.report_date.as_deref()) {
                        Some(date) => format!("{assessment} {date}"),
                        None => assessment.to_owned(),
                    },
                )
            })
            .collect();
        let allowlisted = self.validation.iter().any(|v| {
            v.name
                .as_deref()
                .is_some_and(|n| n.to_ascii_lowercase().contains("whitelist"))
        });
        finding
            .list_attr("validations", &validations.values)
            .list_attr("validation_messages", &messages.values)
            .list_attr("false_positive", &false_positive)
            .tag_if(allowlisted, "allowlisted")
    }

    /// The address's reputation, place, position and AS. **Pure.**
    fn place(&self, finding: Finding) -> Finding {
        let mut finding = finding
            .opt_attr(
                "reputation",
                self.reputation.as_ref().map(Number::to_string),
            )
            .opt_attr("country", self.country_code.as_deref())
            .opt_attr("country_name", self.country_name.as_deref())
            .opt_attr("continent", self.continent_code.as_deref())
            .opt_attr("region", self.region.as_deref())
            .opt_attr("city", self.city())
            .opt_attr("postal_code", self.postal_code.as_deref())
            .opt_attr(
                "accuracy_radius_km",
                self.accuracy_radius.as_ref().map(Number::to_string),
            );
        if let Some(position) = self.position() {
            finding = finding.attr("coordinates", &position);
            if self.city().is_some() {
                finding = finding.pivot(
                    PivotKind::Coordinates,
                    position,
                    "Position OTX gives for the address's city",
                );
            }
        }
        if let Some((asn, org)) = self.asn.as_deref().and_then(|a| a.split_once(' ')) {
            finding = finding
                .pivot(PivotKind::Asn, asn, "Origin AS OTX gives for the address")
                .pivot(
                    PivotKind::Organisation,
                    org,
                    "AS holder OTX gives for the address",
                );
        }
        finding
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or names another indicator.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let mut raw: Value = api_leg::decode(body)?;
    let answer: Body = api_leg::decode_value(&raw)?;
    if !is_about(&answer.indicator, indicator) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let pulses = match raw
        .pointer_mut("/pulse_info")
        .and_then(Value::as_object_mut)
        .and_then(|info| info.remove("pulses"))
    {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(pulses)) => pulses,
        Some(_) => return Err(LegError::Decode("pulse_info.pulses is not a list".into())),
    };
    if !answer.says_anything(&pulses) {
        return Ok(None);
    }
    let count = answer.pulse_info.count;
    let summary = if count > 0 {
        format!("OTX: named in {count} pulse(s)")
    } else {
        "OTX: in no pulse".to_owned()
    };
    let mut finding = Finding::new(summary)
        .attr("pulse_count", count.to_string())
        .attr("pulses_listed", pulses.len().to_string())
        .tag_if(count > 0, "threat-reported");
    finding = Pulses::read(&pulses, &answer.pulse_info).into_finding(finding);
    finding = answer.assessments(finding);
    finding = answer.place(finding);
    if !pulses.is_empty() {
        finding = finding.attr("raw_pulses", Value::Array(pulses).to_string());
    }
    Ok(Some(finding.attr("raw_general", raw.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for a Tor exit on 2026-10-14 (pulses trimmed to two).
    const TOR_EXIT: &str = r#"{"whois":"http://whois.domaintools.com/185.220.101.1","reputation":0,"indicator":"185.220.101.1","type":"IPv4","type_title":"IPv4","asn":"AS208294 cia triad security llc","country_code":"DE","pulse_info":{"count":50,"pulses":[{"id":"5a7e3e70c44e7b48947593a7","name":"Webscanners 2018-02-09  thru current day","tags":["webscanner, bruteforce, web app attack","probing","webscan","scanning"],"malware_families":[],"adversary":"","created":"2018-02-10T00:36:00.396000","modified":"2026-10-14T15:06:19.514000","TLP":"white"},{"id":"6acf984af42a81561422a1af","name":"Anonymization_Network | Oct 15, 2026 | Part 1/4","tags":["anonymization_network"],"malware_families":[{"id":"Mirai","display_name":"Mirai","target":null}],"adversary":"","created":"2026-10-14T14:57:14.536000","modified":"2026-10-14T14:57:14.536000","TLP":"white"}],"references":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]},"other":{"adversary":[],"malware_families":[],"industries":["Finance","Defense"]}}},"validation":[{"source":"tor_exits","message":"IP Associated with Tor Exit Nodes","name":"IP Assosciated with Tor Exit Nodes"}]}"#;
    /// Recorded without a key for `example.com` on 2026-10-14 (trimmed).
    const ALLOWLISTED: &str = r#"{"sections":["general"],"indicator":"example.com","type":"domain","validation":[{"source":"majestic","message":"Whitelisted domain example.com","name":"Whitelisted domain"}],"pulse_info":{"count":0,"pulses":[],"references":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]},"other":{"adversary":[],"malware_families":[],"industries":[]}}}}"#;

    #[test]
    fn a_recorded_answer_keeps_pulses_families_and_the_as() {
        let f = decode(TOR_EXIT.as_bytes(), Indicator::Ip("185.220.101.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "OTX: named in 50 pulse(s)");
        assert!(f.attrs.contains(&("malware_families", "Mirai".into())));
        assert!(
            f.attrs
                .contains(&("targeted_industries", "Finance,Defense".into()))
        );
        assert!(f.tags.contains(&tags::MALICIOUS));
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS208294")
        );
    }

    #[test]
    fn an_allowlisted_domain_is_reported_and_an_unknown_one_is_a_zero() {
        let f = decode(ALLOWLISTED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.tags, ["allowlisted"]);
        let empty =
            r#"{"indicator":"zz.example","pulse_info":{"count":0,"pulses":[]},"validation":[]}"#;
        assert_eq!(
            decode(empty.as_bytes(), Indicator::Domain("zz.example")),
            Ok(None)
        );
        assert!(decode(ALLOWLISTED.as_bytes(), Indicator::Domain("other.example")).is_err());
    }

    #[test]
    fn an_answer_without_pulse_info_is_drift_not_a_zero() {
        for body in [
            r#"{"indicator":"zz.example"}"#,
            r#"{"indicator":"zz.example","validation":[]}"#,
            r#"{"indicator":"zz.example","pulse_info":null,"validation":[]}"#,
        ] {
            let decoded = decode(body.as_bytes(), Indicator::Domain("zz.example"));
            assert!(
                matches!(decoded, Err(LegError::Decode(_))),
                "{body}: {decoded:?}"
            );
        }
    }

    #[test]
    fn an_ipv6_answer_written_in_full_is_about_the_address_looked_up() {
        // Recorded for `2606:4700:4700::1111` on 2026-10-15, shortened: OTX writes it in full.
        let answer = r#"{"indicator":"2606:4700:4700:0:0:0:0:1111","type":"IPv6","asn":"AS13335 cloudflare","country_code":"US","pulse_info":{"count":0,"pulses":[]},"validation":[]}"#;
        let f = decode(answer.as_bytes(), Indicator::Ip("2606:4700:4700::1111"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("an answer with an AS is kept"));
        assert_eq!(f.summary, "OTX: in no pulse");
        assert!(f.tags.is_empty(), "{:?}", f.tags);
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS13335")
        );
        assert!(decode(answer.as_bytes(), Indicator::Ip("2606:4700:4700::1001")).is_err());
    }

    /// One pulse OTX listed for `45.155.205.233` on 2026-10-15 (description, references and
    /// ATT&CK techniques trimmed, counters left out), with the rest of that answer.
    const PLACED: &str = r#"{"whois":"http://whois.domaintools.com/45.155.205.233","reputation":0,"indicator":"45.155.205.233","type":"IPv4","type_title":"IPv4","base_indicator":{"id":2670653312,"indicator":"45.155.205.233","type":"IPv4","title":"","description":"","content":"","access_type":"public","access_reason":""},"pulse_info":{"count":26,"pulses":[{"id":"61b886db3f57da33ac504548","name":"Apache Log4j Vulnerability Called Log4Shell Actively Exploited","description":"A vulnerability in Apache Log4j, a widely used logging packa","modified":"2022-01-13T00:05:19.097000","created":"2021-12-14T11:58:18.325000","tags":["cve-2021-44228","log4shell"],"references":["https://www.trendmicro.com/content/dam/trendmicro/global/en/research/21/l/patch-now-apache-log4j-vulnerability-called-log4shell-being-actively-exploited/IOCs-PatchNow-Log4Shell-Vulnerability.txt"],"public":1,"adversary":"","targeted_countries":[],"malware_families":[],"attack_ids":[{"id":"T1190","name":"Exploit Public-Facing Application","display_name":"T1190 - Exploit Public-Facing Application"},{"id":"T1203","name":"Exploitation for Client Execution","display_name":"T1203 - Exploitation for Client Execution"}],"industries":[],"TLP":"white","pulse_source":"web","author":{"username":"AlienVault","id":"2"},"indicator_count":86,"related_indicator_type":"IPv4","related_indicator_is_active":0}],"references":["https://www.virustotal.com/gui/ip-address/45.155.205.233/relations"],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]},"other":{"adversary":[],"malware_families":["Mirai"],"industries":["Finance"]}}},"false_positive":[],"validation":[],"asn":"AS49505 ooo network of data-centers selectel","city_data":true,"city":"St Petersburg","region":"SPE","continent_code":"EU","country_code3":"RUS","country_code2":"RU","subdivision":"SPE","latitude":59.8983,"postal_code":"190824","longitude":30.2618,"accuracy_radius":1000,"country_code":"RU","country_name":"Russian Federation","dma_code":0,"charset":0,"area_code":0,"flag_url":"/assets/images/flags/ru.png","flag_title":"Russian Federation","sections":["general","geo","reputation","url_list","passive_dns","malware","nids_list","http_scans"]}"#;

    /// OTX's whole answer for `8.8.8.8` on 2026-10-15.
    const UNPLACED: &str = r#"{"whois": "http://whois.domaintools.com/8.8.8.8", "reputation": 0, "indicator": "8.8.8.8", "type": "IPv4", "type_title": "IPv4", "base_indicator": {"id": 11911, "indicator": "8.8.8.8", "type": "IPv4", "title": "", "description": "", "content": "", "access_type": "public", "access_reason": ""}, "pulse_info": {"count": 0, "pulses": [], "references": [], "related": {"alienvault": {"adversary": [], "malware_families": [], "industries": []}, "other": {"adversary": [], "malware_families": [], "industries": []}}}, "false_positive": [{"assessment": "accepted", "assessment_date": "2021-05-19T15:36:44.966000", "report_date": "2021-03-16T14:46:19.003000"}], "validation": [{"source": "false_positive", "message": "Known False Positive", "name": "Known False Positive"}, {"source": "whitelist", "message": "contained in whitelisted prefix", "name": "Whitelisted IP"}], "asn": "AS15169 google llc", "city_data": true, "city": null, "region": null, "continent_code": "NA", "country_code3": "USA", "country_code2": "US", "subdivision": null, "latitude": 37.751, "postal_code": null, "longitude": -97.822, "accuracy_radius": 1000, "country_code": "US", "country_name": "United States of America", "dma_code": 0, "charset": 0, "area_code": 0, "flag_url": "/assets/images/flags/us.png", "flag_title": "United States of America", "sections": ["general", "geo", "reputation", "url_list", "passive_dns", "malware", "nids_list", "http_scans"]}"#;

    fn value<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_pulse_keeps_everything_it_says() {
        let f = decode(PLACED.as_bytes(), Indicator::Ip("45.155.205.233"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "OTX: named in 26 pulse(s)");
        for (key, expected) in [
            ("pulse_count", "26"),
            ("pulses_listed", "1"),
            ("pulse_ids", "61b886db3f57da33ac504548"),
            ("pulse_authors", "AlienVault"),
            ("pulse_tlp", "white"),
            ("pulse_tags", "cve-2021-44228,log4shell"),
            (
                "attack_ids",
                "T1190 - Exploit Public-Facing Application,T1203 - Exploitation for Client Execution",
            ),
            ("malware_families", "Mirai"),
            ("targeted_industries", "Finance"),
            ("first_pulse", "2021-12-14T11:58:18.325000"),
            ("last_pulse", "2022-01-13T00:05:19.097000"),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        let references = value(&f, "references").unwrap_or_default();
        assert!(references.contains("IOCs-PatchNow-Log4Shell-Vulnerability.txt"));
        assert!(references.ends_with("/45.155.205.233/relations"));
        let raw_pulses: Value =
            serde_json::from_str(value(&f, "raw_pulses").unwrap_or_default()).unwrap_or_default();
        assert_eq!(raw_pulses[0]["indicator_count"], 86);
        let general: Value =
            serde_json::from_str(value(&f, "raw_general").unwrap_or_default()).unwrap_or_default();
        assert_eq!(general["base_indicator"]["id"], 2_670_653_312_u64);
        assert_eq!(general["pulse_info"]["count"], 26);
        assert!(general["pulse_info"].get("pulses").is_none());
    }

    #[test]
    fn a_placed_address_keeps_its_place_and_its_position_is_an_entity() {
        let f = decode(PLACED.as_bytes(), Indicator::Ip("45.155.205.233"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        for (key, expected) in [
            ("reputation", "0"),
            ("country", "RU"),
            ("country_name", "Russian Federation"),
            ("continent", "EU"),
            ("region", "SPE"),
            ("city", "St Petersburg"),
            ("postal_code", "190824"),
            ("accuracy_radius_km", "1000"),
            ("coordinates", "59.898300,30.261800"),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        let pivots: Vec<(PivotKind, &str)> = f
            .pivots
            .iter()
            .map(|p| (p.kind, p.value.as_str()))
            .collect();
        assert_eq!(
            pivots,
            [
                (PivotKind::Coordinates, "59.898300,30.261800"),
                (PivotKind::Asn, "AS49505"),
                (
                    PivotKind::Organisation,
                    "ooo network of data-centers selectel"
                ),
            ]
        );
    }

    #[test]
    fn a_position_without_a_city_is_kept_but_is_not_an_entity() {
        let f = decode(UNPLACED.as_bytes(), Indicator::Ip("8.8.8.8"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(value(&f, "coordinates"), Some("37.751000,-97.822000"));
        assert_eq!(value(&f, "city"), None);
        assert!(
            f.pivots.iter().all(|p| p.kind != PivotKind::Coordinates),
            "{:?}",
            f.pivots
        );
        assert_eq!(
            value(&f, "false_positive"),
            Some("accepted 2021-05-19T15:36:44.966000")
        );
        assert_eq!(
            value(&f, "validations"),
            Some("Known False Positive,Whitelisted IP")
        );
        assert_eq!(
            value(&f, "validation_messages"),
            Some("Known False Positive,contained in whitelisted prefix")
        );
        assert_eq!(f.tags, ["allowlisted"]);
        assert_eq!(value(&f, "raw_pulses"), None);
    }

    #[test]
    fn a_pulse_list_of_another_shape_is_drift() {
        let body = r#"{"indicator":"zz.example","pulse_info":{"count":1,"pulses":{"id":"x"}}}"#;
        let decoded = decode(body.as_bytes(), Indicator::Domain("zz.example"));
        assert!(matches!(decoded, Err(LegError::Decode(_))), "{decoded:?}");
    }

    #[test]
    fn a_mis_shaped_answer_names_no_body_value() {
        let body = r#"{"indicator":"185.220.101.1","pulse_info":{"count":"abc"}}"#;
        let detail = match decode(body.as_bytes(), Indicator::Ip("185.220.101.1")) {
            Err(error) => error.outcome(&API, 1).detail.unwrap_or_default(),
            Ok(found) => panic!("decoded {found:?}"),
        };
        assert_eq!(detail, "otx: unexpected response shape: data error");
    }

    #[test]
    fn a_404_is_a_path_otx_lacks_not_an_unseen_indicator() {
        let transport = crate::test_support::OneResponse::with_headers(
            404,
            &[("content-type", "text/html")],
            "<h1>Not Found</h1>",
        );
        let looked_up = lookup(
            &transport,
            &Keys::default(),
            Indicator::Domain("zz.example"),
            1,
        );
        assert!(
            matches!(looked_up, Err(LegError::Unexpected(404))),
            "{looked_up:?}"
        );
    }

    #[test]
    fn the_url_names_the_section_for_each_kind() {
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://otx.alienvault.com/api/v1/indicators/IPv6/2001%3Adb8%3A%3A1/general")
        );
        assert_eq!(url(Indicator::Email("a@b.example")), None);
    }
}
