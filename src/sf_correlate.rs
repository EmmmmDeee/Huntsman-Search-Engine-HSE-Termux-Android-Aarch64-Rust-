//! Spiderfoot 4.0's correlation rules, run over a scan's data elements.
//!
//! A rule is Spiderfoot's own YAML: `collections` of `collect` blocks whose first method picks
//! elements by `type`, `module` or `data` and whose later methods refine them, also through each
//! element's `source.`, `child.` and `entity.`; an optional `aggregation` that buckets them by a
//! field; `analysis` methods (`threshold`, `outlier`, `first_collection_only`,
//! `match_all_to_first_collection`) that drop buckets; and a `headline` naming each result. The
//! semantics are Spiderfoot's (`spiderfoot/correlation.py` at 0f815a2), including how a list of
//! `not` patterns combines. Spiderfoot's 37 shipped rules are embedded unchanged
//! (`src/correlations/spiderfoot`, MIT); rules in a directory the operator names are loaded beside
//! them, and one with a shipped rule's id replaces it. Beyond Spiderfoot: `publish_collections`
//! is honoured, regular expressions run in linear time ([`crate::pattern`]), elements flagged
//! false positive are left out, and a Spiderfoot module name in a rule (`sfp_crt`) also matches
//! the Huntsman source that does that module's work (`crtsh`).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::correlator::Severity;
use crate::pattern::Pattern;
use crate::sf_elements::DataElement;
use crate::sf_types::{self, Category};
use crate::sha256::{hex32, sha256};
use crate::yaml_lite;

/// A correlation's risk, as Spiderfoot grades it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Risk {
    High,
    Medium,
    Low,
    Info,
}

impl Risk {
    /// The risk a Huntsman rule's severity reads as: Spiderfoot has no level above HIGH.
    #[must_use]
    pub const fn of(severity: Severity) -> Self {
        match severity {
            Severity::Critical | Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "HIGH" => Some(Self::High),
            "MEDIUM" => Some(Self::Medium),
            "LOW" => Some(Self::Low),
            "INFO" => Some(Self::Info),
            _ => None,
        }
    }
}

/// Why a rule could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("correlation rule {rule}: {reason}")]
pub struct RuleError {
    pub rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Own,
    Source,
    Child,
    Entity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attr {
    Type,
    Module,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Field {
    scope: Scope,
    attr: Attr,
}

impl Field {
    fn parse(text: &str) -> Option<Self> {
        let (scope, attr) = match text.split_once('.') {
            Some(("source", attr)) => (Scope::Source, attr),
            Some(("child", attr)) => (Scope::Child, attr),
            Some(("entity", attr)) => (Scope::Entity, attr),
            Some(_) => return None,
            None => (Scope::Own, text),
        };
        let attr = match attr {
            "type" => Attr::Type,
            "module" => Attr::Module,
            "data" => Attr::Data,
            _ => return None,
        };
        Some(Self { scope, attr })
    }
}

#[derive(Debug, Clone)]
enum Test {
    Exact(String),
    Regex(Pattern),
}

#[derive(Debug, Clone)]
struct Criterion {
    negated: bool,
    test: Test,
}

impl Criterion {
    fn hits(&self, values: &[&str]) -> bool {
        values.iter().any(|value| match &self.test {
            Test::Exact(want) => value == want,
            Test::Regex(pattern) => pattern.is_match(value),
        })
    }
}

#[derive(Debug, Clone)]
struct Matcher {
    field: Field,
    criteria: Vec<Criterion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchMethod {
    Subnet,
    Exact,
    Contains,
}

#[derive(Debug, Clone)]
enum Analysis {
    Threshold {
        field: Field,
        minimum: u64,
        maximum: u64,
        unique: bool,
    },
    Outlier {
        maximum_percent: f64,
        noisy_percent: f64,
    },
    FirstCollectionOnly {
        field: Field,
    },
    MatchAllToFirst {
        field: Field,
        method: MatchMethod,
    },
}

/// One correlation rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risk: Risk,
    /// `spiderfoot` for a shipped rule, else the file it was read from.
    pub origin: String,
    /// The rule as written.
    pub yaml: String,
    collections: Vec<Vec<Matcher>>,
    aggregation: Option<Field>,
    analysis: Vec<Analysis>,
    headline: String,
    publish: Option<BTreeSet<usize>>,
}

/// One result: a rule's headline over the elements it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable for the rule and the bucket it found.
    pub id: String,
    pub rule: String,
    pub name: String,
    pub description: String,
    pub risk: Risk,
    pub title: String,
    /// `spiderfoot` for a shipped rule, else the file the rule was read from.
    pub origin: String,
    /// The rule as written.
    pub logic: String,
    pub elements: Vec<String>,
}

fn error(rule: &str, reason: impl Into<String>) -> RuleError {
    RuleError {
        rule: rule.to_owned(),
        reason: reason.into(),
    }
}

fn text<'a>(value: &'a Value, key: &str, rule: &str) -> Result<&'a str, RuleError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error(rule, format!("{key} is missing or not text")))
}

fn field(value: &Value, rule: &str) -> Result<Field, RuleError> {
    let name = text(value, "field", rule)?;
    Field::parse(name).ok_or_else(|| error(rule, format!("unknown field {name}")))
}

fn number(value: &Value, key: &str, default: f64) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(default)
}

fn matcher(value: &Value, rule: &str, first: bool) -> Result<Matcher, RuleError> {
    let field = field(value, rule)?;
    if first && field.scope != Scope::Own {
        return Err(error(
            rule,
            "the first method of a collect must use type, module or data",
        ));
    }
    let method = text(value, "method", rule)?;
    let values: Vec<String> = match value.get("value") {
        Some(Value::Array(items)) => items.iter().map(scalar_text).collect(),
        Some(Value::Null) | None => return Err(error(rule, "a method has no value")),
        Some(other) => vec![scalar_text(other)],
    };
    let mut criteria = Vec::new();
    for raw in values {
        let (negated, pattern) = match raw.strip_prefix("not ") {
            Some(rest) => (true, rest.trim_start().to_owned()),
            None => (false, raw),
        };
        let test = match method {
            "exact" => {
                if first && field.attr == Attr::Type && sf_types::find(&pattern).is_none() {
                    return Err(error(rule, format!("unknown type {pattern}")));
                }
                Test::Exact(pattern)
            }
            "regex" => Test::Regex(
                Pattern::new_ignore_case(&pattern)
                    .map_err(|failure| error(rule, failure.to_string()))?,
            ),
            other => return Err(error(rule, format!("unknown method {other}"))),
        };
        criteria.push(Criterion { negated, test });
    }
    Ok(Matcher { field, criteria })
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn analysis(value: &Value, rule: &str) -> Result<Analysis, RuleError> {
    Ok(match text(value, "method", rule)? {
        "threshold" => Analysis::Threshold {
            field: field(value, rule)?,
            minimum: value.get("minimum").and_then(Value::as_u64).unwrap_or(0),
            maximum: value
                .get("maximum")
                .and_then(Value::as_u64)
                .unwrap_or(999_999_999),
            unique: ["count_unique_only", "must_be_unique"]
                .iter()
                .any(|key| value.get(key).and_then(Value::as_bool) == Some(true)),
        },
        "outlier" => Analysis::Outlier {
            maximum_percent: value
                .get("maximum_percent")
                .and_then(Value::as_f64)
                .ok_or_else(|| error(rule, "outlier needs maximum_percent"))?,
            noisy_percent: number(value, "noisy_percent", 10.0),
        },
        "first_collection_only" => Analysis::FirstCollectionOnly {
            field: field(value, rule)?,
        },
        "match_all_to_first_collection" => Analysis::MatchAllToFirst {
            field: field(value, rule)?,
            method: match text(value, "match_method", rule)? {
                "subnet" => MatchMethod::Subnet,
                "exact" => MatchMethod::Exact,
                "contains" => MatchMethod::Contains,
                other => return Err(error(rule, format!("unknown match_method {other}"))),
            },
        },
        other => return Err(error(rule, format!("unknown analysis method {other}"))),
    })
}

impl Rule {
    /// Read one rule. `id` is the name its file gives it; the rule's own `id` must agree.
    ///
    /// # Errors
    /// [`RuleError`] for YAML outside the supported subset, a missing or unknown component, an
    /// unknown first-collection type, or a regular expression that does not compile.
    pub fn parse(id: &str, yaml: &str, origin: &str) -> Result<Self, RuleError> {
        let doc = yaml_lite::parse(yaml).map_err(|failure| error(id, failure.to_string()))?;
        let Some(object) = doc.as_object() else {
            return Err(error(id, "not a mapping"));
        };
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "id" | "version"
                    | "meta"
                    | "collections"
                    | "aggregation"
                    | "analysis"
                    | "headline"
                    | "enabled"
            ) {
                return Err(error(id, format!("unexpected component {key}")));
            }
        }
        if text(&doc, "id", id)? != id {
            return Err(error(id, "its id does not match its file name"));
        }
        let meta = doc
            .get("meta")
            .ok_or_else(|| error(id, "meta is missing"))?;
        let risk = text(meta, "risk", id)?;
        let risk = Risk::parse(risk).ok_or_else(|| error(id, format!("unknown risk {risk}")))?;
        let mut collections = Vec::new();
        for collection in doc
            .get("collections")
            .and_then(Value::as_array)
            .ok_or_else(|| error(id, "collections is missing"))?
        {
            let methods = collection
                .get("collect")
                .and_then(Value::as_array)
                .filter(|methods| !methods.is_empty())
                .ok_or_else(|| error(id, "a collection has no collect methods"))?;
            let mut matchers = Vec::new();
            for (index, method) in methods.iter().enumerate() {
                matchers.push(matcher(method, id, index == 0)?);
            }
            collections.push(matchers);
        }
        if collections.is_empty() {
            return Err(error(id, "collections is empty"));
        }
        let aggregation = match doc.get("aggregation") {
            Some(value) => Some(field(value, id)?),
            None => None,
        };
        let mut analyses = Vec::new();
        for value in doc
            .get("analysis")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
        {
            analyses.push(analysis(value, id)?);
        }
        let (headline, publish) = match doc.get("headline") {
            Some(Value::String(headline)) => (headline.clone(), None),
            Some(value @ Value::Object(_)) => (
                text(value, "text", id)?.to_owned(),
                value
                    .get("publish_collections")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_u64)
                            .filter_map(|index| usize::try_from(index).ok())
                            .collect()
                    }),
            ),
            _ => return Err(error(id, "headline is missing")),
        };
        Ok(Self {
            id: id.to_owned(),
            name: text(meta, "name", id)?.trim().to_owned(),
            description: text(meta, "description", id)?.trim().to_owned(),
            risk,
            origin: origin.to_owned(),
            yaml: yaml.to_owned(),
            collections,
            aggregation,
            analysis: analyses,
            headline,
            publish,
        })
    }

    /// Whether the rule's file turned it off with `enabled: false`.
    fn disabled(yaml: &str) -> bool {
        yaml_lite::parse(yaml)
            .ok()
            .and_then(|doc| doc.get("enabled").and_then(Value::as_bool))
            == Some(false)
    }
}

macro_rules! shipped {
    ($($id:literal),* $(,)?) => {
        [$(($id, include_str!(concat!("correlations/spiderfoot/", $id, ".yaml")))),*]
    };
}

/// Spiderfoot 4.0's rules, as it ships them (everything in its `correlations/` but the template).
const SHIPPED: [(&str, &str); 37] = shipped!(
    "cert_expired",
    "cloud_bucket_open",
    "cloud_bucket_open_related",
    "data_from_base64",
    "data_from_docmeta",
    "database_exposed",
    "dev_or_test_system",
    "dns_zone_transfer_possible",
    "egress_ip_from_wikipedia",
    "email_in_multiple_breaches",
    "email_in_whois",
    "email_only_from_pasteleak_site",
    "host_only_from_bruteforce",
    "host_only_from_certificatetransparency",
    "http_errors",
    "human_name_in_whois",
    "internal_host",
    "multiple_malicious",
    "multiple_malicious_affiliate",
    "multiple_malicious_cohost",
    "name_only_from_pasteleak_site",
    "open_port_version",
    "outlier_cloud",
    "outlier_country",
    "outlier_email",
    "outlier_hostname",
    "outlier_ipaddress",
    "outlier_registrar",
    "outlier_webserver",
    "remote_desktop_exposed",
    "root_path_needs_auth",
    "stale_host",
    "strong_affiliate_certs",
    "strong_similardomain_crossref",
    "vulnerability_critical",
    "vulnerability_high",
    "vulnerability_mediumlow",
);

/// Spiderfoot's shipped rules. Each is checked by a test, so none is dropped here.
pub fn shipped() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        SHIPPED
            .iter()
            .filter_map(|(id, yaml)| Rule::parse(id, yaml, "spiderfoot").ok())
            .collect()
    })
}

/// The largest rule file read.
pub const MAX_RULE_BYTES: u64 = 64 * 1024;

/// The most rule files read from one directory.
pub const MAX_RULE_FILES: usize = 500;

/// The shipped rules plus every `*.yaml` rule in `dir`, a rule there replacing a shipped one of
/// the same id and `enabled: false` turning one off; with the rules that could not be read.
/// A missing directory adds nothing.
#[must_use]
pub fn with_dir(dir: &Path) -> (Vec<Rule>, Vec<RuleError>) {
    let mut rules: BTreeMap<String, Rule> = shipped()
        .iter()
        .map(|rule| (rule.id.clone(), rule.clone()))
        .collect();
    let mut errors = Vec::new();
    let Ok(listing) = std::fs::read_dir(dir) else {
        return (rules.into_values().collect(), errors);
    };
    let mut paths: Vec<_> = listing
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    paths.sort();
    for path in paths.into_iter().take(MAX_RULE_FILES) {
        let id = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        let origin = path.display().to_string();
        let text = match crate::fsio::read_bounded(&path, MAX_RULE_BYTES)
            .map_err(|failure| failure.to_string())
            .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned()))
        {
            Ok(text) => text,
            Err(reason) => {
                errors.push(error(&origin, reason));
                continue;
            }
        };
        if Rule::disabled(&text) {
            rules.remove(&id);
            continue;
        }
        match Rule::parse(&id, &text, &origin) {
            Ok(rule) => {
                rules.insert(id, rule);
            }
            Err(failure) => errors.push(failure),
        }
    }
    (rules.into_values().collect(), errors)
}

/// The Spiderfoot module names a Huntsman source does the work of, beside `sfp_<source>`.
fn spiderfoot_names(module: &str) -> Vec<String> {
    let extra: &[&str] = match module {
        "crtsh" => &["sfp_crt"],
        "dns" => &["sfp_dnsresolve", "sfp_dnsraw"],
        "internetdb" => &["sfp_shodan"],
        "otx" => &["sfp_alienvault"],
        "hibp" | "hibp_account" => &["sfp_haveibeenpwned"],
        "ipqs" => &["sfp_ipqualityscore"],
        "ripestat" => &["sfp_ripe"],
        "urlhaus" | "threatfox" => &["sfp_abusech"],
        "github_user" => &["sfp_github"],
        "openpgp_keys" => &["sfp_pgp"],
        "whoxy" | "rdap" => &["sfp_whois"],
        "kickbox" => &["sfp_debounce"],
        "greynoise" => &["sfp_greynoise_community"],
        "hostdomain" => &["sfp_dnsresolve"],
        _ => &[],
    };
    let mut names = vec![module.to_owned(), format!("sfp_{module}")];
    names.extend(extra.iter().map(|name| (*name).to_owned()));
    names
}

/// One collected element, with its source, children and entity as the rule's fields see them.
#[derive(Debug, Clone)]
struct Hit {
    element: usize,
    collection: usize,
    source: Vec<usize>,
    child: Vec<usize>,
    entity: Vec<usize>,
}

struct Scan<'a> {
    elements: &'a [DataElement],
    by_id: BTreeMap<&'a str, usize>,
    children: BTreeMap<&'a str, Vec<usize>>,
}

impl<'a> Scan<'a> {
    fn new(elements: &'a [DataElement]) -> Self {
        let mut by_id = BTreeMap::new();
        let mut children: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, element) in elements.iter().enumerate() {
            by_id.insert(element.id.as_str(), index);
            if let Some(source) = &element.source {
                children.entry(source.as_str()).or_default().push(index);
            }
        }
        Self {
            elements,
            by_id,
            children,
        }
    }

    fn source(&self, index: usize) -> Option<usize> {
        self.elements[index]
            .source
            .as_deref()
            .and_then(|source| self.by_id.get(source).copied())
    }

    /// The nearest element up the source chain that is an entity (or the root).
    fn entity(&self, index: usize) -> Option<usize> {
        let mut at = self.source(index)?;
        for _ in 0..self.elements.len() {
            let category = sf_types::find(&self.elements[at].kind).map(|kind| kind.category);
            if matches!(category, Some(Category::Entity | Category::Internal)) {
                return Some(at);
            }
            at = self.source(at)?;
        }
        None
    }

    fn hit(&self, element: usize, collection: usize) -> Hit {
        Hit {
            element,
            collection,
            source: self.source(element).into_iter().collect(),
            child: self
                .children
                .get(self.elements[element].id.as_str())
                .cloned()
                .unwrap_or_default(),
            entity: self.entity(element).into_iter().collect(),
        }
    }

    fn attr(&self, index: usize, attr: Attr) -> &'a str {
        let element = &self.elements[index];
        match attr {
            Attr::Type => &element.kind,
            Attr::Module => &element.module,
            Attr::Data => &element.data,
        }
    }

    fn scoped(hit: &Hit, scope: Scope) -> &[usize] {
        match scope {
            Scope::Own => std::slice::from_ref(&hit.element),
            Scope::Source => &hit.source,
            Scope::Child => &hit.child,
            Scope::Entity => &hit.entity,
        }
    }

    fn values(&self, hit: &Hit, field: Field) -> Vec<&'a str> {
        Self::scoped(hit, field.scope)
            .iter()
            .map(|index| self.attr(*index, field.attr))
            .collect()
    }

    /// Spiderfoot's `event_keep`: the last pattern's kind decides when none matched.
    fn keeps(&self, hit: &Hit, matcher: &Matcher) -> bool {
        Self::scoped(hit, matcher.field.scope).iter().any(|index| {
            let value = self.attr(*index, matcher.field.attr);
            let names = if matcher.field.attr == Attr::Module {
                spiderfoot_names(value)
            } else {
                vec![value.to_owned()]
            };
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let mut keep = false;
            for criterion in &matcher.criteria {
                let hits = criterion.hits(&names);
                if criterion.negated {
                    if hits {
                        return false;
                    }
                    keep = true;
                } else {
                    if hits {
                        return true;
                    }
                    keep = false;
                }
            }
            keep
        })
    }
}

type Buckets = Vec<(String, Vec<Hit>)>;

/// Whether `value` is an address inside `network`; a bare address is a network of one, as
/// Spiderfoot's `netaddr.IPNetwork` reads it.
fn in_subnet(value: &str, network: &str) -> bool {
    let (base, bits) = network.split_once('/').unwrap_or((network, ""));
    let (Ok(address), Ok(base)) = (
        value.trim().parse::<IpAddr>(),
        base.trim().parse::<IpAddr>(),
    ) else {
        return false;
    };
    let bits = match (bits.trim(), base) {
        ("", IpAddr::V4(_)) => 32,
        ("", IpAddr::V6(_)) => 128,
        (bits, _) => match bits.parse::<u32>() {
            Ok(bits) => bits,
            Err(_) => return false,
        },
    };
    match (address, base) {
        (IpAddr::V4(address), IpAddr::V4(base)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(address) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(address), IpAddr::V6(base)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(address) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}

impl Scan<'_> {
    fn collect(&self, rule: &Rule) -> Vec<Hit> {
        let mut hits = Vec::new();
        for (collection, matchers) in rule.collections.iter().enumerate() {
            for (index, element) in self.elements.iter().enumerate() {
                if element.fp {
                    continue;
                }
                let hit = self.hit(index, collection);
                if matchers.iter().all(|matcher| self.keeps(&hit, matcher)) {
                    hits.push(hit);
                }
            }
        }
        hits
    }

    fn aggregate(&self, hits: Vec<Hit>, field: Field) -> Buckets {
        let mut buckets: Buckets = Vec::new();
        let mut positions: BTreeMap<String, usize> = BTreeMap::new();
        for hit in hits {
            for value in self.values(&hit, field) {
                let mut copy = hit.clone();
                // A bucket of a source, child or entity value keeps only those that have it.
                if field.scope != Scope::Own {
                    let kept: Vec<usize> = Self::scoped(&hit, field.scope)
                        .iter()
                        .copied()
                        .filter(|index| self.attr(*index, field.attr) == value)
                        .collect();
                    match field.scope {
                        Scope::Source => copy.source = kept,
                        Scope::Child => copy.child = kept,
                        Scope::Entity => copy.entity = kept,
                        Scope::Own => {}
                    }
                }
                let position = *positions.entry(value.to_owned()).or_insert_with(|| {
                    buckets.push((value.to_owned(), Vec::new()));
                    buckets.len() - 1
                });
                buckets[position].1.push(copy);
            }
        }
        buckets
    }

    fn analyse(&self, analysis: &Analysis, buckets: &mut Buckets) {
        match analysis {
            Analysis::Threshold {
                field,
                minimum,
                maximum,
                unique,
            } => buckets.retain(|(_, hits)| {
                let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
                for hit in hits {
                    for value in self.values(hit, *field) {
                        *counts.entry(value).or_default() += 1;
                    }
                }
                if *unique {
                    let uniques = u64::try_from(counts.len()).unwrap_or(u64::MAX);
                    (*minimum..=*maximum).contains(&uniques)
                } else {
                    counts
                        .values()
                        .all(|count| (*minimum..=*maximum).contains(count))
                }
            }),
            Analysis::Outlier {
                maximum_percent,
                noisy_percent,
            } => outliers(buckets, *maximum_percent, *noisy_percent),
            Analysis::FirstCollectionOnly { field } => {
                let first: BTreeSet<&str> = buckets
                    .iter()
                    .flat_map(|(_, hits)| hits)
                    .filter(|hit| hit.collection == 0)
                    .flat_map(|hit| self.values(hit, *field))
                    .collect();
                buckets.retain(|(_, hits)| {
                    hits.iter().all(|hit| hit.collection == 0)
                        && !hits.iter().any(|hit| {
                            hit.collection > 0
                                && self
                                    .values(hit, *field)
                                    .iter()
                                    .any(|value| first.contains(value))
                        })
                });
            }
            Analysis::MatchAllToFirst { field, method } => {
                let reference: BTreeSet<&str> = buckets
                    .iter()
                    .flat_map(|(_, hits)| hits)
                    .filter(|hit| hit.collection == 0)
                    .flat_map(|hit| self.values(hit, *field))
                    .collect();
                let matches = |value: &str| match method {
                    MatchMethod::Exact => reference.contains(value),
                    MatchMethod::Contains => reference.iter().any(|item| item.contains(value)),
                    MatchMethod::Subnet => reference.iter().any(|item| in_subnet(value, item)),
                };
                for (_, hits) in buckets.iter_mut() {
                    hits.retain(|hit| {
                        hit.collection == 0
                            || self.values(hit, *field).iter().any(|value| matches(value))
                    });
                }
                buckets.retain(|(_, hits)| hits.iter().any(|hit| hit.collection > 0));
            }
        }
    }

    fn title(&self, rule: &Rule, hit: &Hit) -> String {
        let mut title = rule.headline.clone();
        let mut rest = rule.headline.as_str();
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                break;
            };
            let name = &after[..close];
            rest = &after[close + 1..];
            if let Some(value) =
                Field::parse(name).and_then(|field| self.values(hit, field).first().copied())
            {
                let line = value.replace('\r', "");
                let first = line.split('\n').next().unwrap_or_default();
                title = title.replace(&format!("{{{name}}}"), first);
            }
        }
        title
    }

    fn run(&self, rule: &Rule) -> Vec<Finding> {
        let hits = self.collect(rule);
        if hits.is_empty() {
            return Vec::new();
        }
        let mut buckets = match rule.aggregation {
            Some(field) => self.aggregate(hits, field),
            None => vec![("default".to_owned(), hits)],
        };
        for analysis in &rule.analysis {
            self.analyse(analysis, &mut buckets);
        }
        buckets
            .into_iter()
            .filter_map(|(key, hits)| {
                let first = hits.first()?;
                let title = self.title(rule, first);
                let mut seen = BTreeSet::new();
                let elements: Vec<String> = hits
                    .iter()
                    .filter(|hit| {
                        rule.publish
                            .as_ref()
                            .is_none_or(|publish| publish.contains(&hit.collection))
                    })
                    .map(|hit| self.elements[hit.element].id.clone())
                    .filter(|id| seen.insert(id.clone()))
                    .collect();
                let mut key_bytes = rule.id.clone().into_bytes();
                key_bytes.push(0);
                key_bytes.extend_from_slice(key.as_bytes());
                Some(Finding {
                    id: hex32(&sha256(&key_bytes))[..16].to_owned(),
                    rule: rule.id.clone(),
                    name: rule.name.clone(),
                    description: rule.description.clone(),
                    risk: rule.risk,
                    title,
                    origin: rule.origin.clone(),
                    logic: rule.yaml.clone(),
                    elements,
                })
            })
            .collect()
    }
}

/// Spiderfoot's outlier analysis: with the average bucket under `noisy_percent` of the whole
/// nothing is an outlier; otherwise only buckets at most `maximum_percent` of the whole stay.
fn outliers(buckets: &mut Buckets, maximum_percent: f64, noisy_percent: f64) {
    #[allow(clippy::cast_precision_loss)]
    let total = buckets.iter().map(|(_, hits)| hits.len()).sum::<usize>() as f64;
    #[allow(clippy::cast_precision_loss)]
    let count = buckets.len() as f64;
    if buckets.is_empty() || total == 0.0 {
        buckets.clear();
        return;
    }
    let average_percent = (total / count) / total * 100.0;
    if average_percent < noisy_percent {
        buckets.clear();
        return;
    }
    #[allow(clippy::cast_precision_loss)]
    buckets.retain(|(_, hits)| (hits.len() as f64 / total) * 100.0 <= maximum_percent);
}

/// Run every rule over a scan's elements.
#[must_use]
pub fn run(rules: &[Rule], elements: &[DataElement]) -> Vec<Finding> {
    let scan = Scan::new(elements);
    rules.iter().flat_map(|rule| scan.run(rule)).collect()
}

#[cfg(test)]
mod tests;
