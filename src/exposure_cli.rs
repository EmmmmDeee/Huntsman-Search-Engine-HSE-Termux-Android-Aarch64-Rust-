//! End-to-end front-end for `huntsman-recon exposure`.
//!
//! The address is canonicalised once, then the account-keyed legs of
//! [`breach_hybrid::exposure_order`] run in that order: HIBP `breachedaccount`,
//! then the stolen.tax cascade. The keyless legs (Pwned Passwords, the HIBP
//! catalogue) are not keyed on an address and are not run here. Each HIBP breach
//! becomes evidence on the seed email entity, tagged `breach` or `stealer-log`;
//! stolen.tax entities are taken as that module builds them. Everything flows
//! through `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`. A leg
//! without its key makes no request and records `AuthRequired`, never a zero.
//!
//! Each HIBP breach is also an [`Incident`]: the public context of the breach as
//! the source describes it. Its HTML description becomes a bounded plain-text
//! summary and the http(s) links the description itself gives; no URL is built
//! or guessed, so a domain stays a domain. The report text closes with an
//! incidents section, every third-party value written through
//! [`escape_controls`]. An incident describes a public breach, never the person:
//! being listed is evidence, not a verdict. A fabricated or spam-list incident is
//! flagged in the evidence, the entity tags and the text.

use std::path::PathBuf;

use crate::breach_hybrid::{self, BreachLeg};
use crate::canonical::{canonical_email, canonical_url};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::hibp::client::HibpClient;
use crate::hibp::error::HibpError;
use crate::hibp::types::{BreachModel, BreachedAccountOptions};
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::stolen_tax::{self, StolenTaxError};
use crate::tags;
use crate::textnorm::{decode_html_entities, escape_controls, is_escaped};

pub const EXPOSURE_USAGE: &str = "usage: huntsman-recon exposure ADDR [--save FILE]";
pub const EXPOSURE_HELP: &str = "\
exposure ADDR [--save FILE]
Canonicalise ADDR and run the keyed breach legs in order: HIBP breached-account, then the stolen.tax cascade. A leg without its key makes no request and reports auth_required. Results are lineage-rendered entities. Then incidents=N (none when HIBP gave no answer) and, per HIBP breach sorted by name (a name the source repeats is shown once, keeping every flag any of its records sets): an incident row (title, breach and added dates, domain, account count, verified, flags), a caution row for a fabricated or spam-list breach, its summary, data classes, attribution, and the reference links its own description gives. This is public context about each breach, not a finding about the person. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the HIBP breached-account leg.
pub const SOURCE: &str = "hibp_account";
/// Source label for the stolen.tax leg.
pub const STOLEN_TAX_SOURCE: &str = "stolen_tax";

/// The longest incident summary or attribution, in characters. Longer text is cut on a character
/// boundary and ends with [`ELLIPSIS`], which counts toward the limit.
pub const MAX_SUMMARY_CHARS: usize = 600;
/// The most reference links kept for one incident, in the order its description first gives them.
pub const MAX_REFERENCE_LINKS: usize = 8;
/// The longest reference link kept, in bytes, after canonicalisation. A longer one is dropped,
/// never shortened, so every link shown is one the source wrote.
pub const MAX_REFERENCE_BYTES: usize = 2048;
/// Ends a summary or attribution that [`MAX_SUMMARY_CHARS`] cut short.
pub const ELLIPSIS: char = '\u{2026}';

/// The label of the HIBP fabricated flag.
const FABRICATED: &str = "fabricated";
/// The label of the HIBP spam-list flag.
const SPAM_LIST: &str = "spam-list";
/// The label of the HIBP stealer-log flag.
const STEALER_LOG: &str = "stealer-log";
/// Every status flag label, in the order an incident lists its flags.
const STATUS_LABELS: [&str; 7] = [
    FABRICATED,
    SPAM_LIST,
    "malware",
    STEALER_LOG,
    "sensitive",
    "retired",
    "subscription-free",
];

/// The HTML elements that separate text: a tag of one of these reads as a space, any other tag as
/// nothing, so `a<br>b` reads `a b` and `a<b>b</b>` reads `ab`.
const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];

/// One status flag the source sets on an incident, and the value it gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFlag {
    /// `fabricated`, `spam-list`, `malware`, `stealer-log`, `sensitive`, `retired` or
    /// `subscription-free`.
    pub label: &'static str,
    /// The value the source gives.
    pub set: bool,
}

/// The public context of one breach incident the address is listed in, as the source states it.
/// It describes the incident, never the person.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Incident {
    /// The source's stable breach name.
    pub name: String,
    /// The display title.
    pub title: Option<String>,
    /// The breached service's domain, as the source gives it. It is never turned into a link.
    pub domain: Option<String>,
    /// When the breach happened.
    pub breach_date: Option<String>,
    /// When the source added it.
    pub added_date: Option<String>,
    /// When the source last changed it.
    pub modified_date: Option<String>,
    /// How many accounts the source loaded from it.
    pub pwn_count: Option<u64>,
    /// Whether the source considers it verified.
    pub verified: Option<bool>,
    /// The kinds of data it exposed, as the source names them.
    pub data_classes: Vec<String>,
    /// Every status flag the source sends, in a fixed order. A flag it omits is absent.
    pub status: Vec<StatusFlag>,
    /// The description as plain text, at most [`MAX_SUMMARY_CHARS`] characters.
    pub summary: Option<String>,
    /// The canonical http(s) links the description gives (the public coverage the source cites),
    /// first-seen order, without repeats, at most [`MAX_REFERENCE_LINKS`].
    pub references: Vec<String>,
    /// The credit the data provider asked for, as plain text, at most [`MAX_SUMMARY_CHARS`].
    pub attribution: Option<String>,
}

impl Incident {
    /// The incident HIBP describes with `breach`.
    #[must_use]
    pub fn from_breach(breach: &BreachModel) -> Self {
        let description = breach.description.as_deref();
        // The values in `STATUS_LABELS` order.
        let values = [
            breach.is_fabricated,
            breach.is_spam_list,
            breach.is_malware,
            breach.is_stealer_log,
            breach.is_sensitive,
            breach.is_retired,
            breach.is_subscription_free,
        ];
        let status = STATUS_LABELS
            .into_iter()
            .zip(values)
            .filter_map(|(label, value)| value.map(|set| StatusFlag { label, set }))
            .collect();
        Self {
            name: breach.name.clone(),
            title: breach.title.clone(),
            domain: breach.domain.clone(),
            breach_date: breach.breach_date.clone(),
            added_date: breach.added_date.clone(),
            modified_date: breach.modified_date.clone(),
            pwn_count: breach.pwn_count,
            verified: breach.is_verified,
            data_classes: breach.data_classes.clone(),
            status,
            summary: description.and_then(|html| html_to_text(html, MAX_SUMMARY_CHARS)),
            references: description
                .map(|html| reference_links(html, MAX_REFERENCE_LINKS))
                .unwrap_or_default(),
            attribution: breach
                .attribution
                .as_deref()
                .and_then(|html| html_to_text(html, MAX_SUMMARY_CHARS)),
        }
    }

    /// The labels of the flags the source sets to true, in [`Incident::status`] order.
    pub fn flags(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.status
            .iter()
            .filter(|flag| flag.set)
            .map(|flag| flag.label)
    }

    /// Whether the source sets the flag `label`.
    #[must_use]
    pub fn has_flag(&self, label: &str) -> bool {
        self.flags().any(|flag| flag == label)
    }

    /// The value the source gives the flag `label`, or `None` when it omits it.
    fn flag_value(&self, label: &str) -> Option<bool> {
        self.status
            .iter()
            .find(|flag| flag.label == label)
            .map(|flag| flag.set)
    }

    /// Folds `later`, a record the source gave after this one under the same name, into this
    /// one. A descriptive field (title, domain, dates, account count, data classes, summary,
    /// references, attribution) keeps the first value given and takes the later one only where
    /// this record has none. The status flags and `verified` are merged so that a caution is
    /// never lost: a flag either record sets to true is set, and the incident is verified only
    /// when no record says otherwise.
    fn absorb(&mut self, later: Self) {
        fn fill<T>(first: &mut Option<T>, later: Option<T>) {
            if first.is_none() {
                *first = later;
            }
        }
        fn fill_list<T>(first: &mut Vec<T>, later: Vec<T>) {
            if first.is_empty() {
                *first = later;
            }
        }
        self.status = STATUS_LABELS
            .into_iter()
            .filter_map(|label| {
                let values = [self.flag_value(label), later.flag_value(label)];
                let given = values.iter().any(Option::is_some);
                given.then(|| StatusFlag {
                    label,
                    set: values.contains(&Some(true)),
                })
            })
            .collect();
        self.verified = self
            .verified
            .into_iter()
            .chain(later.verified)
            .reduce(|a, b| a && b);
        fill(&mut self.title, later.title);
        fill(&mut self.domain, later.domain);
        fill(&mut self.breach_date, later.breach_date);
        fill(&mut self.added_date, later.added_date);
        fill(&mut self.modified_date, later.modified_date);
        fill(&mut self.pwn_count, later.pwn_count);
        fill(&mut self.summary, later.summary);
        fill(&mut self.attribution, later.attribution);
        fill_list(&mut self.data_classes, later.data_classes);
        fill_list(&mut self.references, later.references);
    }
}

/// One incident per breach name, sorted by name. HIBP documents a breach name as unique, so only
/// a malformed or hostile answer repeats one; records that share a name are folded into the first
/// of them in source order with [`Incident::absorb`], so no flag one of them sets is dropped.
fn merge_incidents(mut incidents: Vec<Incident>) -> Vec<Incident> {
    // A stable sort: records that share a name stay in source order.
    incidents.sort_by(|a, b| a.name.cmp(&b.name));
    let mut merged: Vec<Incident> = Vec::with_capacity(incidents.len());
    for incident in incidents {
        match merged.last_mut() {
            Some(last) if last.name == incident.name => last.absorb(incident),
            _ => merged.push(incident),
        }
    }
    merged
}

/// What a flag that changes how an incident should be read means, in the source's terms.
fn caution(flag: &str) -> Option<&'static str> {
    match flag {
        FABRICATED => Some(
            "the source flags this incident as fabricated: it is unlikely to have come from the \
             named service and usually holds little or no legitimate data",
        ),
        SPAM_LIST => Some(
            "the source flags this incident as a spam list: its data did not come from a \
             security compromise",
        ),
        _ => None,
    }
}

/// The evidence attribute that holds the flag `label`: `spam-list` is `breach_spam_list`.
fn flag_attribute(label: &str) -> String {
    format!("breach_{}", label.replace('-', "_"))
}

/// The configured legs. `None` means that leg has no operator key.
#[derive(Clone, Copy, Default)]
pub struct Sources<'a> {
    pub hibp: Option<&'a HibpClient>,
    pub stolen_tax: Option<(&'a dyn Transport, &'a Keys)>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    /// The breach incidents HIBP lists the address in, sorted by breach name, one per name
    /// (records that share a name are merged, see [`Incident::absorb`]). The HIBP evidence is
    /// built from these same incidents. `None` when HIBP gave no answer (no key, or a failed
    /// request), which is not a zero.
    pub incidents: Option<Vec<Incident>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureArgs {
    pub email: String,
    pub save: Option<PathBuf>,
}

impl ExposureArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("exposure needs exactly one ADDR".into()));
        }
        let email = canonical_email(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid email address"))?;
        Ok(Self { email, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExposureRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// Run every configured account-keyed breach leg for `email`.
#[must_use]
pub fn run(sources: Sources<'_>, email: &str, now_unix: u64) -> ExposureRun {
    let Some(email) = canonical_email(email) else {
        return ExposureRun::Failed("invalid email address".into());
    };
    let scan_id = crate::entity::scan_id("exposure", &email);
    let mut report = Report {
        entities: vec![seed_entity(&email, &scan_id)],
        outcomes: Vec::new(),
        incidents: None,
    };
    let mut network = None;

    for leg in breach_hybrid::exposure_order(true) {
        let outcome = match leg {
            BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => continue,
            BreachLeg::HibpAccount => match sources.hibp {
                None => missing_key(SOURCE, now_unix),
                Some(client) => hibp_leg(
                    client,
                    &email,
                    &scan_id,
                    now_unix,
                    &mut report,
                    &mut network,
                ),
            },
            BreachLeg::StolenTax => match sources.stolen_tax {
                None => missing_key(STOLEN_TAX_SOURCE, now_unix),
                Some((transport, keys)) => {
                    stolen_tax_leg(transport, keys, &email, &scan_id, now_unix, &mut report)
                }
            },
        };
        report.outcomes.push(outcome);
    }
    merge_by_uid(&mut report.entities);

    let collected = report.outcomes.iter().any(|o| o.kind.is_accepted());
    if let (false, Some(msg)) = (collected, network) {
        return ExposureRun::Network(msg);
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(mut text) => {
            text.push_str(&render_incidents(report.incidents.as_deref()));
            ExposureRun::Printed { text, report }
        }
        Err(msg) => ExposureRun::Failed(msg),
    }
}

/// The incidents section that follows the lookup report. The first line is `incidents=N`, or
/// `incidents=none` when HIBP gave no answer. Each incident then has tab-separated rows, each led
/// by its kind and the breach name: one `incident` row (title, breach date, added date, domain,
/// account count, verified, flags; `unknown` for a value the source omits), a `caution` row for
/// each flag that changes how it should be read, then `summary`, `data_classes` and `attribution`
/// when the source gives them, and one `reference` row per link. Every value is written through
/// [`escape_controls`], so description text can neither drive the terminal nor forge a row.
fn render_incidents(incidents: Option<&[Incident]>) -> String {
    let Some(incidents) = incidents else {
        return "incidents=none\n".to_owned();
    };
    let mut out = format!("incidents={}\n", incidents.len());
    for incident in incidents {
        let name = escape_controls(&incident.name);
        let text = |value: &Option<String>| known(value.as_deref().map(escape_controls));
        let flags: Vec<&str> = incident.flags().collect();
        let flag_list = if flags.is_empty() {
            "none".to_owned()
        } else {
            flags.join(",")
        };
        let row = [
            "incident".to_owned(),
            name.clone(),
            format!("title={}", text(&incident.title)),
            format!("breach_date={}", text(&incident.breach_date)),
            format!("added={}", text(&incident.added_date)),
            format!("domain={}", text(&incident.domain)),
            format!(
                "accounts={}",
                known(incident.pwn_count.map(|n| n.to_string()))
            ),
            format!(
                "verified={}",
                known(incident.verified.map(|v| v.to_string()))
            ),
            format!("flags={flag_list}"),
        ];
        push_row(&mut out, &row);
        for message in flags.iter().filter_map(|flag| caution(flag)) {
            push_row(
                &mut out,
                &["caution".to_owned(), name.clone(), message.to_owned()],
            );
        }
        let classes = incident.data_classes.join(", ");
        for (kind, value) in [
            ("summary", incident.summary.as_deref()),
            (
                "data_classes",
                Some(classes.as_str()).filter(|c| !c.is_empty()),
            ),
            ("attribution", incident.attribution.as_deref()),
        ] {
            if let Some(value) = value {
                push_row(
                    &mut out,
                    &[kind.to_owned(), name.clone(), escape_controls(value)],
                );
            }
        }
        for link in &incident.references {
            push_row(
                &mut out,
                &["reference".to_owned(), name.clone(), escape_controls(link)],
            );
        }
    }
    out
}

/// `value` as the report shows it, or `unknown` when the source omits it.
fn known(value: Option<String>) -> String {
    value.unwrap_or_else(|| "unknown".to_owned())
}

/// Appends one row of already escaped fields, tab-separated and ending in a newline.
fn push_row(out: &mut String, fields: &[String]) {
    out.push_str(&fields.join("\t"));
    out.push('\n');
}

fn missing_key(source: &str, now_unix: u64) -> SourceExecutionOutcome {
    // The HIBP account API needs a key only to automate the check. An individual can
    // check their own address for free on the website, so the HIBP leg names that route
    // rather than reporting a bare dead end.
    let detail = if source == SOURCE {
        "no operator key configured; no request made. Check this address for free at \
         https://haveibeenpwned.com/ (the key only automates the API)"
    } else {
        "no operator key configured; no request made"
    };
    SourceExecutionOutcome::failed(
        source,
        now_unix,
        SourceOutcomeKind::AuthRequired,
        None,
        detail,
    )
}

fn hibp_leg(
    client: &HibpClient,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
    network: &mut Option<String>,
) -> SourceExecutionOutcome {
    let options = BreachedAccountOptions {
        truncate_response: Some(false),
        ..BreachedAccountOptions::default()
    };
    match client.breached_account(email, &options) {
        Ok(breaches) if breaches.is_empty() => {
            report.incidents = Some(Vec::new());
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
        }
        Ok(breaches) => {
            // Merged before the evidence is built, so the evidence, the tags, the incidents
            // section and the found count all describe the same one record per breach name.
            let incidents = merge_incidents(breaches.iter().map(Incident::from_breach).collect());
            report.entities.extend(
                incidents
                    .iter()
                    .map(|incident| breach_entity(email, scan_id, incident)),
            );
            let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, incidents.len());
            let outcome = if incidents.len() < breaches.len() {
                outcome.with_detail(format!(
                    "the source gave {} records for {} breach names; records that share a name \
                     are merged and keep every flag any of them sets",
                    breaches.len(),
                    incidents.len()
                ))
            } else {
                outcome
            };
            report.incidents = Some(incidents);
            outcome
        }
        Err(err) => {
            if let HibpError::Transport(msg) = &err {
                network.get_or_insert_with(|| msg.clone());
            }
            SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                outcome_kind(&err),
                None,
                err.to_string(),
            )
        }
    }
}

fn stolen_tax_leg(
    transport: &dyn Transport,
    keys: &Keys,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    match stolen_tax::lookup(transport, keys, email, scan_id, now_unix) {
        Ok(got) => {
            let found = got.entities.len();
            report.entities.extend(got.entities);
            let outcome = SourceExecutionOutcome::success(STOLEN_TAX_SOURCE, now_unix, found);
            match got.truncation {
                Some(why) => outcome.with_detail(format!("partial: {why}")),
                None => outcome,
            }
        }
        Err(err) => {
            let kind = match &err {
                StolenTaxError::MissingKey => SourceOutcomeKind::AuthRequired,
                StolenTaxError::Refused(_) => SourceOutcomeKind::ConnectFailure,
                StolenTaxError::BudgetExhausted { .. } => SourceOutcomeKind::BodyTimeout,
                StolenTaxError::Failed(_) => SourceOutcomeKind::Inconclusive,
            };
            SourceExecutionOutcome::failed(STOLEN_TAX_SOURCE, now_unix, kind, None, err.to_string())
        }
    }
}

fn outcome_kind(err: &HibpError) -> SourceOutcomeKind {
    match err {
        HibpError::MissingKey => SourceOutcomeKind::AuthRequired,
        HibpError::Unauthorized(_) | HibpError::Forbidden(_) => SourceOutcomeKind::AuthRejected,
        HibpError::PlanNotEntitled { .. } => SourceOutcomeKind::EntitlementDenied,
        HibpError::RateLimited { .. } => SourceOutcomeKind::RateLimited,
        HibpError::Server { .. } => SourceOutcomeKind::Upstream5xx,
        HibpError::BadRequest(_) | HibpError::UnexpectedStatus { .. } => {
            SourceOutcomeKind::Upstream4xx
        }
        HibpError::Decode(_) => SourceOutcomeKind::SchemaDrift,
        HibpError::Transport(_) => SourceOutcomeKind::ConnectFailure,
        HibpError::InvalidInput(_) | HibpError::OAuth(_) => SourceOutcomeKind::Inconclusive,
    }
}

fn seed_entity(email: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, email, 0.99, scan_id);
    entity.tag("seed");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied email selector",
    ));
    entity
}

/// The address as listed in one HIBP incident. The evidence keeps every field of the incident:
/// the plain-text summary, the reference links (space-separated; a kept link holds no
/// whitespace), the dates, the attribution and each status flag the source sends.
fn breach_entity(email: &str, scan_id: &str, incident: &Incident) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, email, 0.90, scan_id);
    if incident.has_flag(STEALER_LOG) {
        entity.tag(tags::STEALER_LOG);
    }
    entity.tag(tags::BREACH);
    if incident.has_flag(FABRICATED) {
        entity.tag(tags::FABRICATED_BREACH);
    }
    if incident.has_flag(SPAM_LIST) {
        entity.tag(tags::SPAM_LIST);
    }

    let cautions: Vec<&str> = incident
        .flags()
        .filter(|flag| caution(flag).is_some())
        .collect();
    let summary = if cautions.is_empty() {
        format!("Address listed in HIBP breach {}", incident.name)
    } else {
        format!(
            "Address listed in HIBP breach {}, which the source flags as {}",
            incident.name,
            cautions.join(" and ")
        )
    };
    let mut evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("breach_name", &incident.name)
        .with_attr("data_classes", incident.data_classes.join(", "));
    let references = incident.references.join(" ");
    for (key, value) in [
        ("breach_title", incident.title.as_deref()),
        ("breach_domain", incident.domain.as_deref()),
        ("breach_date", incident.breach_date.as_deref()),
        ("breach_added_date", incident.added_date.as_deref()),
        ("breach_modified_date", incident.modified_date.as_deref()),
        ("breach_attribution", incident.attribution.as_deref()),
        ("breach_summary", incident.summary.as_deref()),
        (
            "breach_references",
            Some(references.as_str()).filter(|links| !links.is_empty()),
        ),
    ] {
        if let Some(value) = value {
            evidence = evidence.with_attr(key, value);
        }
    }
    if let Some(count) = incident.pwn_count {
        evidence = evidence.with_attr("pwn_count", count.to_string());
    }
    if let Some(verified) = incident.verified {
        evidence = evidence.with_attr("breach_verified", verified.to_string());
    }
    for flag in &incident.status {
        evidence = evidence.with_attr(flag_attribute(flag.label), flag.set.to_string());
    }
    entity.add_evidence(evidence);
    entity
}

/// `html` as readable plain text: tags removed (a block tag reads as a space), comments and the
/// content of `script` and `style` dropped, character references decoded, whitespace collapsed,
/// and at most `max_chars` characters, the last of them [`ELLIPSIS`] when the text was cut.
/// `None` when no text is left. Malformed markup cannot make it panic or loop: a `<` that opens
/// no complete tag is text, and every step moves forward through the input.
fn html_to_text(html: &str, max_chars: usize) -> Option<String> {
    let mut raw = String::with_capacity(html.len());
    for piece in Markup::new(html) {
        match piece {
            Piece::Text(text) => raw.push_str(text),
            Piece::Tag { name, .. }
                if BLOCK_ELEMENTS
                    .iter()
                    .any(|block| name.eq_ignore_ascii_case(block)) =>
            {
                raw.push(' ');
            }
            Piece::Tag { .. } | Piece::Ignored => {}
        }
    }
    let decoded = decode_html_entities(&raw);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() || max_chars == 0 {
        return None;
    }
    if collapsed.chars().nth(max_chars).is_none() {
        return Some(collapsed);
    }
    let keep = max_chars - 1;
    let cut = collapsed
        .char_indices()
        .nth(keep)
        .map_or(collapsed.len(), |(index, _)| index);
    let mut out = collapsed
        .get(..cut)
        .unwrap_or_default()
        .trim_end()
        .to_owned();
    out.push(ELLIPSIS);
    Some(out)
}

/// The http(s) links of the anchor (`a`) tags in `html`, canonicalised by [`canonical_url`],
/// in first-seen order without repeats, at most `max`. A `javascript:`, `data:`, `mailto:` or
/// relative link, an empty `href`, a link longer than [`MAX_REFERENCE_BYTES`] and one holding
/// whitespace or a control character are dropped. Only links the source wrote are returned.
fn reference_links(html: &str, max: usize) -> Vec<String> {
    let mut links: Vec<String> = Vec::new();
    for piece in Markup::new(html) {
        if links.len() >= max {
            break;
        }
        let Piece::Tag {
            name,
            end: false,
            attrs,
        } = piece
        else {
            continue;
        };
        if !name.eq_ignore_ascii_case("a") {
            continue;
        }
        let Some(link) = attribute(attrs, "href").and_then(reference_url) else {
            continue;
        };
        if !links.contains(&link) {
            links.push(link);
        }
    }
    links
}

/// The canonical form of one `href` value when it is a usable http(s) link.
fn reference_url(href: &str) -> Option<String> {
    let decoded = decode_html_entities(href);
    let url = canonical_url(decoded.trim())?;
    let clean = url.len() <= MAX_REFERENCE_BYTES
        && !url.chars().any(|c| c.is_whitespace() || is_escaped(c));
    clean.then_some(url)
}

/// The value of the attribute `wanted` (ASCII case ignored) in the attribute text of a start tag.
/// A quoted value runs to its closing quote and an unquoted one to the next whitespace. The first
/// occurrence decides, as in HTML. An attribute with no value, or a quote that never closes, gives
/// `None`. Each step consumes at least one character, so the scan ends.
fn attribute<'a>(attrs: &'a str, wanted: &str) -> Option<&'a str> {
    let mut rest = attrs;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '/');
        if rest.is_empty() {
            return None;
        }
        let name_len = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '=' || c == '/')
            .unwrap_or(rest.len());
        let name = rest.get(..name_len)?;
        let after_name = rest
            .get(name_len..)?
            .trim_start_matches(|c: char| c.is_ascii_whitespace());
        let (value, after) = match after_name.strip_prefix('=') {
            None => (None, after_name),
            Some(value) => {
                let value = value.trim_start_matches(|c: char| c.is_ascii_whitespace());
                if let Some(quote @ ('"' | '\'')) = value.chars().next() {
                    let body = value.get(1..)?;
                    match body.find(quote) {
                        Some(close) => (body.get(..close), body.get(close + 1..)?),
                        None => (None, ""),
                    }
                } else {
                    let len = value
                        .find(|c: char| c.is_ascii_whitespace())
                        .unwrap_or(value.len());
                    (value.get(..len), value.get(len..)?)
                }
            }
        };
        if !name.is_empty() && name.eq_ignore_ascii_case(wanted) {
            return value;
        }
        rest = after;
    }
}

/// One piece of an HTML fragment, as [`Markup`] reads it.
enum Piece<'a> {
    /// Text between tags, its character references still encoded.
    Text(&'a str),
    /// A start or end tag: its name as written, and for a start tag the text of its attributes.
    Tag {
        name: &'a str,
        end: bool,
        attrs: &'a str,
    },
    /// A comment, a declaration, a processing instruction, or a `script` or `style` element.
    Ignored,
}

/// A forward-only reader of an HTML fragment. A `<` opens markup only when a letter, `/` and a
/// letter, `!` or `?` follows it and a `>` closes it; any other `<` is text. In a tag, a `>`
/// inside a quoted attribute value does not close it, as in [`attribute`]. Markup that never
/// closes is text, and so is everything after it: each search starts where the last one ended,
/// and none is repeated after one fails, so reading is linear in the input even when it is
/// malformed.
struct Markup<'a> {
    html: &'a str,
    /// `html` with ASCII letters lower-cased: the same bytes at the same offsets otherwise, for
    /// case-insensitive searches.
    lower: String,
    pos: usize,
    /// Markup at or before `pos` never closed, so the rest of the input is text.
    no_close: bool,
    /// No `-->` at or after `pos`.
    no_comment_close: bool,
}

/// The offset in `tag` (the text after a tag's `<`) of the `>` that closes it, or `None` when the
/// input ends first. A quote right after an `=` (spaces allowed between) opens a value that runs to
/// the same quote; any other quote is an ordinary character.
fn tag_close(tag: &str) -> Option<usize> {
    let bytes = tag.as_bytes();
    let mut index = 0;
    let mut after_equals = false;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'>' => return Some(index),
            b'=' => after_equals = true,
            b'"' | b'\'' if after_equals => {
                let value = tag.get(index + 1..)?;
                index += 1 + value.find(char::from(byte))?;
                after_equals = false;
            }
            _ if byte.is_ascii_whitespace() => {}
            _ => after_equals = false,
        }
        index += 1;
    }
    None
}

impl<'a> Markup<'a> {
    fn new(html: &'a str) -> Self {
        Self {
            html,
            lower: html.to_ascii_lowercase(),
            pos: 0,
            no_close: false,
            no_comment_close: false,
        }
    }

    /// The markup that the `<` at `start` opens and the offset just past it, or `None` when that
    /// `<` is text.
    fn markup_at(&mut self, start: usize) -> Option<(Piece<'a>, usize)> {
        if self.no_close {
            return None;
        }
        let after = self.html.get(start + 1..)?;
        let mut bytes = after.bytes();
        let first = bytes.next()?;
        let second = bytes.next();
        if after.starts_with("!--") && !self.no_comment_close {
            let body = start + 4;
            match self.lower.get(body..)?.find("-->") {
                Some(offset) => return Some((Piece::Ignored, body + offset + 3)),
                None => self.no_comment_close = true,
            }
        }
        let end_tag = first == b'/';
        let tag = first.is_ascii_alphabetic()
            || (end_tag && second.is_some_and(|b| b.is_ascii_alphabetic()));
        if !tag && !matches!(first, b'!' | b'?') {
            return None;
        }
        let closed = if tag {
            tag_close(after)
        } else {
            after.find('>')
        };
        let Some(offset) = closed else {
            self.no_close = true;
            return None;
        };
        let gt = start + 1 + offset;
        let next = gt + 1;
        if !tag {
            return Some((Piece::Ignored, next));
        }
        let inner = self.html.get(start + 1 + usize::from(end_tag)..gt)?;
        let name_len = inner.bytes().take_while(u8::is_ascii_alphanumeric).count();
        let name = inner.get(..name_len)?;
        let attrs = inner.get(name_len..)?;
        let raw_text = ["script", "style"]
            .into_iter()
            .find(|element| name.eq_ignore_ascii_case(element));
        if let (Some(element), false) = (raw_text, end_tag) {
            // The element's content is not text: skip to its end tag, or to the end of input.
            let end_marker = format!("</{element}");
            let resume = self
                .lower
                .get(next..)
                .and_then(|rest| rest.find(&end_marker))
                .map_or(self.html.len(), |offset| {
                    let after_marker = next + offset + end_marker.len();
                    self.html
                        .get(after_marker..)
                        .and_then(|rest| rest.find('>'))
                        .map_or(self.html.len(), |end| after_marker + end + 1)
                });
            return Some((Piece::Ignored, resume));
        }
        Some((
            Piece::Tag {
                name,
                end: end_tag,
                attrs,
            },
            next,
        ))
    }
}

impl<'a> Iterator for Markup<'a> {
    type Item = Piece<'a>;

    fn next(&mut self) -> Option<Piece<'a>> {
        let rest = self.html.get(self.pos..).filter(|rest| !rest.is_empty())?;
        if !rest.starts_with('<') {
            let len = rest.find('<').unwrap_or(rest.len());
            self.pos += len;
            return rest.get(..len).map(Piece::Text);
        }
        let start = self.pos;
        if let Some((piece, next)) = self.markup_at(start) {
            self.pos = next;
            return Some(piece);
        }
        self.pos = start + 1;
        Some(Piece::Text("<"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_makes_no_request_and_reports_auth_required() {
        let ExposureRun::Printed { report, text } = run(Sources::default(), "Ada@Example.com", 7)
        else {
            panic!("expected a printed report");
        };
        let legs: Vec<_> = report
            .outcomes
            .iter()
            .map(|o| (o.module.as_str(), o.kind))
            .collect();
        assert_eq!(
            legs,
            [
                (SOURCE, SourceOutcomeKind::AuthRequired),
                (STOLEN_TAX_SOURCE, SourceOutcomeKind::AuthRequired)
            ],
            "every keyed leg is reported, in breach_hybrid order"
        );
        assert_eq!(report.entities.len(), 1);
        assert!(!report.entities[0].tags.iter().any(|t| t == tags::BREACH));
        assert_eq!(report.incidents, None, "no answer is not a zero");
        assert!(text.ends_with("\nincidents=none\n"), "{text}");

        // The HIBP leg names the free self-service route; stolen.tax, which has none, does not.
        let detail = |module: &str| {
            report
                .outcomes
                .iter()
                .find(|o| o.module == module)
                .and_then(|o| o.detail.clone())
                .unwrap_or_default()
        };
        assert!(
            detail(SOURCE).contains("https://haveibeenpwned.com/"),
            "{}",
            detail(SOURCE)
        );
        assert!(
            !detail(STOLEN_TAX_SOURCE).contains("haveibeenpwned"),
            "{}",
            detail(STOLEN_TAX_SOURCE)
        );
    }

    #[test]
    fn each_hibp_breach_is_evidence_on_the_one_email_entity() {
        let (text, report, urls) = run_with(&serde_json::json!([
            {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
             "PwnCount": 152_445_165, "DataClasses": ["Email addresses", "Passwords"],
             "IsVerified": true, "IsStealerLog": false},
            {"Name": "Logs", "DataClasses": ["Email addresses"], "IsStealerLog": true}
        ]));
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert!(urls[0].contains("/breachedaccount/"), "{urls:?}");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcomes[0].found, Some(2));
        assert_eq!(report.entities.len(), 1, "merged by uid: {text}");
        let entity = &report.entities[0];
        assert!(entity.tags.iter().any(|t| t == tags::BREACH));
        assert!(entity.tags.iter().any(|t| t == tags::STEALER_LOG));
        let breaches: Vec<_> = entity
            .evidence
            .iter()
            .filter_map(|e| e.attributes.get("breach_name"))
            .collect();
        assert_eq!(breaches.len(), 2, "{breaches:?}");
    }

    #[test]
    fn invalid_address_fails() {
        assert!(matches!(
            run(Sources::default(), "not-an-email", 7),
            ExposureRun::Failed(_)
        ));
    }

    /// Answers every request with one 200 JSON body and records each requested URL.
    struct FakeHibp {
        body: String,
        urls: std::sync::Mutex<Vec<String>>,
    }

    impl Transport for FakeHibp {
        fn send(
            &self,
            request: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            self.urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.url.clone());
            Ok(crate::test_support::json_ok(&self.body))
        }
    }

    /// Runs `exposure` for one fixed address against a fake HIBP that answers `breaches`, with
    /// local pacing off so the tests never wait on the shared limiter.
    fn run_with(breaches: &serde_json::Value) -> (String, Report, Vec<String>) {
        let transport = std::sync::Arc::new(FakeHibp {
            body: breaches.to_string(),
            urls: std::sync::Mutex::default(),
        });
        let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
            panic!("the fixture key is a valid HIBP key");
        };
        let client = HibpClient::with_config(
            transport.clone(),
            crate::hibp::client::Auth::ApiKey(key),
            crate::hibp::client::HibpConfig::default(),
            std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
        );
        let sources = Sources {
            hibp: Some(&client),
            stolen_tax: None,
        };
        let ExposureRun::Printed { text, report } = run(sources, "ada@example.com", 7) else {
            panic!("expected a printed report");
        };
        let urls = transport
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (text, report, urls)
    }

    /// The attribute `key` of the HIBP evidence for breach `name`.
    fn breach_attr<'a>(report: &'a Report, name: &str, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .flat_map(|entity| &entity.evidence)
            .find(|evidence| {
                evidence.attributes.get("breach_name").map(String::as_str) == Some(name)
            })
            .and_then(|evidence| evidence.attributes.get(key))
            .map(String::as_str)
    }

    /// Nested tags, the common entities, one link twice (once with a fragment and mixed-case
    /// host), and a `javascript:`, a relative and a `mailto:` link.
    const ADOBE_DESCRIPTION: &str = "<p>In October 2013, <b>153 <i>million</i></b> Adobe \
        accounts were <a href=\"https://KrebsOnSecurity.com/2013/10/adobe-breach/#top\" \
        target=\"_blank\" rel=\"noopener\">breached</a> &amp; each held an ID, email \
        &lt;address&gt;, &quot;encrypted&quot; password and a hint&#39;s text. Hints \
        <a href='https://www.troyhunt.com/adobe-credentials-and-serious/'>disclosed&nbsp;much\
        </a>&#x2014;see <a href=\"https://krebsonsecurity.com/2013/10/adobe-breach/\">the \
        report</a> again, <a href=\"javascript:alert(1)\">this</a>, <a href=\"/breach/Adobe\">\
        that</a> and <a href=\"mailto:x@example.com\">mail</a>.</p>";

    const ADOBE_SUMMARY: &str = "In October 2013, 153 million Adobe accounts were breached & \
        each held an ID, email <address>, \"encrypted\" password and a hint's text. Hints \
        disclosed much\u{2014}see the report again, this, that and mail.";

    const ADOBE_REFERENCES: [&str; 2] = [
        "https://krebsonsecurity.com/2013/10/adobe-breach/",
        "https://www.troyhunt.com/adobe-credentials-and-serious/",
    ];

    #[test]
    fn each_incident_shows_its_summary_and_the_links_its_source_gives() {
        let (text, report, _) = run_with(&serde_json::json!([{
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "ModifiedDate": "2022-05-15T23:52:49Z",
            "PwnCount": 152_445_165,
            "Description": ADOBE_DESCRIPTION,
            "Attribution": "Data provided by a researcher",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": true,
            "IsFabricated": false,
            "IsSensitive": false,
            "IsRetired": false,
            "IsSpamList": false,
            "IsMalware": false,
            "IsStealerLog": false
        }]));

        assert!(text.contains("\nincidents=1\n"), "{text}");
        assert!(
            text.contains(
                "\nincident\tAdobe\ttitle=Adobe\tbreach_date=2013-10-04\t\
                 added=2013-12-04T00:00:00Z\tdomain=adobe.com\taccounts=152445165\t\
                 verified=true\tflags=none\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(&format!("\nsummary\tAdobe\t{ADOBE_SUMMARY}\n")),
            "{text}"
        );
        let references: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_prefix("reference\tAdobe\t"))
            .collect();
        assert_eq!(references, ADOBE_REFERENCES, "{text}");
        assert!(
            text.contains("\nattribution\tAdobe\tData provided by a researcher\n"),
            "{text}"
        );

        assert_eq!(
            breach_attr(&report, "Adobe", "breach_summary"),
            Some(ADOBE_SUMMARY)
        );
        assert_eq!(
            breach_attr(&report, "Adobe", "breach_references"),
            Some(ADOBE_REFERENCES.join(" ").as_str())
        );
        for (key, value) in [
            ("breach_added_date", "2013-12-04T00:00:00Z"),
            ("breach_modified_date", "2022-05-15T23:52:49Z"),
            ("breach_attribution", "Data provided by a researcher"),
            ("breach_fabricated", "false"),
            ("breach_sensitive", "false"),
            ("breach_retired", "false"),
            ("breach_spam_list", "false"),
            ("breach_malware", "false"),
            ("breach_stealer_log", "false"),
        ] {
            assert_eq!(breach_attr(&report, "Adobe", key), Some(value), "{key}");
        }
        assert_eq!(
            breach_attr(&report, "Adobe", "breach_subscription_free"),
            None,
            "a flag the source does not send is not invented"
        );
    }

    /// The incidents section of a report: from its count line to the end.
    fn incidents_section(text: &str) -> &str {
        let Some(start) = text.find("\nincidents=") else {
            panic!("no incidents section: {text}");
        };
        &text[start + 1..]
    }

    #[test]
    fn a_fabricated_or_spam_list_incident_is_unmistakable() {
        let (text, report, _) = run_with(&serde_json::json!([
            {"Name": "Genuine", "Description": "<p>A real breach.</p>", "IsVerified": true,
             "IsFabricated": false, "IsSpamList": false},
            {"Name": "Fake", "Domain": "fake.example", "Description": "<p>Not real.</p>",
             "IsVerified": false, "IsFabricated": true, "IsSpamList": false},
            {"Name": "Spammy", "Description": "<p>A list.</p>", "IsVerified": true,
             "IsFabricated": false, "IsSpamList": true}
        ]));
        let section = incidents_section(&text);
        let fabricated = caution(FABRICATED).unwrap_or_default();
        let spam_list = caution(SPAM_LIST).unwrap_or_default();
        assert!(!fabricated.is_empty() && !spam_list.is_empty());
        assert_eq!(
            section,
            format!(
                "incidents=3\n\
                 incident\tFake\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=fake.example\taccounts=unknown\tverified=false\tflags=fabricated\n\
                 caution\tFake\t{fabricated}\n\
                 summary\tFake\tNot real.\n\
                 incident\tGenuine\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=unknown\taccounts=unknown\tverified=true\tflags=none\n\
                 summary\tGenuine\tA real breach.\n\
                 incident\tSpammy\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=unknown\taccounts=unknown\tverified=true\tflags=spam-list\n\
                 caution\tSpammy\t{spam_list}\n\
                 summary\tSpammy\tA list.\n"
            ),
            "the domain is shown as a domain, never as a guessed link"
        );

        assert_eq!(
            breach_attr(&report, "Fake", "breach_fabricated"),
            Some("true")
        );
        assert_eq!(
            breach_attr(&report, "Spammy", "breach_spam_list"),
            Some("true")
        );
        assert_eq!(
            breach_attr(&report, "Genuine", "breach_fabricated"),
            Some("false")
        );
        let summaries: Vec<&str> = report
            .entities
            .iter()
            .flat_map(|entity| &entity.evidence)
            .map(|evidence| evidence.summary.as_str())
            .collect();
        for expected in [
            "Address listed in HIBP breach Fake, which the source flags as fabricated",
            "Address listed in HIBP breach Spammy, which the source flags as spam-list",
            "Address listed in HIBP breach Genuine",
        ] {
            assert!(summaries.contains(&expected), "{summaries:?}");
        }
        let Some(entity) = report
            .entities
            .iter()
            .find(|e| e.tags.iter().any(|t| t == tags::BREACH))
        else {
            panic!("no breach entity: {text}");
        };
        for tag in [tags::FABRICATED_BREACH, tags::SPAM_LIST] {
            assert!(
                entity.tags.iter().any(|t| t == tag),
                "{tag}: {:?}",
                entity.tags
            );
        }
        assert!(
            text.contains("seed,breach,fabricated-breach,spam-list"),
            "the tags reach the entity row: {text}"
        );
    }

    #[test]
    fn an_over_long_description_is_cut_on_a_character_boundary() {
        // Twelve characters, three of them more than one byte, 1,200 in all.
        let long = "Z\u{fc}rich \u{2013} \u{6771}\u{4eac} ".repeat(100);
        let (text, report, _) = run_with(&serde_json::json!([
            {"Name": "Long", "Description": format!("<p>{long}</p>")}
        ]));
        let Some(summary) = breach_attr(&report, "Long", "breach_summary") else {
            panic!("no summary: {text}");
        };
        assert_eq!(summary.chars().count(), MAX_SUMMARY_CHARS, "{summary}");
        let Some(kept) = summary.strip_suffix(ELLIPSIS) else {
            panic!("a cut summary ends with an ellipsis: {summary}");
        };
        assert!(
            long.starts_with(kept),
            "the summary is a prefix of the text"
        );
        assert!(
            kept.ends_with('\u{4eac}'),
            "the cut follows a 3-byte character"
        );
        assert!(
            text.contains(&format!("\nsummary\tLong\t{summary}\n")),
            "{text}"
        );
    }

    #[test]
    fn control_characters_from_the_source_are_escaped_in_the_output() {
        let (text, report, _) = run_with(&serde_json::json!([{
            "Name": "Evil\u{1b}[2J",
            "Title": "Title\nforged\trow",
            "Domain": "evil.example\u{1b}]0;owned\u{7}",
            "Description": "<p>Clear\u{1b}[2J screen &#x1b;[31mred\u{7f} nul\u{0} \
                bidi\u{202e}txt <a href=\"https://evil.example/\u{1b}[1m\">x</a> \
                <a href=\"https://evil.example/ok\">ok</a></p>",
            "Attribution": "Credit\u{1b}[5m",
            "DataClasses": ["Email\u{1b}[0m addresses"]
        }]));
        let section = incidents_section(&text);
        assert!(
            crate::test_support::unexpected_controls(&text, &['\n', '\t']).is_empty(),
            "a control character other than the report's own separators: {text:?}"
        );
        let kinds = [
            "incident",
            "caution",
            "summary",
            "data_classes",
            "attribution",
            "reference",
        ];
        for line in section.lines().skip(1) {
            assert!(
                kinds
                    .iter()
                    .any(|kind| line.starts_with(&format!("{kind}\t"))),
                "text inside a value became a row of its own: {line:?}"
            );
            assert!(!line.contains('\u{202e}'), "{line:?}");
        }
        let incident_row = section.lines().nth(1).unwrap_or_default();
        assert_eq!(incident_row.matches('\t').count(), 8, "{incident_row:?}");
        for escaped in [
            "incident\tEvil\\u{1b}[2J\ttitle=Title\\nforged\\trow\t",
            "domain=evil.example\\u{1b}]0;owned\\u{7}\t",
            "summary\tEvil\\u{1b}[2J\tClear\\u{1b}[2J screen \\u{1b}[31mred\\u{7f} nul\\u{0} \
             bidi\\u{202e}txt x ok\n",
            "attribution\tEvil\\u{1b}[2J\tCredit\\u{1b}[5m\n",
            "data_classes\tEvil\\u{1b}[2J\tEmail\\u{1b}[0m addresses\n",
            "reference\tEvil\\u{1b}[2J\thttps://evil.example/ok\n",
        ] {
            assert!(section.contains(escaped), "{escaped:?} in {section:?}");
        }
        assert_eq!(
            section.matches("\nreference\t").count(),
            1,
            "a link holding a control character is dropped: {section:?}"
        );
        assert_eq!(
            breach_attr(&report, "Evil\u{1b}[2J", "breach_summary"),
            Some("Clear\u{1b}[2J screen \u{1b}[31mred\u{7f} nul\u{0} bidi\u{202e}txt x ok"),
            "the evidence keeps the source's text; only the printed report escapes it"
        );
    }

    #[test]
    fn no_breaches_prints_a_zero_count_and_nothing_else() {
        let (text, report, urls) = run_with(&serde_json::json!([]));
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
        assert_eq!(report.incidents, Some(Vec::new()));
        assert_eq!(incidents_section(&text), "incidents=0\n", "{text}");
    }

    #[test]
    fn the_incidents_are_in_name_order_whatever_order_the_source_uses() {
        let breaches = [
            serde_json::json!({"Name": "Zeta", "Title": "Z", "Description": "<p>z</p>"}),
            serde_json::json!({"Name": "Alpha", "Title": "First Alpha"}),
            serde_json::json!({"Name": "Mid", "Description": "<a href=\"https://m.example/\">m</a>"}),
            serde_json::json!({"Name": "Alpha", "Title": "Second Alpha"}),
        ];
        let (forward, report, _) = run_with(&serde_json::Value::from(breaches.to_vec()));
        let names: Vec<&str> = report
            .incidents
            .iter()
            .flatten()
            .map(|incident| incident.name.as_str())
            .collect();
        assert_eq!(names, ["Alpha", "Mid", "Zeta"], "sorted, one per name");
        let section = incidents_section(&forward);
        assert!(
            section.contains("\tAlpha\ttitle=First Alpha\t"),
            "{section}"
        );
        assert!(!section.contains("Second Alpha"), "{section}");

        let mut rotated = breaches.to_vec();
        rotated.rotate_left(2);
        let (again, _, _) = run_with(&serde_json::Value::from(rotated));
        // Rotating moves the second Alpha record ahead of the first, so its title is kept instead.
        assert_eq!(
            incidents_section(&again).replace("Second Alpha", "First Alpha"),
            section,
            "the same incidents print the same section"
        );
        let (repeat, _, _) = run_with(&serde_json::Value::from(breaches.to_vec()));
        assert_eq!(repeat, forward, "the whole report is deterministic");
    }

    /// The HIBP evidence summaries in `report`, in order.
    fn hibp_summaries(report: &Report) -> Vec<&str> {
        report
            .entities
            .iter()
            .flat_map(|entity| &entity.evidence)
            .filter(|evidence| evidence.attributes.contains_key("breach_name"))
            .map(|evidence| evidence.summary.as_str())
            .collect()
    }

    #[test]
    fn a_repeated_breach_name_cannot_hide_a_flag_from_the_text() {
        // HIBP documents Name as unique, so only a malformed or hostile answer repeats one. The
        // later record carries the flags; whichever record comes first, the text, the evidence and
        // the tags must all show them, and must agree on the count. A descriptive field comes from
        // the first record that gives it: the domain, which only the flagged record gives, too.
        let genuine = serde_json::json!({
            "Name": "Alpha", "Title": "Genuine record", "BreachDate": "2020-01-01",
            "Description": "<a href=\"https://one.example/\">one</a>",
            "DataClasses": ["Email addresses"], "IsVerified": true,
            "IsFabricated": false, "IsSpamList": false
        });
        let flagged = serde_json::json!({
            "Name": "Alpha", "Title": "Fabricated record", "Domain": "alpha.example",
            "Description": "<a href=\"https://two.example/\">two</a> \
                            <a href=\"https://one.example/\">one</a>",
            "DataClasses": ["Passwords", "Email addresses"], "IsVerified": false,
            "IsFabricated": true, "IsSpamList": true, "IsMalware": true
        });
        let other = serde_json::json!({"Name": "Beta", "IsFabricated": false});
        let fabricated = caution(FABRICATED).unwrap_or_default();
        let spam_list = caution(SPAM_LIST).unwrap_or_default();
        assert!(!fabricated.is_empty() && !spam_list.is_empty());
        let expected_section = format!(
            "incidents=2\n\
             incident\tAlpha\ttitle=Genuine record\tbreach_date=2020-01-01\tadded=unknown\t\
             domain=alpha.example\taccounts=unknown\tverified=false\t\
             flags=fabricated,spam-list,malware\n\
             caution\tAlpha\t{fabricated}\n\
             caution\tAlpha\t{spam_list}\n\
             summary\tAlpha\tone\n\
             data_classes\tAlpha\tEmail addresses\n\
             reference\tAlpha\thttps://one.example\n\
             incident\tBeta\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
             domain=unknown\taccounts=unknown\tverified=unknown\tflags=none\n"
        );

        for (order, breaches) in [
            ("flagged second", [&genuine, &flagged, &other]),
            ("flagged first", [&flagged, &other, &genuine]),
        ] {
            let breaches: Vec<serde_json::Value> = breaches.into_iter().cloned().collect();
            let (text, report, _) = run_with(&serde_json::Value::from(breaches));
            let section = incidents_section(&text);
            if order == "flagged second" {
                assert_eq!(section, expected_section, "{order}");
            }
            for row in [
                "flags=fabricated,spam-list,malware\n",
                &format!("\ncaution\tAlpha\t{fabricated}\n"),
                &format!("\ncaution\tAlpha\t{spam_list}\n"),
                "verified=false\t",
            ] {
                assert!(section.contains(row), "{order}: {row:?} in {section}");
            }
            assert!(section.starts_with("incidents=2\n"), "{order}: {section}");
            assert!(
                text.contains("\nhibp_account\tsuccess\tfound=2\t"),
                "{order}: the outcome counts the incidents the section prints: {text}"
            );
            let detail = report.outcomes[0].detail.as_deref().unwrap_or_default();
            assert!(
                detail.contains("3 records") && detail.contains("2 breach names"),
                "{order}: the merge is on record: {detail:?}"
            );

            assert_eq!(
                hibp_summaries(&report),
                [
                    "Address listed in HIBP breach Alpha, which the source flags as fabricated \
                     and spam-list",
                    "Address listed in HIBP breach Beta",
                ],
                "{order}: one evidence per breach name, in name order"
            );
            for (key, value) in [
                ("breach_fabricated", "true"),
                ("breach_spam_list", "true"),
                ("breach_malware", "true"),
                ("breach_verified", "false"),
                ("breach_domain", "alpha.example"),
            ] {
                assert_eq!(
                    breach_attr(&report, "Alpha", key),
                    Some(value),
                    "{order}: {key}"
                );
            }
            let Some(entity) = report
                .entities
                .iter()
                .find(|e| e.tags.iter().any(|t| t == tags::BREACH))
            else {
                panic!("{order}: no breach entity: {text}");
            };
            for tag in [tags::FABRICATED_BREACH, tags::SPAM_LIST] {
                assert!(entity.tags.iter().any(|t| t == tag), "{order}: {tag}");
            }
        }
    }

    /// A record of breach `Alpha` with the title, `verified` value and status flags given.
    fn alpha(title: &str, verified: Option<bool>, status: &[(&'static str, bool)]) -> Incident {
        Incident {
            name: "Alpha".to_owned(),
            title: Some(title.to_owned()),
            verified,
            status: status
                .iter()
                .map(|&(label, set)| StatusFlag { label, set })
                .collect(),
            ..Incident::default()
        }
    }

    #[test]
    fn merging_records_keeps_every_caution_whatever_their_order() {
        let plain = alpha(
            "first",
            Some(true),
            &[(FABRICATED, false), ("retired", false)],
        );
        let flagged = alpha(
            "second",
            None,
            &[("sensitive", false), (SPAM_LIST, true), (FABRICATED, true)],
        );
        let unverified = alpha("third", Some(false), &[]);
        let other = Incident {
            name: "Beta".to_owned(),
            ..Incident::default()
        };
        let expected_status: Vec<StatusFlag> = [
            (FABRICATED, true),
            (SPAM_LIST, true),
            ("sensitive", false),
            ("retired", false),
        ]
        .into_iter()
        .map(|(label, set)| StatusFlag { label, set })
        .collect();

        for records in [
            [&plain, &flagged, &unverified, &other],
            [&other, &flagged, &unverified, &plain],
            [&unverified, &other, &plain, &flagged],
        ] {
            let records: Vec<Incident> = records.into_iter().cloned().collect();
            let first_title = records
                .iter()
                .find(|record| record.name == "Alpha")
                .and_then(|record| record.title.clone());
            let merged = merge_incidents(records);
            let names: Vec<&str> = merged.iter().map(|i| i.name.as_str()).collect();
            assert_eq!(names, ["Alpha", "Beta"]);
            let alpha = &merged[0];
            assert_eq!(alpha.title, first_title, "the first record's title is kept");
            assert_eq!(
                alpha.status, expected_status,
                "any true wins, a flag no record sends stays absent, in the fixed order"
            );
            assert_eq!(
                alpha.verified,
                Some(false),
                "verified only if no record denies it"
            );
            assert_eq!(merged[1].status, [], "{:?}", merged[1]);
        }
    }

    #[test]
    fn merging_records_fills_only_the_fields_the_first_record_lacks() {
        let mut only_true = alpha("a", Some(true), &[]);
        only_true.absorb(alpha("b", None, &[]));
        assert_eq!(only_true.verified, Some(true));
        assert_eq!(only_true.title.as_deref(), Some("a"));
        let mut unknown = alpha("a", None, &[]);
        unknown.absorb(alpha("b", None, &[]));
        assert_eq!(unknown.verified, None);

        let mut gaps = Incident {
            name: "Alpha".to_owned(),
            ..Incident::default()
        };
        gaps.absorb(Incident {
            name: "Alpha".to_owned(),
            domain: Some("alpha.example".to_owned()),
            data_classes: vec!["Passwords".to_owned()],
            references: vec!["https://alpha.example/news".to_owned()],
            ..Incident::default()
        });
        assert_eq!(gaps.domain.as_deref(), Some("alpha.example"));
        assert_eq!(gaps.data_classes, ["Passwords"]);
        assert_eq!(gaps.references, ["https://alpha.example/news"]);
        gaps.absorb(Incident {
            name: "Alpha".to_owned(),
            domain: Some("later.example".to_owned()),
            data_classes: vec!["Usernames".to_owned()],
            references: vec!["https://later.example/".to_owned()],
            ..Incident::default()
        });
        assert_eq!(gaps.domain.as_deref(), Some("alpha.example"));
        assert_eq!(gaps.data_classes, ["Passwords"]);
        assert_eq!(gaps.references, ["https://alpha.example/news"]);
    }

    #[test]
    fn a_saved_report_with_incidents_reloads_with_verify() {
        let (_, report, _) = run_with(&serde_json::json!([
            {"Name": "Adobe", "Description": ADOBE_DESCRIPTION, "IsFabricated": true}
        ]));
        let dir = std::env::temp_dir().join(format!(
            "huntsman-exposure-incidents-save-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("temporary directory: {err}");
        }
        let path = dir.join("exposure.json");
        let saved = crate::lookup_save::save(
            &path,
            &report.entities,
            &report.outcomes,
            crate::lookup_save::EXPOSURE_POLICY,
        );
        let loaded = crate::ledger::load_chain(&path);
        let _ = std::fs::remove_dir_all(&dir);
        let (Ok(saved), Ok(loaded)) = (saved, loaded) else {
            panic!("the exposure ledger must save and reload");
        };
        assert_eq!(loaded, saved);
        assert_eq!(saved.len(), report.outcomes.len() + report.entities.len());
    }

    #[test]
    fn html_to_text_reads_malformed_markup_without_panicking() {
        for (html, expected) in [
            ("Hello <b world", Some("Hello <b world")),
            (
                "<a title=\"1 > 0\" href='x>y'>link</a> text",
                Some("link text"),
            ),
            (
                "<a title=\"never closed>x</a> <b>y</b>",
                Some("<a title=\"never closed>x</a> <b>y</b>"),
            ),
            ("a < b > c", Some("a < b > c")),
            ("<<<>>>", Some("<<<>>>")),
            ("x<", Some("x<")),
            ("</", Some("</")),
            ("<!-- never closed", Some("<!-- never closed")),
            ("a<!-- hidden -->b", Some("ab")),
            ("a<!-- x > y -->b", Some("ab")),
            ("<!DOCTYPE html><?xml x?>text", Some("text")),
            ("<p>one</p><p>two<br/>three</p>", Some("one two three")),
            ("in<b>line</b>d", Some("inlined")),
            (
                "Before<script>alert('<p>')</script>After",
                Some("BeforeAfter"),
            ),
            ("Before<STYLE>p{}</style >After", Some("BeforeAfter")),
            ("Before<script>never closed", Some("Before")),
            ("&amp;lt;b&amp;gt;", Some("&lt;b&gt;")),
            (
                "&#39;&apos;&quot;&gt;&lt;&amp;&nbsp;&#x41;&#65;&bogus; &#xD800;",
                Some("''\"><& AA&bogus; &#xD800;"),
            ),
            ("  \t\n <p> </p> &nbsp; ", None),
            ("", None),
            ("<a href=\"x\">", None),
        ] {
            assert_eq!(html_to_text(html, 100).as_deref(), expected, "{html:?}");
        }
        assert_eq!(html_to_text("text", 0), None);
    }

    #[test]
    fn html_to_text_bounds_its_output_on_a_character_boundary() {
        assert_eq!(
            html_to_text("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", 3).as_deref(),
            Some("\u{e9}\u{e9}\u{2026}")
        );
        assert_eq!(
            html_to_text("\u{e9}\u{e9}\u{e9}", 3).as_deref(),
            Some("\u{e9}\u{e9}\u{e9}"),
            "text that fits is not cut"
        );
        assert_eq!(
            html_to_text("ab cd", 4).as_deref(),
            Some("ab\u{2026}"),
            "no space is left before the ellipsis"
        );
        assert_eq!(html_to_text("abc", 1).as_deref(), Some("\u{2026}"));
    }

    #[test]
    fn malformed_markup_takes_linear_time() {
        // Each of these makes a naive reader rescan the rest of the input at every `<`.
        for html in [
            "<a".repeat(50_000),
            "<!--".repeat(50_000),
            "<script>".repeat(50_000),
            "<a href=\"".repeat(50_000),
            format!("{}>", "<".repeat(50_000)),
        ] {
            let started = std::time::Instant::now();
            let text = html_to_text(&html, MAX_SUMMARY_CHARS);
            let links = reference_links(&html, MAX_REFERENCE_LINKS);
            assert!(links.is_empty(), "{links:?}");
            assert!(
                text.as_deref()
                    .is_none_or(|t| t.chars().count() <= MAX_SUMMARY_CHARS),
                "{text:?}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{} bytes took {:?}",
                html.len(),
                started.elapsed()
            );
        }
    }

    #[test]
    fn reference_links_keep_only_the_http_links_the_source_wrote() {
        for (html, expected) in [
            ("<a href=\"\">empty</a>", &[][..]),
            ("<a href=>empty</a><a href>bare</a><a>none</a>", &[]),
            (
                "<a href=https://example.com/unquoted>u</a>",
                &["https://example.com/unquoted"][..],
            ),
            ("<a href=\"https://example.com/open", &[]),
            ("<a href=\"https://example.com/never-quoted>x</a>", &[]),
            (
                "<a href='https://example.com/x' href=\"https://other.example/\">",
                &["https://example.com/x"],
            ),
            (
                "<A title=\"a > b\" HREF = \"https://Example.COM/y?utm_source=z&amp;b=2#frag\">",
                &["https://example.com/y?b=2"],
            ),
            (
                "<a href=\"javascript:alert(1)\">j</a><a href=\" JavaScript:x\">j</a>\
                 <a href=\"data:text/html,x\">d</a><a href=\"mailto:a@example.com\">m</a>\
                 <a href=\"/relative\">r</a><a href=\"relative.html\">r</a>\
                 <a href=\"//proto-relative.example/x\">p</a><a href=\"ftp://x.example/\">f</a>",
                &[],
            ),
            ("<a href=\"https://example.com/a b\">space</a>", &[]),
            ("<a href=\"https://user@example.com/\">userinfo</a>", &[]),
            (
                "<abbr href=\"https://example.com/\">x</abbr><link href=\"https://example.com/\">",
                &[],
            ),
            ("</a href=\"https://example.com/\">", &[]),
            ("< a href=\"https://example.com/\">", &[]),
            ("<a href=\"https://example.com/\"", &[]),
            ("<!-- <a href=\"https://hidden.example/\">h</a> -->", &[]),
            ("<script><a href=\"https://hidden.example/\"></script>", &[]),
            (
                "<a href=\"https://example.com/\">1</a><a href=\"HTTPS://EXAMPLE.COM:443\">2</a>",
                &["https://example.com"],
            ),
        ] {
            assert_eq!(
                reference_links(html, MAX_REFERENCE_LINKS),
                expected,
                "{html:?}"
            );
        }
        let too_long = format!(
            "<a href=\"https://example.com/{}\">",
            "x".repeat(MAX_REFERENCE_BYTES)
        );
        assert!(reference_links(&too_long, MAX_REFERENCE_LINKS).is_empty());
    }

    #[test]
    fn reference_links_are_capped_in_first_seen_order() {
        let anchors: Vec<String> = (0..20)
            .map(|n| format!("<a href=\"https://example.com/{n}\">{n}</a>"))
            .collect();
        let links = reference_links(&anchors.concat(), MAX_REFERENCE_LINKS);
        let expected: Vec<String> = (0..MAX_REFERENCE_LINKS)
            .map(|n| format!("https://example.com/{n}"))
            .collect();
        assert_eq!(links, expected);
    }

    #[test]
    fn hibp_errors_keep_their_cause() {
        assert_eq!(
            outcome_kind(&HibpError::Unauthorized("x".into())),
            SourceOutcomeKind::AuthRejected
        );
        assert_eq!(
            outcome_kind(&HibpError::Decode("x".into())),
            SourceOutcomeKind::SchemaDrift
        );
    }
}
