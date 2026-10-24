//! End-to-end front-end for `huntsman-recon exposure`.
//!
//! The address is canonicalised once, then the account-keyed legs of
//! [`breach_hybrid::exposure_order`] run at once, each on a thread of its own, and their answers
//! fold in that order: HIBP `breachedaccount`, then the stolen.tax cascade, then `OathNet` breach
//! search, then `DeHashed` exact-match search (addresses only). A lookup waits for its slowest leg,
//! not for every leg in turn, and its report is the one the legs gave when they ran in turn.
//! The keyless legs (Pwned Passwords, the HIBP
//! catalogue) are not keyed on an address and are not run here. Each HIBP breach
//! becomes evidence on the seed email entity, tagged `breach` or `stealer-log`;
//! stolen.tax entities are taken as that module builds them. Each `OathNet` breach
//! database becomes evidence on the seed email entity carrying its exposure metadata
//! (dataset, record count, exposed field types, dates) and every non-credential value
//! its records hold, a field whose name holds one of [`oathnet::CREDENTIAL_MARKERS`]
//! (an [`oathnet::NOT_A_CREDENTIAL`] aside), or a list or object with such a field
//! inside, only as exposed; the usernames and
//! other addresses in its records become pivots. Each `DeHashed` breach database
//! becomes evidence on the seed email entity carrying exposure metadata only
//! (dataset, record count, whether a password or hash is exposed), with the same
//! pivots. Everything flows
//! through `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`. A leg
//! without its key makes no request and records `NotConfigured`, never a zero.
//!
//! Each HIBP breach is also an [`Incident`]: the public context of the breach as
//! the source describes it. Its HTML description becomes a bounded plain-text
//! summary and the http(s) links the description itself gives; no URL is built
//! or guessed, so a domain stays a domain. The report text closes with an
//! incidents section, every third-party value written through
//! [`escape_controls`]. An incident describes a public breach, never the person:
//! being listed is evidence, not a verdict. A fabricated or spam-list incident is
//! flagged in the evidence, the entity tags and the text.
//!
//! When no breach source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69); a source that answered, even with an error, and
//! the seed alone, make it print.

use std::path::PathBuf;

use crate::breach_hybrid::{self, BreachLeg};
use crate::canonical::{canonical_email, canonical_url};
use crate::concurrent::{self, Job};
use crate::dehashed::{
    self, DehashedClient,
    exposure::{ExposureBreach, ExposureSearch},
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::hibp::client::HibpClient;
use crate::hibp::error::HibpError;
use crate::hibp::types::{BreachModel, BreachedAccountOptions};
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::module_selection::Selection;
use crate::oathnet::{self, OathnetError};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceReach, SourceRun};
use crate::stolen_tax::{self, StolenTaxError};
use crate::tags;
use crate::textnorm::{decode_html_entities, escape_controls, is_escaped};

pub const EXPOSURE_USAGE: &str = "usage: huntsman-recon exposure ADDR|HANDLE [--save FILE]";
pub const EXPOSURE_HELP: &str = "\
exposure ADDR|HANDLE [--save FILE]
Canonicalise the email address ADDR or the username HANDLE and run the keyed breach legs at once, reported in this order: HIBP breached-account (addresses only), then the stolen.tax cascade, then OathNet breach search, then DeHashed exact-match search (addresses only). The lookup takes as long as its slowest leg. A leg without its key makes no request and reports not_configured. Results are lineage-rendered entities. Then incidents=N (none when HIBP gave no answer) and, per HIBP breach sorted by name (a name the source repeats is shown once, keeping every flag any of its records sets): an incident row (title, breach and added dates, domain, account count, verified, flags), a caution row for a fabricated or spam-list breach, its summary, data classes, attribution, and the reference links its own description gives. This is public context about each breach, not a finding about the person. Then oathnet_breaches=N (none when OathNet gave no answer) and one oathnet_breach row per breach database: records, title, breach date, indexed range, whether a password or hash is exposed, and the exposed field types (at most 64, each named in ASCII letters, digits and _ within 48 bytes and shown in lower case; a field named otherwise is left out), followed by one oathnet_value row (field=value) per distinct non-credential value its records hold (at most 64 per field; a value over 1024 bytes is left out, never cut). A field whose name holds pass, pwd, hash or salt in any case is a credential, except that a pass beginning passport does not count: neither its value nor a list or object holding such a field at any depth is shown or kept. The row says a password or hash is exposed when such a field whose words name one holds a value, as a field or inside a list or object, even if the field's name is left out: a word beginning password, passwd, passwort, passphrase or passcode, a word pwd, pwdhash, passhash, userpass or salt, or pass or hash alone or beside another such word or one such as user, old or md5, but never a field that describes one (pwdLastSet, password_changed_at). Then dehashed_breaches=N (none when DeHashed gave no answer) and one dehashed_breach row per breach database: records and whether a password or hash is exposed; DeHashed rows carry no record value beyond usernames and addresses as pivots. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the HIBP breached-account leg.
pub const SOURCE: &str = "hibp_account";
/// The module a lookup asks for HIBP's account search by.
pub const HIBP_MODULE: &str = "hibp";
/// Source label for the stolen.tax leg.
pub const STOLEN_TAX_SOURCE: &str = "stolen_tax";
/// Source label for the `OathNet` leg.
pub const OATHNET_SOURCE: &str = oathnet::SOURCE;
/// Source label for the `DeHashed` leg. The same label the standalone collector uses, so both
/// paths relaying one `DeHashed` dataset share one evidence root family.
pub const DEHASHED_SOURCE: &str = dehashed::COLLECTOR_ID;

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

/// The configured legs. `None` means that leg has no operator key. The legs run at once, so a
/// leg's transport is shared with its thread and must be `Sync`.
#[derive(Clone, Copy, Default)]
pub struct Sources<'a> {
    pub hibp: Option<&'a HibpClient>,
    pub stolen_tax: Option<(&'a (dyn Transport + Sync), &'a Keys)>,
    pub oathnet: Option<(&'a (dyn Transport + Sync), &'a Keys)>,
    pub dehashed: Option<&'a DehashedClient>,
    /// The modules the lookup asks; `None` asks every one. A leg it leaves out sends nothing and
    /// leaves no row, configured or not.
    pub selection: Option<&'a Selection>,
}

impl Sources<'_> {
    /// Whether a lookup of `selector` would reach at least one keyed leg it asks: HIBP or
    /// `DeHashed` for an address, stolen.tax or `OathNet` for either. Another lookup of the same
    /// selector runs exposure when this holds, so a configured paid source is never left out of it.
    #[must_use]
    pub fn reach(&self, selector: &str) -> bool {
        let email = canonical_email(selector).is_some();
        let email_only = email
            && ((self.hibp.is_some() && self.runs(HIBP_MODULE))
                || (self.dehashed.is_some() && self.runs(DEHASHED_SOURCE)));
        canonical_selector(selector).is_some()
            && (email_only
                || (self.stolen_tax.is_some() && self.runs(STOLEN_TAX_SOURCE))
                || (self.oathnet.is_some() && self.runs(OATHNET_SOURCE)))
    }

    /// Whether the lookup asks `module`.
    #[must_use]
    pub fn runs(&self, module: &str) -> bool {
        self.selection
            .is_none_or(|selection| selection.runs(module))
    }
}

/// Fold an exposure `report` into another lookup's `entities` and `outcomes` for the same
/// selector, and render the combined report: one entity and outcome table, then the incidents
/// `OathNet` and `DeHashed` sections. The seed entity both lookups emit is merged by uid. On an error,
/// `entities` and `outcomes` are left as they were.
///
/// # Errors
/// The report renderer's error.
pub fn fold_into(
    entities: &mut Vec<Entity>,
    outcomes: &mut Vec<SourceExecutionOutcome>,
    report: Report,
) -> Result<String, String> {
    let Report {
        entities: found,
        outcomes: ran,
        incidents,
        oathnet,
        dehashed,
    } = report;
    let mut all_entities = entities.clone();
    all_entities.extend(found);
    merge_by_uid(&mut all_entities);
    let mut all_outcomes = outcomes.clone();
    all_outcomes.extend(ran);
    let mut text = lookup_report::render(&all_entities, &all_outcomes)?;
    text.push_str(&render_incidents(incidents.as_deref()));
    text.push_str(&render_oathnet(oathnet.as_deref()));
    text.push_str(&render_dehashed(dehashed.as_deref()));
    *entities = all_entities;
    *outcomes = all_outcomes;
    Ok(text)
}

/// The line that stands for an exposure run that gave no report, so the lookup it rode along
/// with still says the keyed legs were tried: `exposure=unavailable reason=...`.
#[must_use]
pub fn unavailable_line(reason: &str) -> String {
    format!("exposure=unavailable reason={}\n", escape_controls(reason))
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
    /// The breach databases `OathNet` lists the address in, sorted by name. `None` when `OathNet`
    /// gave no answer (no key, or a failed request), which is not a zero.
    pub oathnet: Option<Vec<oathnet::Breach>>,
    /// The breach databases `DeHashed` lists the address in, sorted by name. `None` when
    /// `DeHashed` gave no answer (no key, or a failed request), which is not a zero.
    pub dehashed: Option<Vec<ExposureBreach>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureArgs {
    /// A canonical email address or username, as [`canonical_selector`] gives it.
    pub selector: String,
    pub save: Option<PathBuf>,
}

impl ExposureArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "exposure needs exactly one ADDR")?;
        let selector = canonical_selector(&raw)
            .ok_or_else(|| Error::invalid_value("not an email address or username"))?;
        Ok(Self { selector, save })
    }
}

/// How an exposure lookup ended. A lookup no breach source answered ends through [`SourceReach`]:
/// a refusal is [`ExposureRun::Network`] (exit 77), no response is [`ExposureRun::Failed`] (exit
/// 69); a source that answered, even with an error, still prints, as does the seed alone.
pub type ExposureRun = SourceRun<Report>;

/// The selector an exposure lookup is keyed on: a canonical email address, else a username by
/// the `username` command's rule. An address always wins, so `a@b.com` is never a handle.
#[must_use]
pub fn canonical_selector(raw: &str) -> Option<String> {
    canonical_email(raw).or_else(|| crate::username_cli::canonical_username(raw).ok())
}

/// Run every configured account-keyed breach leg for `selector`, an email address or a
/// username. HIBP and `DeHashed` search addresses only, so a username skips them without a
/// request or an outcome; stolen.tax and `OathNet` search either. The legs run at once and fold
/// in [`breach_hybrid::exposure_order`].
#[must_use]
pub fn run(sources: Sources<'_>, selector: &str, now_unix: u64) -> ExposureRun {
    let Some(value) = canonical_selector(selector) else {
        return ExposureRun::Failed("not an email address or username".into());
    };
    let kind = if canonical_email(&value).is_some() {
        EntityKind::Email
    } else {
        EntityKind::Username
    };
    let scan_id = crate::entity::scan_id("exposure", &value);
    let mut report = Report {
        entities: vec![seed_entity(&kind, &value, &scan_id)],
        outcomes: Vec::new(),
        incidents: None,
        oathnet: None,
        dehashed: None,
    };
    let seed = (&kind, value.as_str());
    let jobs: Vec<Job<'_, Option<LegRun>>> = breach_hybrid::exposure_order(true)
        .into_iter()
        .filter(|&leg| searches(leg, &kind) && sources.runs(leg_module(leg)))
        .map(|leg| {
            let scan_id = scan_id.as_str();
            Box::new(move || run_leg(sources, leg, seed, scan_id, now_unix))
                as Job<'_, Option<LegRun>>
        })
        .collect();
    // Folded in the legs' order, so the entities and outcomes are the ones the legs gave when they
    // ran one after another.
    for ran in concurrent::all(jobs).into_iter().flatten() {
        let LegRun { outcome, found } = ran;
        report.entities.extend(found.entities);
        report.incidents = report.incidents.or(found.incidents);
        report.oathnet = report.oathnet.or(found.oathnet);
        report.dehashed = report.dehashed.or(found.dehashed);
        report.outcomes.push(outcome);
    }
    merge_by_uid(&mut report.entities);

    // No breach source answered: the lookup ends from its rows. A request refused before sending
    // is a refusal (exit 77); a source reached but silent is no usable response (exit 69); a
    // source that answered with an error still prints, as does the seed alone.
    if let Some(run) =
        SourceReach::of(&report.outcomes).stopped(&format!("no source answered for {value}"))
    {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(mut text) => {
            text.push_str(&render_incidents(report.incidents.as_deref()));
            text.push_str(&render_oathnet(report.oathnet.as_deref()));
            text.push_str(&render_dehashed(report.dehashed.as_deref()));
            ExposureRun::Printed { text, report }
        }
        Err(msg) => ExposureRun::Failed(msg),
    }
}

/// What one leg gave: its outcome row, and what it found (entities and its own section). How the
/// leg ended is read from its `outcome` row, like every other front-end's.
struct LegRun {
    outcome: SourceExecutionOutcome,
    found: Report,
}

/// Whether `leg` is run for a selector of `kind`. The keyless legs are not keyed on a selector,
/// and HIBP and `DeHashed` search addresses only, so a username sends them nothing.
fn searches(leg: BreachLeg, kind: &EntityKind) -> bool {
    match leg {
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => false,
        BreachLeg::HibpAccount | BreachLeg::DeHashed => *kind == EntityKind::Email,
        BreachLeg::StolenTax | BreachLeg::OathNet => true,
    }
}

/// The module a scan chooses `leg` by.
fn leg_module(leg: BreachLeg) -> &'static str {
    match leg {
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog | BreachLeg::HibpAccount => HIBP_MODULE,
        BreachLeg::StolenTax => STOLEN_TAX_SOURCE,
        BreachLeg::OathNet => OATHNET_SOURCE,
        BreachLeg::DeHashed => DEHASHED_SOURCE,
    }
}

/// Run one keyed leg on its own [`Report`]; a leg without its key makes no request. `None` for a
/// keyless leg, which is not keyed on a selector.
fn run_leg(
    sources: Sources<'_>,
    leg: BreachLeg,
    seed: (&EntityKind, &str),
    scan_id: &str,
    now_unix: u64,
) -> Option<LegRun> {
    let mut found = Report::default();
    let outcome = match leg {
        BreachLeg::HibpAccount => match sources.hibp {
            None => missing_key(SOURCE, now_unix),
            Some(client) => hibp_leg(client, seed.1, scan_id, now_unix, &mut found),
        },
        BreachLeg::StolenTax => match sources.stolen_tax {
            None => missing_key(STOLEN_TAX_SOURCE, now_unix),
            Some((transport, keys)) => {
                stolen_tax_leg(transport, keys, seed.1, scan_id, now_unix, &mut found)
            }
        },
        BreachLeg::OathNet => match sources.oathnet {
            None => missing_key(OATHNET_SOURCE, now_unix),
            Some((transport, keys)) => {
                oathnet_leg(transport, keys, seed, scan_id, now_unix, &mut found)
            }
        },
        BreachLeg::DeHashed => match sources.dehashed {
            None => missing_key(DEHASHED_SOURCE, now_unix),
            Some(client) => dehashed_leg(client, seed.1, scan_id, now_unix, &mut found),
        },
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => return None,
    };
    Some(LegRun { outcome, found })
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

/// The `OathNet` section that follows the incidents: `oathnet_breaches=N`, or `none` when `OathNet`
/// gave no answer, then one tab-separated `oathnet_breach` row per breach database, in name order:
/// records, title, breach date, indexed range, whether a password or hash is exposed, and the
/// exposed field types, each followed by one `oathnet_value` row per distinct non-credential value
/// its records hold. Every value is written through [`escape_controls`].
fn render_oathnet(breaches: Option<&[oathnet::Breach]>) -> String {
    let Some(breaches) = breaches else {
        return "oathnet_breaches=none\n".to_owned();
    };
    let mut out = format!("oathnet_breaches={}\n", breaches.len());
    for breach in breaches {
        let text = |value: &Option<String>| known(value.as_deref().map(escape_controls));
        let fields: Vec<&str> = breach.fields.iter().map(String::as_str).collect();
        let row = [
            "oathnet_breach".to_owned(),
            escape_controls(&breach.dbname),
            format!("records={}", breach.records),
            format!("title={}", text(&breach.title)),
            format!("breach_date={}", text(&breach.breach_date)),
            format!("first_indexed={}", text(&breach.first_indexed)),
            format!("last_indexed={}", text(&breach.last_indexed)),
            format!("password_exposed={}", breach.password_exposed),
            format!(
                "fields={}",
                if fields.is_empty() {
                    "unknown".to_owned()
                } else {
                    fields.join(",")
                }
            ),
        ];
        push_row(&mut out, &row);
        for (field, values) in &breach.values {
            for value in values {
                push_row(
                    &mut out,
                    &[
                        "oathnet_value".to_owned(),
                        escape_controls(&breach.dbname),
                        format!("{}={}", escape_controls(field), escape_controls(value)),
                    ],
                );
            }
        }
    }
    out
}

/// The `DeHashed` section that follows the `OathNet` section: `dehashed_breaches=N`, or `none`
/// when `DeHashed` gave no answer, then one tab-separated `dehashed_breach` row per breach
/// database, in name order: how many records hold the address and whether any of them exposes a
/// password or a hash. The database name is written through [`escape_controls`].
fn render_dehashed(breaches: Option<&[ExposureBreach]>) -> String {
    let Some(breaches) = breaches else {
        return "dehashed_breaches=none\n".to_owned();
    };
    let mut out = format!("dehashed_breaches={}\n", breaches.len());
    for breach in breaches {
        let row = [
            "dehashed_breach".to_owned(),
            escape_controls(&breach.dbname),
            format!("records={}", breach.records),
            format!("password_exposed={}", breach.password_exposed),
        ];
        push_row(&mut out, &row);
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
        SourceOutcomeKind::NotConfigured,
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
) -> SourceExecutionOutcome {
    let options = BreachedAccountOptions::full_model();
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
            let outcome = SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                outcome_kind(&err),
                err.http_status(),
                err.to_string(),
            );
            match err {
                // HIBP's client waits on the pause as sent; the outcome records it within the
                // bound every other leg's fetch applies.
                HibpError::RateLimited {
                    retry_after: Some(retry_after),
                } => outcome.with_retry_after(
                    retry_after
                        .as_secs()
                        .min(crate::fetch::MAX_RETRY_AFTER_SECS),
                ),
                _ => outcome,
            }
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
            let mut notes: Vec<String> = got
                .truncation
                .into_iter()
                .map(|why| format!("partial: {why}"))
                .collect();
            if got.unnamed_rows > 0 {
                notes.push(format!(
                    "{} row(s) name no breach or stealer host",
                    got.unnamed_rows
                ));
            }
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => {
            // The row keeps the kind the first failed path saw, so `SourceReach` reads a path
            // that got no response as a no-response (exit 69) and a path the source answered
            // with an error as reached, never as a refusal. A budget spent before any path was
            // sent (no failure to name) is the lookup's own timeout.
            let kind = match &err {
                StolenTaxError::MissingKey => SourceOutcomeKind::NotConfigured,
                StolenTaxError::Refused(_) => SourceOutcomeKind::RefusedBeforeSending,
                StolenTaxError::BudgetExhausted { failed, .. } => failed
                    .first()
                    .map_or(SourceOutcomeKind::BodyTimeout, |first| first.kind),
                StolenTaxError::Failed(first) => first.kind,
            };
            SourceExecutionOutcome::failed(STOLEN_TAX_SOURCE, now_unix, kind, None, err.to_string())
        }
    }
}

fn oathnet_leg(
    transport: &dyn Transport,
    keys: &Keys,
    seed: (&EntityKind, &str),
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    let query = if *seed.0 == EntityKind::Email {
        oathnet::Query::Email(seed.1)
    } else {
        oathnet::Query::Username(seed.1)
    };
    match oathnet::search(transport, keys, query, now_unix) {
        Ok(search) => {
            report
                .entities
                .extend(oathnet_entities(seed, scan_id, &search));
            let outcome = if search.records == 0 {
                SourceExecutionOutcome::valid_zero(OATHNET_SOURCE, now_unix)
            } else {
                SourceExecutionOutcome::success(OATHNET_SOURCE, now_unix, search.breaches.len())
            }
            .with_http_status(200);
            let mut notes: Vec<String> = search.truncation().into_iter().collect();
            if search.unnamed_records > 0 {
                notes.push(format!(
                    "{} record(s) name no breach database",
                    search.unnamed_records
                ));
            }
            report.oathnet = Some(search.breaches);
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => {
            let outcome = SourceExecutionOutcome::failed(
                OATHNET_SOURCE,
                now_unix,
                err.outcome_kind(),
                err.http_status(),
                err.to_string(),
            );
            match err {
                OathnetError::RateLimited {
                    retry_after: Some(secs),
                } => outcome.with_retry_after(secs),
                _ => outcome,
            }
        }
    }
}

/// One seed entity per `OathNet` breach database, carrying that breach's exposure metadata and the
/// non-credential values its records hold, then one pivot per distinct username and address in the
/// records other than the seed. A credential field's value never reaches an entity:
/// [`oathnet::decode`] keeps only that one was exposed (see [`oathnet::CREDENTIAL_MARKERS`]).
fn oathnet_entities(
    (seed_kind, seed): (&EntityKind, &str),
    scan_id: &str,
    search: &oathnet::Search,
) -> Vec<Entity> {
    let mut entities = Vec::new();
    for breach in &search.breaches {
        let mut entity = Entity::new(seed_kind.clone(), seed, 0.85, scan_id);
        entity.tag(tags::BREACH);
        if breach.password_exposed {
            entity.tag(tags::PASSWORD_AT_RISK);
        }
        let fields: Vec<&str> = breach.fields.iter().map(String::as_str).collect();
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(OATHNET_SOURCE, scan_id),
            format!(
                "Address listed in OathNet breach database {}",
                breach.dbname
            ),
        )
        .with_attr("dbname", &breach.dbname)
        .with_attr("records", breach.records.to_string())
        .with_attr("exposed_fields", fields.join(","))
        .with_attr("password_exposed", breach.password_exposed.to_string());
        for (key, value) in [
            ("breach_title", breach.title.as_deref()),
            ("breach_domain", breach.domain.as_deref()),
            ("breach_date", breach.breach_date.as_deref()),
            ("first_indexed", breach.first_indexed.as_deref()),
            ("last_indexed", breach.last_indexed.as_deref()),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(key, value);
            }
        }
        if let Some(count) = breach.pwn_count {
            evidence = evidence.with_attr("pwn_count", count.to_string());
        }
        // The de-redacted payload: every non-credential value each exposed field held (cleartext
        // passwords, hashes and salts are held back in `oathnet.rs`), keyed `value_<field>` so it
        // cannot clobber the metadata attributes above.
        for (field, values) in &breach.values {
            let joined = values.iter().cloned().collect::<Vec<_>>().join(", ");
            evidence = evidence.with_attr(format!("value_{field}"), joined);
        }
        entity.add_evidence(evidence);
        entities.push(entity);
    }
    let pivot_note = "Seen in an OathNet breach record that holds the queried address";
    // The seed itself is not a pivot. Records quote it as stored, so compare canonical forms.
    let is_seed = |kind: &EntityKind, value: &str| {
        kind == seed_kind && canonical_selector(value).as_deref() == Some(seed)
    };
    let others = search
        .emails
        .iter()
        .map(|other| (EntityKind::Email, other))
        .chain(search.usernames.iter().map(|u| (EntityKind::Username, u)))
        .filter(|(kind, value)| !is_seed(kind, value));
    for (kind, value) in others {
        let mut entity = Entity::new(kind, value, 0.50, scan_id);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(OATHNET_SOURCE, scan_id),
            pivot_note,
        ));
        entities.push(entity);
    }
    entities
}

fn dehashed_leg(
    client: &DehashedClient,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    match dehashed::exposure::search_email(client, email) {
        Ok(search) => {
            report
                .entities
                .extend(dehashed_entities(email, scan_id, &search));
            let outcome = if search.records == 0 {
                SourceExecutionOutcome::valid_zero(DEHASHED_SOURCE, now_unix)
            } else {
                SourceExecutionOutcome::success(DEHASHED_SOURCE, now_unix, search.breaches.len())
            }
            .with_http_status(200);
            let mut notes: Vec<String> = search.truncation().into_iter().collect();
            if search.unnamed_records > 0 {
                notes.push(format!(
                    "{} record(s) name no breach database",
                    search.unnamed_records
                ));
            }
            report.dehashed = Some(search.breaches);
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => err.outcome(DEHASHED_SOURCE, now_unix),
    }
}

/// One email entity per `DeHashed` breach database, carrying that breach's exposure metadata, then
/// one pivot per distinct username and per other address in the records. No record value other
/// than a username or address reaches an entity: [`dehashed::exposure::search_email`] keeps none.
fn dehashed_entities(email: &str, scan_id: &str, search: &ExposureSearch) -> Vec<Entity> {
    let mut entities = Vec::new();
    for breach in &search.breaches {
        let mut entity = Entity::new(EntityKind::Email, email, 0.85, scan_id);
        entity.tag(tags::BREACH);
        if breach.password_exposed {
            entity.tag(tags::PASSWORD_AT_RISK);
        }
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(DEHASHED_SOURCE, scan_id),
            format!(
                "Address listed in DeHashed breach database {}",
                breach.dbname
            ),
        )
        .with_attr("database_name", &breach.dbname)
        .with_attr("records", breach.records.to_string())
        .with_attr("password_exposed", breach.password_exposed.to_string());
        entity.add_evidence(evidence);
        entities.push(entity);
    }
    let pivot_note = "Seen in a DeHashed breach record that holds the queried address";
    let others = search
        .emails
        .iter()
        .filter(|other| canonical_email(other).as_deref() != Some(email))
        .map(|other| (EntityKind::Email, other));
    let usernames = search.usernames.iter().map(|u| (EntityKind::Username, u));
    for (kind, value) in others.chain(usernames) {
        let mut entity = Entity::new(kind, value, 0.50, scan_id);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(DEHASHED_SOURCE, scan_id),
            pivot_note,
        ));
        entities.push(entity);
    }
    entities
}

/// The outcome a failed HIBP lookup records. A failure without a response keeps the cause the
/// fetch observed, as the `OathNet` and `DeHashed` legs do.
fn outcome_kind(err: &HibpError) -> SourceOutcomeKind {
    match err {
        HibpError::MissingKey => SourceOutcomeKind::NotConfigured,
        HibpError::Unauthorized(_) | HibpError::Forbidden(_) => SourceOutcomeKind::AuthRejected,
        HibpError::PlanNotEntitled { .. } => SourceOutcomeKind::EntitlementDenied,
        HibpError::RateLimited { .. } => SourceOutcomeKind::RateLimited,
        HibpError::Server { .. } => SourceOutcomeKind::Upstream5xx,
        HibpError::BadRequest(_) | HibpError::UnexpectedStatus { .. } => {
            SourceOutcomeKind::Upstream4xx
        }
        HibpError::Decode(_) => SourceOutcomeKind::SchemaDrift,
        HibpError::Transport { kind, .. } | HibpError::NotAnAnswer(kind) => *kind,
        HibpError::Refused => SourceOutcomeKind::RefusedBeforeSending,
        HibpError::InvalidInput(_) | HibpError::OAuth(_) => SourceOutcomeKind::Inconclusive,
    }
}

fn seed_entity(kind: &EntityKind, value: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(kind.clone(), value, 0.99, scan_id);
    entity.tag("seed");
    let what = if *kind == EntityKind::Email {
        "operator-supplied email selector"
    } else {
        "operator-supplied username selector"
    };
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        what,
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
    fn no_key_makes_no_request_and_reports_not_configured() {
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
                (SOURCE, SourceOutcomeKind::NotConfigured),
                (STOLEN_TAX_SOURCE, SourceOutcomeKind::NotConfigured),
                (OATHNET_SOURCE, SourceOutcomeKind::NotConfigured),
                (DEHASHED_SOURCE, SourceOutcomeKind::NotConfigured)
            ],
            "every keyed leg is reported, in breach_hybrid order"
        );
        assert_eq!(report.entities.len(), 1);
        assert!(!report.entities[0].tags.iter().any(|t| t == tags::BREACH));
        assert_eq!(report.incidents, None, "no answer is not a zero");
        assert!(
            text.ends_with("\nincidents=none\noathnet_breaches=none\ndehashed_breaches=none\n"),
            "{text}"
        );

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
    fn the_help_describes_what_the_report_prints() {
        // A keyless leg's row, as the no-key test above sees it.
        let keyless = format!("reports {}.", SourceOutcomeKind::NotConfigured.as_str());
        assert!(EXPOSURE_HELP.contains(&keyless), "{EXPOSURE_HELP}");
        // Every OathNet column and row render_oathnet writes, values included.
        let rows = render_oathnet(Some(&[oathnet::Breach {
            dbname: "acme_forum".into(),
            records: 1,
            values: [(
                "phone_number".to_owned(),
                ["+15555550100".to_owned()].into(),
            )]
            .into(),
            ..oathnet::Breach::default()
        }]));
        assert!(
            rows.contains("\ttitle=") && rows.contains("oathnet_value\t"),
            "{rows}"
        );
        // What the decoder holds back and how far it reads, as `oathnet` defines them.
        let [pass, pwd, hash, salt] = oathnet::CREDENTIAL_MARKERS;
        for named in [
            "oathnet_breach row per breach database: records, title,".to_owned(),
            "one oathnet_value row (field=value) per distinct non-credential value".to_owned(),
            format!("(at most {}, each named", oathnet::MAX_FIELDS),
            format!("within {} bytes", oathnet::MAX_FIELD_BYTES),
            format!("(at most {} per field;", oathnet::MAX_VALUES_PER_FIELD),
            format!("a value over {} bytes", oathnet::MAX_VALUE_BYTES),
            format!("A field whose name holds {pass}, {pwd}, {hash} or {salt} in any case"),
            format!(
                "a {pass} beginning {} does not count",
                oathnet::NOT_A_CREDENTIAL
            ),
            "neither its value nor a list or object holding such a field".to_owned(),
            "such a field whose words name one holds a value, as a field or inside a list or \
             object, even if the field's name is left out"
                .to_owned(),
            match oathnet::PASSWORD_WORDS {
                [first @ .., last] => format!("a word beginning {} or {last}", first.join(", ")),
            },
            match oathnet::PASSWORD_NAMES {
                [first @ .., last] => format!("a word {} or {last}", first.join(", ")),
            },
            "never a field that describes one (pwdLastSet, password_changed_at)".to_owned(),
        ] {
            assert!(EXPOSURE_HELP.contains(&named), "{named:?}: {EXPOSURE_HELP}");
        }
        assert!(
            !EXPOSURE_HELP.contains("No record value other than"),
            "OathNet values are printed: {EXPOSURE_HELP}"
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
    fn a_selector_that_is_neither_an_address_nor_a_username_fails() {
        for bad in ["not an email", "ada@", "", "ünï"] {
            assert!(
                matches!(run(Sources::default(), bad, 7), ExposureRun::Failed(_)),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn an_address_is_never_read_as_a_handle() {
        assert_eq!(
            canonical_selector(" Ada@Example.com ").as_deref(),
            Some("ada@example.com")
        );
        assert_eq!(canonical_selector("@Ada_99").as_deref(), Some("ada_99"));
    }

    fn oathnet_only<'a>(transport: &'a (dyn Transport + Sync), keys: &'a Keys) -> Sources<'a> {
        Sources {
            oathnet: Some((transport, keys)),
            ..Sources::default()
        }
    }

    fn oathnet_keys() -> Keys {
        Keys::parse(&format!(
            "{}=on-test-key-0123456789abcdef\n",
            oathnet::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"))
    }

    #[test]
    fn a_configured_keyed_leg_reaches_every_selector_it_can_search() {
        let transport = Counting::default();
        let keys = oathnet_keys();
        assert!(
            !Sources::default().reach("ada@example.com"),
            "no key, no leg"
        );
        let sources = oathnet_only(&transport, &keys);
        assert!(sources.reach("ada@example.com"));
        assert!(sources.reach("@Ada_99"), "OathNet searches a username too");
        assert!(!sources.reach("two words"), "not a selector");
    }

    /// Counts requests and answers each with a 404, so a test can prove a leg sent nothing.
    #[derive(Default)]
    struct Counting(std::sync::Mutex<usize>);

    impl Transport for Counting {
        fn send(
            &self,
            _: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            Ok(crate::http::Response {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            })
        }
    }

    #[test]
    fn dehashed_searches_an_address_and_never_a_username() {
        let counting = std::sync::Arc::new(Counting::default());
        let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
            .unwrap_or_else(|e| panic!("fixture secret: {e}"));
        let client = DehashedClient::new(counting.clone(), secret);
        let sources = Sources {
            dehashed: Some(&client),
            ..Sources::default()
        };
        assert!(sources.reach("ada@example.com"));
        assert!(
            !sources.reach("@Ada_99"),
            "DeHashed alone cannot search a username"
        );
        let ExposureRun::Printed { report, .. } = run(sources, "@Ada_99", 7) else {
            panic!("expected a printed report");
        };
        assert_eq!(
            *counting
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            0
        );
        assert!(
            report.outcomes.iter().all(|o| o.module != DEHASHED_SOURCE),
            "a username lookup records no DeHashed leg: {:?}",
            report.outcomes
        );
        assert_eq!(report.dehashed, None);
    }

    #[test]
    fn an_email_lookup_folds_in_the_keyed_legs_under_one_report() {
        // Gravatar, Duolingo and keys.openpgp.org each find nothing.
        let reply = |status: u16, body: &str| {
            Ok(crate::http::Response {
                status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
        };
        let email_sources = crate::test_support::ScriptedTransport::new(vec![
            reply(404, ""),
            reply(200, r#"{"users":[]}"#),
            reply(404, "No key found"),
        ]);
        let crate::email_cli::EmailRun::Printed { report: email, .. } =
            crate::email_cli::run(&email_sources, "ada@example.com", 7)
        else {
            panic!("expected an email report");
        };
        let body = serde_json::json!({"success": true, "data": {
            "items": [{"email": "ada@example.com", "password": "hunter2", "dbname": "acme_forum"}],
            "meta": {"total": 1, "has_more": false}
        }});
        let transport = FakeHibp {
            body: body.to_string(),
            urls: std::sync::Mutex::default(),
        };
        let keys = oathnet_keys();
        let ExposureRun::Printed { report, .. } =
            run(oathnet_only(&transport, &keys), "ada@example.com", 7)
        else {
            panic!("expected an exposure report");
        };
        let (mut entities, mut outcomes) = (email.entities, email.outcomes);
        let before = outcomes.len();
        let text = match fold_into(&mut entities, &mut outcomes, report) {
            Ok(text) => text,
            Err(m) => panic!("fold failed: {m}"),
        };
        let legs: Vec<&str> = outcomes[before..]
            .iter()
            .map(|o| o.module.as_str())
            .collect();
        assert_eq!(
            legs,
            [SOURCE, STOLEN_TAX_SOURCE, OATHNET_SOURCE, DEHASHED_SOURCE]
        );
        assert_eq!(text.matches("entities=").count(), 1, "{text}");
        assert!(text.contains("oathnet_breaches=1"), "{text}");
        assert!(text.contains("dehashed_breaches=none"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        let seeds = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email && e.raw_value == "ada@example.com")
            .count();
        assert_eq!(seeds, 1, "the seed both lookups emit is merged");
        assert!(
            entities
                .iter()
                .any(|e| e.raw_value == "ada@example.com"
                    && e.tags.iter().any(|t| t == tags::BREACH)),
            "{text}"
        );
    }

    #[test]
    fn an_unavailable_exposure_line_cannot_forge_a_row() {
        assert_eq!(
            unavailable_line("refused\nentities=9"),
            "exposure=unavailable reason=refused\\nentities=9\n"
        );
    }

    #[test]
    fn a_username_skips_hibp_and_searches_oathnet_by_username() {
        let body = serde_json::json!({"success": true, "data": {
            "items": [
                {"email": "ada@example.com", "username": "Ada_99", "password_hash": "deadbeef",
                 "dbname": "acme_forum"},
                {"email": "a.l@example.org", "username": "ada_99", "dbname": "acme_forum"}
            ],
            "meta": {"total": 2, "has_more": false}
        }});
        let transport = FakeHibp {
            body: body.to_string(),
            urls: std::sync::Mutex::default(),
        };
        let keys = Keys::parse(&format!(
            "{}=on-test-key-0123456789abcdef\n",
            oathnet::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let sources = Sources {
            oathnet: Some((&transport, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Printed { text, report } = run(sources, "@Ada_99", 7) else {
            panic!("expected a printed report");
        };
        let urls = transport
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert!(urls[0].contains("username%5B%5D=ada_99"), "{urls:?}");

        let legs: Vec<&str> = report.outcomes.iter().map(|o| o.module.as_str()).collect();
        assert_eq!(
            legs,
            [STOLEN_TAX_SOURCE, OATHNET_SOURCE],
            "HIBP is email-only"
        );

        let seed = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.raw_value == "ada_99")
            .unwrap_or_else(|| panic!("no username seed: {text}"));
        assert!(seed.tags.iter().any(|t| t == tags::BREACH), "{text}");
        assert!(
            seed.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK),
            "{text}"
        );
        let emails: Vec<&str> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.raw_value.as_str())
            .collect();
        assert_eq!(emails, ["a.l@example.org", "ada@example.com"], "{text}");
        assert_eq!(
            report
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Username)
                .count(),
            1,
            "the seed's own spelling in a record is not a second username: {text}"
        );
        assert!(!text.contains("deadbeef"), "{text}");
    }

    #[test]
    fn oathnet_breaches_surface_values_but_not_cleartext_credentials() {
        let body = serde_json::json!({"success": true, "data": {
            "items": [
                {"email": "ada@example.com", "username": "ada99", "password": "hunter2-secret",
                 "dbname": "linkedin_2012", "indexed_at": "2026-04-18T12:00:00Z"},
                {"email": "ada@example.com", "phone_number": "+15555550100",
                 "dbname": "acme_forum"}
            ],
            "meta": {"total": 7, "has_more": true},
            "dbname_info": {"linkedin_2012": {"Title": "LinkedIn", "BreachDate": "2012-05-05"}}
        }});
        let transport = FakeHibp {
            body: body.to_string(),
            urls: std::sync::Mutex::default(),
        };
        let keys = Keys::parse(&format!(
            "{}=on-test-key-0123456789abcdef\n",
            oathnet::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let sources = Sources {
            oathnet: Some((&transport, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Printed { text, report } = run(sources, "Ada@Example.com", 7) else {
            panic!("expected a printed report");
        };

        let urls = transport
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert!(
            urls[0].contains("email%5B%5D=ada%40example.com"),
            "{urls:?}"
        );

        let outcome = report
            .outcomes
            .iter()
            .find(|o| o.module == OATHNET_SOURCE)
            .unwrap_or_else(|| panic!("no oathnet outcome: {text}"));
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(outcome.found, Some(2));
        let detail = outcome.detail.clone().unwrap_or_default();
        assert!(detail.contains("first 2 of 7"), "{detail}");

        let email = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .unwrap_or_else(|| panic!("no email entity: {text}"));
        assert!(email.tags.iter().any(|t| t == tags::BREACH));
        assert!(email.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK));
        let datasets: Vec<_> = email
            .evidence
            .iter()
            .filter(|e| e.provenance.source == OATHNET_SOURCE)
            .filter_map(|e| e.attributes.get("dbname"))
            .collect();
        assert_eq!(datasets.len(), 2, "{datasets:?}");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == "ada99"),
            "{text}"
        );

        assert!(text.contains("\noathnet_breaches=2\n"), "{text}");
        assert!(
            text.contains(
                "oathnet_breach\tlinkedin_2012\trecords=1\ttitle=LinkedIn\tbreach_date=2012-05-05\t\
                 first_indexed=2026-04-18T12:00:00Z\tlast_indexed=2026-04-18T12:00:00Z\t\
                 password_exposed=true\tfields=email,password,username\n"
            ),
            "{text}"
        );
        // Non-credential record values are surfaced, not reduced to field names: the phone number
        // a record held appears as its own row.
        assert!(
            text.contains("oathnet_value\tacme_forum\tphone_number=+15555550100\n"),
            "{text}"
        );
        // A cleartext credential is never emitted: the password is reported as exposed (the
        // `password_exposed=true` and `fields=…,password,…` above), but its value appears nowhere.
        assert!(
            !text.contains("oathnet_value\tlinkedin_2012\tpassword="),
            "the cleartext password value must not be emitted: {text}"
        );
        assert!(
            !text.contains("hunter2-secret"),
            "the cleartext password value must not be emitted: {text}"
        );
        let saved = serde_json::to_string(&report.entities).unwrap_or_default();
        for value in ["+15555550100", "ada99"] {
            assert!(
                saved.contains(value),
                "{value} missing from entities: {saved}"
            );
        }
        assert!(
            !saved.contains("hunter2-secret"),
            "the cleartext password value must not reach the entities: {saved}"
        );
    }

    #[test]
    fn dehashed_breaches_are_exposure_metadata_on_the_email_and_never_values() {
        let body = serde_json::json!({
            "entries": [
                {"database_name": "LinkedIn", "email": ["ada@example.com"],
                 "username": ["ada99"], "password": "hunter2-secret", "name": ["Ada Example"]},
                {"database_name": "LinkedIn", "email": ["ada@example.com", "alt@example.com"],
                 "hashed_password": "deadbeef-hash", "phone": "+15555550100"},
                {"database_name": "AcmeForum", "email": ["ada@example.com"]}
            ],
            "total": 5
        });
        let transport = std::sync::Arc::new(FakeHibp {
            body: body.to_string(),
            urls: std::sync::Mutex::default(),
        });
        let secret = crate::keys::Secret::new("dh-test-key-0123456789abcdef".to_owned())
            .unwrap_or_else(|e| panic!("fixture secret: {e}"));
        // Local pacing off so the test never waits on the shared limiter.
        let client = DehashedClient::with_limiter(
            transport.clone(),
            secret,
            crate::hibp::rate_limit::RateLimiter::per_minute(0),
        );
        let sources = Sources {
            dehashed: Some(&client),
            ..Sources::default()
        };
        let ExposureRun::Printed { text, report } = run(sources, "Ada@Example.com", 7) else {
            panic!("expected a printed report");
        };

        let urls = transport
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert!(urls[0].ends_with("/v2/search"), "{urls:?}");

        let outcome = report
            .outcomes
            .iter()
            .find(|o| o.module == DEHASHED_SOURCE)
            .unwrap_or_else(|| panic!("no dehashed outcome: {text}"));
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(outcome.found, Some(2));
        let detail = outcome.detail.clone().unwrap_or_default();
        assert!(detail.contains("first 3 of 5"), "{detail}");

        let email = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "ada@example.com")
            .unwrap_or_else(|| panic!("no email entity: {text}"));
        assert!(email.tags.iter().any(|t| t == tags::BREACH));
        assert!(email.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK));
        let datasets: Vec<_> = email
            .evidence
            .iter()
            .filter(|e| e.provenance.source == DEHASHED_SOURCE)
            .filter_map(|e| e.attributes.get("database_name"))
            .collect();
        assert_eq!(datasets.len(), 2, "one evidence per database: {datasets:?}");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == "ada99"),
            "{text}"
        );

        assert!(text.contains("\ndehashed_breaches=2\n"), "{text}");
        assert!(
            text.contains("dehashed_breach\tAcmeForum\trecords=1\tpassword_exposed=false\n"),
            "{text}"
        );
        assert!(
            text.contains("dehashed_breach\tLinkedIn\trecords=2\tpassword_exposed=true\n"),
            "{text}"
        );
        let saved = serde_json::to_string(&report.entities).unwrap_or_default();
        for secret in [
            "hunter2-secret",
            "deadbeef-hash",
            "+15555550100",
            "Ada Example",
        ] {
            assert!(!text.contains(secret), "{secret} in text: {text}");
            assert!(!saved.contains(secret), "{secret} in entities: {saved}");
        }
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

    /// Gives stolen.tax's `snusbase` path no response and answers every other request with one
    /// 200 JSON body.
    struct SnusbaseDown(&'static str);

    impl Transport for SnusbaseDown {
        fn send(
            &self,
            request: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            if request.url.ends_with("path=snusbase") {
                return Err(crate::http::TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "no route".into(),
                    blocked: false,
                });
            }
            Ok(crate::test_support::json_ok(self.0))
        }
    }

    /// A stolen.tax row that restates the searched handle and names no breach mints nothing,
    /// but its row says stolen.tax matched, beside the partial note when a path failed.
    #[test]
    fn a_stolen_tax_row_that_names_no_breach_is_noted_on_its_row() {
        let body = r#"{"success":true,"data":{"breach_data":[{"username":"ada_99"}]}}"#;
        let keys = Keys::parse(&format!(
            "{}=st-test-key-0123456789abcdef\n",
            stolen_tax::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let row = |transport: &(dyn Transport + Sync)| {
            let sources = Sources {
                stolen_tax: Some((transport, &keys)),
                ..Sources::default()
            };
            let ExposureRun::Printed { report, .. } = run(sources, "ada.99", 7) else {
                panic!("expected a printed report");
            };
            report
                .outcomes
                .into_iter()
                .find(|o| o.module == STOLEN_TAX_SOURCE)
                .unwrap_or_else(|| panic!("no stolen.tax row"))
        };

        let every_path = FakeHibp {
            body: body.into(),
            urls: std::sync::Mutex::default(),
        };
        let answered = row(&every_path);
        assert_eq!(
            (answered.kind, answered.found, answered.detail.as_deref()),
            (
                SourceOutcomeKind::Inconclusive,
                Some(0),
                Some("1 row(s) name no breach or stealer host")
            )
        );

        let partial = row(&SnusbaseDown(body));
        assert_eq!(partial.kind, SourceOutcomeKind::Inconclusive);
        let detail = partial.detail.unwrap_or_default();
        assert!(
            detail.starts_with(
                "partial: 0 retrieved — stopped by the stolen.tax `snusbase` path(s) failing"
            ) && detail.ends_with("; 1 row(s) name no breach or stealer host"),
            "{detail}"
        );
    }

    /// A stolen.tax path the egress refuses before sending now makes the exposure lookup a refusal
    /// (exit 77) naming it, where before it printed an empty report and exited 0 because only a
    /// transport failure, through the old `network` side channel, could stop the lookup.
    #[test]
    fn a_refused_stolen_tax_path_is_a_refusal() {
        let keys = Keys::parse(&format!(
            "{}=st-test-key-0123456789abcdef\n",
            stolen_tax::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let refusing = crate::test_support::Refusing;
        let sources = Sources {
            stolen_tax: Some((&refusing, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Network(why) = run(sources, "ada.99", 7) else {
            panic!("expected a network refusal");
        };
        assert!(why.contains(STOLEN_TAX_SOURCE), "{why}");
    }

    /// A stolen.tax lookup whose every path got no response is no usable response (exit 69)
    /// naming it, never a refusal and never a report. Before, the leg mapped every path failure
    /// to `Inconclusive`, so the lookup printed an empty report and exited 0 with the transport
    /// failure surviving only as text; now the row keeps the kind the fetch saw.
    #[test]
    fn a_silent_stolen_tax_path_is_no_response_not_inconclusive() {
        let keys = Keys::parse(&format!(
            "{}=st-test-key-0123456789abcdef\n",
            stolen_tax::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let silent = crate::test_support::Silent;
        let sources = Sources {
            stolen_tax: Some((&silent, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Failed(why) = run(sources, "ada.99", 7) else {
            panic!("expected no usable response");
        };
        assert!(why.contains(STOLEN_TAX_SOURCE), "{why}");
        assert!(why.contains("no response (DnsFailure)"), "{why}");
    }

    /// A stolen.tax source that answered every path with an error was reached, so the lookup
    /// prints its row (exit 0) with the status's kind, not a transport failure and never a
    /// refusal.
    #[test]
    fn a_failing_stolen_tax_path_is_reached_with_the_status_kind() {
        let keys = Keys::parse(&format!(
            "{}=st-test-key-0123456789abcdef\n",
            stolen_tax::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let failing = crate::test_support::Failing;
        let sources = Sources {
            stolen_tax: Some((&failing, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Printed { report, .. } = run(sources, "ada.99", 7) else {
            panic!("expected a printed report");
        };
        let Some(row) = report
            .outcomes
            .iter()
            .find(|row| row.module == STOLEN_TAX_SOURCE)
        else {
            panic!("expected a stolen_tax row, got {:?}", report.outcomes);
        };
        assert_eq!(row.kind, SourceOutcomeKind::Upstream5xx);
        assert!(!row.kind.is_transport_failure());
        assert_eq!(
            row.detail.as_deref(),
            Some("stolen_tax: `snusbase` path failed: HTTP 500 (Upstream5xx)")
        );
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
            ..Sources::default()
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

    /// The incidents section: from `incidents=` up to the `OathNet` section that follows it.
    fn incidents_section(text: &str) -> &str {
        let Some(start) = text.find("\nincidents=") else {
            panic!("no incidents section: {text}");
        };
        let Some(end) = text.find("\noathnet_breaches=") else {
            panic!("no oathnet section: {text}");
        };
        &text[start + 1..=end]
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
        let evidence: usize = report
            .entities
            .iter()
            .map(|entity| entity.evidence.len())
            .sum();
        assert_eq!(
            saved.len(),
            report.outcomes.len() + report.entities.len() + evidence
        );
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
        let no_response = HibpError::Transport {
            message: "request failed".into(),
            kind: SourceOutcomeKind::TlsFailure,
        };
        assert_eq!(outcome_kind(&no_response), SourceOutcomeKind::TlsFailure);
        assert_eq!(
            outcome_kind(&HibpError::NotAnAnswer(SourceOutcomeKind::BotWaf)),
            SourceOutcomeKind::BotWaf
        );
        let statuses = [
            (HibpError::BadRequest("x".into()), Some(400)),
            (HibpError::Unauthorized("x".into()), Some(401)),
            (HibpError::Forbidden("x".into()), Some(403)),
            (HibpError::RateLimited { retry_after: None }, Some(429)),
            (
                HibpError::Server {
                    status: 503,
                    body: String::new(),
                },
                Some(503),
            ),
            (
                HibpError::UnexpectedStatus {
                    status: 418,
                    body: String::new(),
                },
                Some(418),
            ),
            (no_response, None),
            (HibpError::Decode("x".into()), None),
            (HibpError::MissingKey, None),
        ];
        for (error, status) in statuses {
            assert_eq!(error.http_status(), status, "{error:?}");
        }
    }

    /// Answers every request with one fixed result, so a client can be asked more than once.
    struct Answers(Result<crate::http::Response, crate::http::TransportFailure>);

    impl Transport for Answers {
        fn send(
            &self,
            _: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            self.0.clone()
        }
    }

    /// A keyed HIBP client over [`Answers`], with local pacing off.
    fn hibp_answering(
        answer: Result<crate::http::Response, crate::http::TransportFailure>,
    ) -> HibpClient {
        let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
            panic!("the fixture key is a valid HIBP key");
        };
        HibpClient::with_config(
            std::sync::Arc::new(Answers(answer)),
            crate::hibp::client::Auth::ApiKey(key),
            crate::hibp::client::HibpConfig::default(),
            std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
        )
    }

    /// A `DeHashed` client over [`Answers`], with local pacing off.
    fn dehashed_answering(
        answer: Result<crate::http::Response, crate::http::TransportFailure>,
    ) -> DehashedClient {
        let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
            .unwrap_or_else(|e| panic!("fixture secret: {e}"));
        DehashedClient::with_limiter(
            std::sync::Arc::new(Answers(answer)),
            secret,
            crate::hibp::rate_limit::RateLimiter::per_minute(0),
        )
    }

    /// A response with `status`, `headers` and no body.
    fn status_only(status: u16, headers: &[(&str, &str)]) -> crate::http::Response {
        crate::http::Response {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            body: Vec::new(),
            truncated: false,
        }
    }

    /// A Cloudflare interstitial served with 200 in place of the API's answer.
    const CHALLENGE: &str = "<html><title>Just a moment...</title>\
        <script src=\"https://challenges.cloudflare.com/x\"></script></html>";

    #[test]
    fn a_keyed_leg_without_a_response_keeps_the_cause_the_fetch_saw() {
        for kind in [
            SourceOutcomeKind::DnsFailure,
            SourceOutcomeKind::TlsFailure,
            SourceOutcomeKind::TtfbTimeout,
        ] {
            // A real no-response (the request was attempted, so `blocked` is false): the leg's row
            // keeps the cause the fetch saw, which `SourceReach` reads as a no-response (exit 69).
            let failure = || {
                Err(crate::http::TransportFailure {
                    kind,
                    detail: "ada@example.com".into(),
                    blocked: false,
                })
            };
            let hibp = hibp_leg(
                &hibp_answering(failure()),
                "ada@example.com",
                "scan-1",
                7,
                &mut Report::default(),
            );
            assert_eq!(hibp.kind, kind, "{hibp:?}");
            let dehashed = dehashed_leg(
                &dehashed_answering(failure()),
                "ada@example.com",
                "scan-1",
                7,
                &mut Report::default(),
            );
            assert_eq!(dehashed.kind, kind, "{dehashed:?}");
        }
    }

    #[test]
    fn a_blocked_keyed_leg_is_refused_before_sending() {
        // The egress policy refused the request before it was sent (`blocked` is true): the leg's
        // row is `RefusedBeforeSending`, which `SourceReach` reads as a refusal (exit 77), never a
        // reached-but-silent transport failure.
        let blocked = || {
            Err(crate::http::TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "ada@example.com".into(),
                blocked: true,
            })
        };
        let hibp = hibp_leg(
            &hibp_answering(blocked()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(
            hibp.kind,
            SourceOutcomeKind::RefusedBeforeSending,
            "{hibp:?}"
        );
        assert!(!hibp.kind.is_transport_failure(), "{hibp:?}");
        let dehashed = dehashed_leg(
            &dehashed_answering(blocked()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(
            dehashed.kind,
            SourceOutcomeKind::RefusedBeforeSending,
            "{dehashed:?}"
        );
        assert!(!dehashed.kind.is_transport_failure(), "{dehashed:?}");
    }

    #[test]
    fn a_challenge_page_is_a_wall_on_a_keyed_leg_not_a_network_failure() {
        let page = || Ok(crate::test_support::html_ok(CHALLENGE));
        let hibp = hibp_leg(
            &hibp_answering(page()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(hibp.kind, SourceOutcomeKind::BotWaf, "{hibp:?}");
        let dehashed = dehashed_leg(
            &dehashed_answering(page()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(dehashed.kind, SourceOutcomeKind::BotWaf, "{dehashed:?}");
    }

    #[test]
    fn a_hibp_rate_limit_records_its_status_and_pause() {
        // Longer than the client waits for, so it gives up at once; a pause past the hour every
        // other leg's fetch allows is recorded at that bound.
        for (sent, recorded) in [("120", 120), ("999999", 3600)] {
            let limited = status_only(429, &[("retry-after", sent)]);
            let outcome = hibp_leg(
                &hibp_answering(Ok(limited)),
                "ada@example.com",
                "scan-1",
                7,
                &mut Report::default(),
            );
            assert_eq!(
                (outcome.kind, outcome.http_status, outcome.retry_after_secs),
                (SourceOutcomeKind::RateLimited, Some(429), Some(recorded)),
                "{sent}: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_dehashed_failure_reads_the_same_on_the_exposure_leg_and_in_the_collector_receipt() {
        let answers = [
            Ok(status_only(400, &[])),
            Ok(status_only(401, &[])),
            Ok(status_only(403, &[])),
            Ok(status_only(429, &[("retry-after", "42")])),
            Ok(status_only(429, &[])),
            Ok(status_only(503, &[])),
            Ok(status_only(418, &[])),
            Ok(status_only(302, &[])),
            Ok(crate::test_support::html_ok(CHALLENGE)),
            Ok(crate::test_support::json_ok(r#"{"results": "x"}"#)),
            Err(crate::http::TransportFailure {
                kind: SourceOutcomeKind::DnsFailure,
                detail: "ada@example.com".into(),
                blocked: false,
            }),
        ];
        let selector = Entity::new(EntityKind::Email, "ada@example.com", 1.0, "scan-1");
        for answer in answers {
            let client = dehashed_answering(answer.clone());
            let leg = dehashed_leg(
                &client,
                "ada@example.com",
                "scan-1",
                7,
                &mut Report::default(),
            );
            let batch = dehashed::collect(
                &client,
                &selector,
                dehashed::Purpose::OwnAccount,
                &crate::collector::CollectionLimits::default(),
                7,
            )
            .unwrap_or_else(|e| panic!("{answer:?}: {e:?}"));
            assert!(!leg.kind.is_accepted(), "{answer:?} gave {leg:?}");
            assert_eq!(leg, batch.receipts[0].outcome, "{answer:?}");
        }
    }

    /// Every leg's first request waits here until all the legs have sent one, or five seconds
    /// pass, then is answered 404. Legs that run one after another never meet: the first waits
    /// out the five seconds alone.
    struct Meeting {
        inside: std::sync::Mutex<usize>,
        arrived: std::sync::Condvar,
        want: usize,
        together: std::sync::Mutex<Vec<bool>>,
    }

    /// One leg's transport into a [`Meeting`].
    struct Attendee {
        meeting: std::sync::Arc<Meeting>,
        sent: std::sync::Mutex<bool>,
    }

    impl Transport for Attendee {
        fn send(
            &self,
            _: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            use std::sync::PoisonError;
            let first = !std::mem::replace(
                &mut *self.sent.lock().unwrap_or_else(PoisonError::into_inner),
                true,
            );
            if first {
                let meeting = &self.meeting;
                let mut inside = meeting
                    .inside
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *inside += 1;
                meeting.arrived.notify_all();
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while *inside < meeting.want && std::time::Instant::now() < until {
                    let left = until.saturating_duration_since(std::time::Instant::now());
                    inside = meeting
                        .arrived
                        .wait_timeout(inside, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
                let met = *inside >= meeting.want;
                drop(inside);
                meeting
                    .together
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(met);
            }
            Ok(crate::http::Response {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            })
        }
    }

    #[test]
    fn the_keyed_legs_run_at_the_same_time_and_report_in_their_order() {
        let meeting = std::sync::Arc::new(Meeting {
            inside: std::sync::Mutex::new(0),
            arrived: std::sync::Condvar::new(),
            want: 4,
            together: std::sync::Mutex::default(),
        });
        let attendee = || Attendee {
            meeting: meeting.clone(),
            sent: std::sync::Mutex::new(false),
        };
        let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
            panic!("the fixture key is a valid HIBP key");
        };
        let hibp = HibpClient::with_config(
            std::sync::Arc::new(attendee()),
            crate::hibp::client::Auth::ApiKey(key),
            crate::hibp::client::HibpConfig::default(),
            std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
        );
        let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
            .unwrap_or_else(|e| panic!("fixture secret: {e}"));
        let dehashed = DehashedClient::new(std::sync::Arc::new(attendee()), secret);
        let (stolen_tax, oathnet) = (attendee(), attendee());
        let keys = Keys::parse(&format!(
            "{}=st-test-key-0123456789abcdef\n{}=on-test-key-0123456789abcdef\n",
            stolen_tax::KEY_SLOT,
            oathnet::KEY_SLOT
        ))
        .unwrap_or_else(|e| panic!("fixture keys: {e}"));
        let sources = Sources {
            hibp: Some(&hibp),
            stolen_tax: Some((&stolen_tax, &keys)),
            oathnet: Some((&oathnet, &keys)),
            dehashed: Some(&dehashed),
            ..Sources::default()
        };
        let started = std::time::Instant::now();
        let ExposureRun::Printed { report, .. } = run(sources, "ada@example.com", 7) else {
            panic!("expected a printed report");
        };
        let together = meeting
            .together
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            together,
            vec![true; 4],
            "each leg's first request found the other three in flight"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "no leg waited for another"
        );
        let legs: Vec<&str> = report.outcomes.iter().map(|o| o.module.as_str()).collect();
        assert_eq!(
            legs,
            [SOURCE, STOLEN_TAX_SOURCE, OATHNET_SOURCE, DEHASHED_SOURCE],
            "the outcomes fold in the legs' order"
        );
    }
}
